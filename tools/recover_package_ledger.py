#!/usr/bin/env python3
"""Review a locale-damaged CSTK package journal; never install or remove packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z')


def names(data):
    result = data.decode('ascii').splitlines()
    if any(not PACKAGE.fullmatch(name) for name in result):
        raise ValueError('Invalid package name in inventory')
    return set(result)


def read_regular(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8*1024*1024:
        raise ValueError(f'Unsafe or oversized inventory: {path}')
    return path.read_bytes()


def reconstruct(baseline, ledger, before, after):
    """Protect the entire earliest retained baseline, including uncertain ownership."""
    if len(before) != len(after) or not before:
        raise ValueError('Expected equal nonempty before/after snapshot sets')
    # Pair by write order, then verify CONTENT continuity, not filenames/times alone.
    if names(before[0]) != baseline:
        raise ValueError('Earliest pending snapshot differs from the pinned baseline')
    for index, (left, right) in enumerate(zip(before, after)):
        if not names(left) <= names(right):
            raise ValueError('Pending window includes package removals; manual review required')
        if index and left != after[index-1]:
            raise ValueError('Pending snapshots do not form a continuous content chain')
    additions = names(after[-1])-baseline
    # Keep successful later ledger additions, recover missing window additions,
    # and conservatively disclaim ALL baseline packages. Earlier ownership unknown.
    return (ledger | additions)-baseline, ledger & baseline


def removal_names(text):
    return {line.split()[1] for line in text.splitlines()
            if line.startswith(('Remv ', 'Purg ')) and len(line.split()) >= 2}


def base_name(name):
    return name.split(':', 1)[0]


def atomic_write(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.cstk-review-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/cstk'))
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--backup-parent', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state_dir
    if os.geteuid() != 0:
        parser.error('Run with sudo to read the root-owned journal')
    if state.is_symlink() or not state.is_dir() or state.stat().st_uid != 0 or state.stat().st_mode & 0o777 != 0o700:
        parser.error('Journal directory must be a root-owned real directory with mode 700')
    raw_baseline = read_regular(args.baseline)
    if hashlib.sha256(raw_baseline).hexdigest() != args.baseline_sha256:
        parser.error('Baseline checksum mismatch')
    baseline = names(raw_baseline)
    if not baseline:
        parser.error('An empty baseline cannot protect the existing OS')
    manager = read_regular(state/'package-manager').decode().strip()
    if manager != 'apt-get':
        parser.error('This recovery procedure supports APT journals only')
    ledger_bytes = read_regular(state/'packages')
    ledger = names(ledger_bytes)
    pending = sorted(state.glob('packages.before.*'), key=lambda p:(p.stat().st_mtime_ns,p.name))
    after = sorted(state.glob('packages.after.*'), key=lambda p:(p.stat().st_mtime_ns,p.name))
    snapshot_paths = pending+after
    snapshots = {p: read_regular(p) for p in snapshot_paths}
    candidate, protected = reconstruct(baseline, ledger,
        [snapshots[p] for p in pending], [snapshots[p] for p in after])
    env = dict(os.environ, LC_ALL='C')
    inventory = subprocess.run(['dpkg-query','-W','-f=${binary:Package} ${db:Status-Status}\n'],
                               capture_output=True,text=True,env=env,check=True,timeout=60)
    active = {line.split()[0] for line in inventory.stdout.splitlines()
              if len(line.split()) == 2 and line.split()[1] not in ('not-installed','config-files')}
    targets = sorted(candidate & active)
    simulation = subprocess.run(['apt-get','-s','purge','--',*targets],
        capture_output=True,text=True,env=env,timeout=120) if targets else None
    output = '' if simulation is None else simulation.stdout+simulation.stderr
    removals = removal_names(output)
    allowed = {base_name(name) for name in targets}
    baseline_ids = {base_name(name) for name in baseline}
    blocked = sorted(name for name in removals
                     if base_name(name) not in allowed or base_name(name) in baseline_ids)
    ready = not blocked and (simulation is None or simulation.returncode == 0)
    report = {'mode':'check','baseline_packages':len(baseline),
        'pending_transactions':len(pending),'original_ledger_entries':len(ledger),
        'protected_baseline_ledger_entries':sorted(protected),
        'proposed_ledger':sorted(candidate),'active_removal_targets':targets,
        'apt_simulated_removals':sorted(removals),'blocked_removals':blocked,
        'simulation_exit':None if simulation is None else simulation.returncode,
        'ready_for_ledger_repair':ready,
        'limits':'Earliest retained snapshot is protected conservatively; earlier CSTK ownership is unknown. APT simulation is not a purge or a guarantee about maintainer scripts.'}
    atomic_write(args.report.with_suffix('.apt.log'), output.encode())
    atomic_write(args.report, (json.dumps(report,indent=2)+'\n').encode())
    if args.apply:
        if not ready:
            parser.exit(1,'Simulation is blocked; no journal files were changed.\n')
        if args.backup_parent is None or not args.backup_parent.is_dir():
            parser.error('--apply requires an existing --backup-parent outside checkout/state')
        checkout = Path(read_regular(state/'checkout').decode().strip()).resolve()
        parent = args.backup_parent.resolve()
        if parent == state.resolve() or state.resolve() in parent.parents or parent == checkout or checkout in parent.parents:
            parser.error('Recovery backup must survive checkout/journal removal')
        # Reject changes since the read-only review earlier in this invocation.
        if read_regular(state/'packages') != ledger_bytes or any(read_regular(p) != snapshots[p] for p in snapshot_paths):
            parser.error('Journal changed during review; stop installs/updates and retry')
        backup = Path(tempfile.mkdtemp(prefix='cstk-package-journal-',dir=parent))
        for path in [state/'packages',state/'package-manager',state/'checkout',*snapshot_paths]:
            shutil.copy2(path,backup/path.name,follow_symlinks=False)
        atomic_write(state/'packages', ('\n'.join(sorted(candidate))+'\n' if candidate else '').encode())
        # No packages are removed here. Snapshots are preserved in the backup.
        for path in snapshot_paths:
            path.unlink()
        report.update(mode='applied',backup=str(backup))
        atomic_write(args.report,(json.dumps(report,indent=2)+'\n').encode())
        print('Journal repaired; original records preserved at '+str(backup))
    else:
        print('Read-only review complete; journal and installed packages unchanged.')
    print('Review: '+str(args.report))
    return 0 if ready else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        raise SystemExit('Recovery stopped: '+str(error))
