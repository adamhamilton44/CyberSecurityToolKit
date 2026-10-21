#!/usr/bin/env python3
"""Run pinned local enumeration profiles; preserve raw evidence and limitations."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile

MAX_OUTPUT = 16 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]


def limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', choices=('linpeas', 'les', 'upc'), required=True)
    parser.add_argument('--output', default=str(ROOT/'reports'))
    parser.add_argument('--seconds', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600:
        parser.error('--seconds must be 1..600')
    os.umask(0o077)
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    profile = json.loads((ROOT/'vendor/PROFILES.json').read_text())[args.tool]
    source = ROOT/'vendor'/profile['file']
    if hashlib.sha256(source.read_bytes()).hexdigest() != profile['sha256']:
        parser.exit(1, 'Pinned enumeration source has changed; refusing execution.\n')
    output = Path(args.output)
    if output.is_symlink():
        parser.error('Output directory must not be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='enumeration-'+args.tool+'-',dir=output)).resolve()
    directory.chmod(0o700)
    report = directory/'upstream-output.txt'
    interpreter = '/bin/bash' if args.tool == 'les' else '/bin/sh'
    command = [interpreter,str(source),*profile['arguments']]
    meta = {'tool':args.tool,'started_utc':datetime.now(timezone.utc).isoformat(),
        'source':profile,'command':command,'status':'incomplete',
        'interpretation':'Raw upstream observations/candidates; not a verified exploit or a clean bill of health.',
        'limitations':'Current account permissions, missing commands, vendor backports and scanner coverage may limit conclusions.',
        'exit_code':None}
    metadata = directory/'assessment.json'
    metadata.write_text(json.dumps(meta,indent=2)+'\n')
    process = None
    try:
        with report.open('wb') as evidence:
            # Input is closed; no passwords or operator-supplied upstream flags.
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=evidence,
                stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limit_output,
                cwd=directory, env={k:v for k,v in os.environ.items() if not k.startswith('BASH_FUNC_') and k not in ('ENV','BASH_ENV','SHELLOPTS','BASHOPTS','LD_PRELOAD','LD_LIBRARY_PATH')})
            try:
                code = process.wait(timeout=args.seconds)
                meta['exit_code'] = code
                meta['status'] = 'completed_unverified' if code == 0 else 'incomplete_tool_error'
            except subprocess.TimeoutExpired:
                meta['status'] = 'incomplete_timeout'
                stop_group(process)
            if report.stat().st_size >= MAX_OUTPUT:
                meta['status'] = 'incomplete_output_limit'
    except KeyboardInterrupt:
        meta['status'] = 'incomplete_interrupted'
        if process is not None:
            stop_group(process)
    except OSError as exc:
        meta['status'] = 'incomplete_runner_error'
        meta['error'] = str(exc)
        if process is not None:
            stop_group(process)
    finally:
        meta['finished_utc'] = datetime.now(timezone.utc).isoformat()
        metadata.write_text(json.dumps(meta,indent=2)+'\n')
        if report.exists():
            report.chmod(0o600)
        metadata.chmod(0o600)
    print('Assessment: '+str(metadata))
    print('Upstream evidence: '+str(report))
    print('Status: '+meta['status']+'; review evidence and omissions. No exploitability verdict was inferred.')
    return 0 if meta['status'] == 'completed_unverified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
