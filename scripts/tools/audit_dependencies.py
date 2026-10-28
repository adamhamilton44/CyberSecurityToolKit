#!/usr/bin/env python3
"""Inventory installer dependencies against available sources, without running tools."""
import argparse
import json
import sys
from pathlib import Path
import re

ROOT = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parents[2]
ALIASES = {
    '7zip': ['7z', '7zz'], 'p7zip-full': ['7z', '7zz'],
    'aria2': ['aria2c'], 'exploitdb': ['searchsploit'],
    'golang': ['go'], 'golang-any': ['go'],
    'httpx-toolkit': ['httpx-toolkit', 'httpx'],
    'impacket-scripts': ['impacket-GetNPUsers', 'impacket-GetUserSPNs', 'impacket-smbclient'],
    'metasploit-framework': ['msfconsole', 'msfvenom', 'msf-pattern_create', 'msf-pattern_offset'],
    'openssh-client': ['ssh', 'scp', 'sftp', 'ssh-keygen'],
    'openssh-server': ['sshd'], 'redis-tools': ['redis-cli'],
    'postgresql-client': ['psql'], 'default-mysql-client': ['mysql', 'mariadb'],
    'ldap-utils': ['ldapsearch'], 'snmpcheck': ['snmp-check'],
    'theharvester': ['theHarvester'], 'bzip2': ['bunzip2'],
    'bloodhound-ce': ['bloodhound-ce-python', 'bloodhound-python'],
}


def collect(reference):
    sources = []
    for path in [ROOT/'cstk.sh', ROOT/'scripts/bin/web_tls_security_assessment',
                 *sorted((ROOT/'scripts/source').rglob('*.py')),
                 *sorted((ROOT/'scripts/tools/zip2go').glob('*.sh')),
                 *sorted((ROOT/'scripts/tools/zip2go/lib').glob('*'))]:
        if path.is_file() and 'tests' not in path.parts:
            sources.append((str(path.relative_to(ROOT)), path.read_text(errors='replace')))
    shipped = {p.name for p in (ROOT/'scripts/bin').iterdir() if p.is_file()}
    matched = set()
    if reference.is_dir():
        for path in sorted(reference.iterdir()):
            if path.is_file() and path.suffix in ('.sh', '.py') and path.stem in shipped:
                matched.add(path.stem)
                sources.append(('reference/'+path.name, path.read_text(errors='replace')))
    return sources, sorted(shipped-matched)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path,
                        default=Path('/home/adam/Documents/Github/CSTK_bin_files'))
    parser.add_argument('--output', type=Path, default=ROOT/'log/development/DEPENDENCY_AUDIT.md')
    args = parser.parse_args()
    policy = json.loads((ROOT/'scripts/tools/dependency_policy.json').read_text())
    installer = (ROOT/'install.sh').read_text()
    current = re.search(r'local required_commands=\(\s*(.*?)\s*\)', installer, re.S).group(1).split()
    if current != policy['default_system_packages']:
        parser.error('Installer list and reviewed dependency policy differ; review the policy before regenerating.')
    sources, unmatched = collect(args.reference)
    items = [(name, 'system') for name in policy['baseline_system_packages']]
    items += [(row['name'], row['kind']) for row in policy['other_downloads']]
    rows = []
    for name, kind in items:
        aliases = list(dict.fromkeys([name, *ALIASES.get(name, [])]))
        pattern = re.compile(r'(?<![\w-])(?:'+ '|'.join(map(re.escape, aliases))+r')(?![\w-])', re.I)
        hits, catalogue = [], []
        for label, text in sources:
            target = catalogue if label.endswith('/PostEx_GTFONow.py') else hits
            for line, content in enumerate(text.splitlines(), 1):
                if pattern.search(content):
                    target.append(f'{label}:{line}')
        removed = policy['removed_defaults'].get(name) or policy['removed_other_downloads'].get(name)
        build = policy['build_prerequisites'].get(name)
        decision = 'Remove automatic install' if removed else 'Retain prerequisite' if build else 'Retain; source references' if hits else 'Retain; review needed'
        reason = removed or build or 'References require interpretation; static matches do not prove execution or usefulness.'
        rows.append(dict(name=name, kind=kind, decision=decision, reason=reason,
                         aliases=aliases, references=hits, catalogue_references=catalogue))
    text = ['# CSTK dependency audit', '',
            f"System install entries: {len(policy['baseline_system_packages'])} → {len(current)}. "
            f"Removed system defaults: {len(policy['removed_defaults'])}.", '',
            'This is a static use audit, not execution of security tools. Installer/updater declarations, '
            'password wordlists, old archives, vendor enumeration data and examples alone are not evidence '
            'that a tool is needed. Package aliases are checked explicitly. Catalogue-only references '
            'do not justify mandatory installation.', '',
            'Reference sources are read-only files outside this checkout. A matching source filename '
            'does not prove equivalence with an opaque compiled executable. References may include '
            'optional checks, hints and descriptions rather than an actual invocation. Unverified '
            'dependencies are retained for review rather than removed on absence of a text match.', '',
            '## Decisions', '', '| Dependency | Kind | Decision | Reason / evidence |',
            '| --- | --- | --- | --- |']
    for row in rows:
        evidence = ', '.join(row['references'][:3]) or 'No non-catalogue source match'
        if len(row['references']) > 3:
            evidence += f" (+{len(row['references'])-3} more; see JSON)"
        reason = row['reason'] if row['decision'] != 'Retain; source references' else evidence
        text.append(f"| `{row['name']}` | {row['kind']} | {row['decision']} | {reason} |")
    text += ['', '## Known limitations and remaining checks', '',
             '- `httpx-toolkit` installs `/usr/bin/httpx-toolkit` in the inspected Kali package, '
             'while available enumeration source checks `httpx`. Retained pending a separate '
             'runtime/source reconciliation; no compatibility wrapper is added here.',
             '- Available enumeration source offers a `bloodhound-python` availability hint; '
             'that is not a justification for automatically installing the BloodHound server/app '
             'or a separate collector. Existing optional checks remain.',
             '- Existing installations are not purged or modified. Older package and pipx ledgers '
             'remain readable for conservative uninstall; affected journals need reviewed baseline recovery before package removal.',
             '- Build tools may also be dependencies of other retained packages. Removing a default '
             'does not guarantee the package will be absent from the final dependency closure.',
             '- Downloaded source helpers shc, nrich, mongosh and MimiPenguin retain '
             'installer/runtime references; they were not executed by this audit.',
             '- Package aliases, versions and dependency resolution remain distribution-specific.', '',
             '## Compiled entries without an exact-name external source match', '',
             ', '.join(f'`{name}`' for name in unmatched), '',
             'Reproduce with `python3 scripts/tools/audit_dependencies.py --reference /path/to/CSTK_bin_files`. '
             'Full reference locations and catalogue matches are in the companion JSON.']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(text)+'\n')
    args.output.with_suffix('.json').write_text(json.dumps({'dependencies': rows,
        'unmatched_compiled_entries': unmatched}, indent=2)+'\n')
    print(f'Reviewed {len(rows)} direct dependency/download entries; wrote {args.output}')


if __name__ == '__main__':
    main()
