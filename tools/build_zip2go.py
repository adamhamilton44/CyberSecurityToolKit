#!/usr/bin/env python3
"""Build the reviewable portable assessment edition; never execute old payloads."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tools/zip2go'
DEST = ROOT / 'scripts/lib/CSTK_Zip2Go.zip'
ENTRY_POINTS = ('run_me.sh', 'system_info.sh', 'network_info.sh', 'permissions_audit.sh',
                'security_config.sh', 'file_inventory.sh', 'serve_files.sh', 'verify.sh', 'web_tls_check.sh',
                'random_user_agent.sh', 'archive_helper.sh', 'files_of_interest.sh', 'sweeper.sh', 'modern_wordlist_creater.sh',
                'HideInfo.sh', 'am_i_on_a_vm.sh', 'make_ssh_keys.sh', 'enumeration.sh')
LIB_FILES = ('common.sh', 'inventory.py', 'serve_files.py', 'portable_utils.py', 'assessment_helpers.py', 'enumeration.py')

VENDOR_FILES = ('les.sh', 'LES-LICENSE', 'unix-privesc-check.sh', 'profile.patch',
                'linpeas-enumeration.sh', 'PEASS-LICENSE', 'PROFILES.json', 'GTFOBINS-LICENSE')


def build(destination=DEST):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise SystemExit('This release builder requires Linux x86_64; source tools remain portable.')
    for command in ['shc', 'musl-gcc', 'strip']:
        if not shutil.which(command):
            raise SystemExit('Missing build dependency: ' + command)
    with tempfile.TemporaryDirectory(prefix='cstk-zip2go-build-') as tmp:
        stage = Path(tmp) / 'CSTK_2Go'
        (stage / 'lib').mkdir(parents=True)
        # Explicit release allowlist: never package reports, private files, or caches.
        for name in ('README.md', *ENTRY_POINTS):
            shutil.copy2(SOURCE / name, stage / name)
        for name in LIB_FILES:
            shutil.copy2(SOURCE / 'lib' / name, stage / 'lib' / name)
        (stage/'vendor').mkdir()
        for name in VENDOR_FILES:
            shutil.copy2(SOURCE/'vendor'/name, stage/'vendor'/name)
        shutil.copy2('/usr/share/common-licenses/GPL-2', stage/'vendor/COPYING.GPL-2')
        shutil.copy2(ROOT / 'scripts/bin/web_tls_security_assessment', stage / 'lib/web_tls_security_assessment.sh')
        shutil.copy2(ROOT / 'Other/LICENSE.txt', stage / 'LICENSE.txt')
        shutil.copy2('/usr/share/common-licenses/GPL-3', stage / 'COPYING.GPL-3.txt')
        shutil.copy2('/usr/share/doc/musl/copyright', stage / 'LICENSE.musl.txt')
        binaries = stage / 'bin/linux-x86_64'
        generated = stage / 'build/generated'
        binaries.mkdir(parents=True)
        generated.mkdir(parents=True)
        license_text = subprocess.run(['shc', '-C'], capture_output=True, text=True, check=True)
        (stage / 'LICENSE.shc.txt').write_text(license_text.stdout + license_text.stderr)
        env = dict(os.environ, CC='musl-gcc', CFLAGS='-static -Os', LDFLAGS='-static')
        for script in sorted(stage.glob('*.sh')):
            subprocess.run(['shc', '-r', '-f', str(script), '-o', str(binaries / script.stem)],
                           env=env, check=True, capture_output=True)
            subprocess.run(['strip', str(binaries / script.stem)], check=True)
            shutil.move(str(script) + '.x.c', generated / (script.stem + '.c'))
            (Path(str(script) + '.x')).unlink(missing_ok=True)
        (stage / 'BUILD.json').write_text(json.dumps({
            'edition': 'portable-assessment', 'version': '2026.10.21',
            'launcher_architecture': 'linux-x86_64', 'launcher_libc': 'static-musl',
            'launcher_command': 'CC=musl-gcc CFLAGS="-static -Os" LDFLAGS=-static shc -r -f INPUT -o OUTPUT',
            'source_fallback': True,
            'web_tls_source_sha256': hashlib.sha256((stage / 'lib/web_tls_security_assessment.sh').read_bytes()).hexdigest(),
        }, indent=2) + '\n')
        entries = sorted(p for p in stage.rglob('*') if p.is_file())
        (stage / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(stage).as_posix() + '\n'
            for p in entries))
        fd, temporary = tempfile.mkstemp(prefix='.zip2go-', suffix='.zip', dir=destination.parent)
        os.close(fd)
        try:
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for path in sorted(stage.rglob('*')):
                    if not path.is_file():
                        continue
                    info = zipfile.ZipInfo('CSTK_2Go/' + path.relative_to(stage).as_posix(), (2026, 10, 21, 0, 0, 0))
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    executable = path.parent == binaries or path.suffix == '.sh' and path.parent == stage
                    info.external_attr = (0o100755 if executable else 0o100644) << 16
                    archive.writestr(info, path.read_bytes())
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    print('Built ' + str(destination))


if __name__ == '__main__':
    build()
