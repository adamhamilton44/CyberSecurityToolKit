#!/usr/bin/env python3
"""Build CSTK single-file runtimes and maintainer utilities; run in a build venv."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(sys.executable if getattr(sys,'frozen',False) else __file__).resolve().parents[2]

def main():
    for tool in ('upx','shc'):
        if not shutil.which(tool): raise SystemExit(f'Missing build tool: {tool}')
    with tempfile.TemporaryDirectory(prefix='cstk-release-build-') as tmp:
        temp=Path(tmp)
        entries=[('cstk_containers',ROOT/'scripts/source/container_tools/cstk_containers.py')]
        entries += [('maint_'+name,ROOT/f'scripts/tools/{name}.py') for name in
                    ('audit_dependencies','build_provisioner','build_zip2go','recover_package_ledger')]
        for name,source in entries:
            subprocess.run([sys.executable,'-m','PyInstaller','--clean','--noconfirm','--onefile','--strip',
                            '--name',name,'--distpath',str(temp/'dist'),'--workpath',str(temp/'build'),
                            '--specpath',str(temp/'spec'),str(source)],check=True)
            packed=temp/'dist'/name
            subprocess.run(['upx','-9',str(packed)],check=True)
            shutil.copy2(packed,ROOT/'scripts/bin'/name)
        source=temp/'run_uninstall_test.sh'
        shutil.copy2(ROOT/'scripts/tools/run_uninstall_test.sh',source)
        packed=temp/'maint_run_uninstall_test'
        subprocess.run(['shc','-r','-f',str(source),'-o',str(packed)],check=True)
        subprocess.run(['upx','-9',str(packed)],check=True)
        shutil.copy2(packed,ROOT/'scripts/bin'/packed.name)
        subprocess.run([sys.executable,'-m','PyInstaller','--clean','--noconfirm',
                        '--distpath',str(temp/'dist'),'--workpath',str(temp/'ai-build'),
                        str(ROOT/'scripts/source/cstk_ai/Etc_cstk_ai.spec')],check=True)
        packed=temp/'dist/Etc_cstk_ai'
        subprocess.run(['upx','-9',str(packed)],check=True)
        shutil.copy2(packed,ROOT/'scripts/bin/Etc_cstk_ai')

if __name__=='__main__': main()
