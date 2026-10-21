"""Run actual install/uninstall scripts in an offline Bubblewrap filesystem.

Package managers and network/build tools are doubles. Host system paths are
read-only; all installer destinations are disposable bind mounts.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/python3
from pathlib import Path
import json, os, sys
name=Path(sys.argv[0]).name
args=sys.argv[1:]
state=Path('/mnt/mock/packages.json')
packages=json.loads(state.read_text()) if state.exists() else []
with open('/mnt/mock/calls','a') as log: log.write(name+' '+ ' '.join(args)+'\n')
if name=='dpkg-query':
    if any('binary:Package' in a for a in args):
        print('base:amd64 installed\npython3:amd64 installed')
        for p in packages: print(p+' installed')
    else:
        package=args[-1]
        if package=='pipx' and package not in packages: sys.exit(1)
        print('installed',end='')
elif name=='apt-get':
    if 'install' in args:
        packages=sorted(set(packages+['pipx','python-helper']))
        state.write_text(json.dumps(packages))
        if os.environ.get('FAIL_INSTALL'): sys.exit(1)
    if 'purge' in args:
        targets=args[args.index('--')+1:]
        if '-s' in args:
            for p in targets: print('Purg '+p)
            if os.environ.get('UNTRACKED_REMOVAL'): print('Remv base:amd64')
        elif os.environ.get('FAIL_REMOVE'): sys.exit(1)
        else: state.write_text(json.dumps([p for p in packages if p not in targets]))
elif name=='pipx':
    directory=Path(os.environ['PIPX_HOME']); directory.mkdir(parents=True,exist_ok=True)
    if args[0]=='install':
        (directory/args[1]).mkdir(exist_ok=True)
        target=Path(os.environ['PIPX_BIN_DIR'])/args[1]
        target.write_text('#!/bin/sh\nexit 0\n'); target.chmod(0o755)
    elif args[0]=='list':
        for p in directory.iterdir(): print(p.name+' 1.0' if '--short' in args else '   package '+p.name+' 1.0')
elif name=='git':
    dest=Path(args[-1]); dest.mkdir(parents=True,exist_ok=True)
    (dest/'.git').mkdir(exist_ok=True)
    if 'mimipenguin' in str(dest):
        for n in ['mimipenguin.sh','mimipenguin.py']: (dest/n).write_text('# test tool\n')
elif name=='go':
    dest=Path(os.environ['GOBIN'])/'katana'
    dest.write_text('#!/bin/sh\nexit 0\n'); dest.chmod(0o755)
elif name in ['nmap','mandb','mongosh','shc','nrich']: pass
else: sys.exit('unexpected mock '+name)
'''

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('bwrap'):
            self.skipTest('Bubblewrap required')
        self.tmp=tempfile.TemporaryDirectory(prefix='cstk-lifecycle-')
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.checkout=self.base/'CSTK'
        shutil.copytree(ROOT,self.checkout,ignore=shutil.ignore_patterns('.git','__pycache__','Other','data','log'))
        (self.checkout/'Other/SecurityChecks').mkdir(parents=True)
        (self.checkout/'Other/SecurityChecks/check_hashes.sh').write_text('# fixture\n')
        self.mounts={}
        for name,target in [('etc','/etc'),('var','/var'),('opt','/opt'),('root','/root'),
                            ('local','/usr/local'),('share','/usr/share'),('mock','/mnt/mock')]:
            path=self.base/name; path.mkdir(); self.mounts[target]=path
        shutil.copytree('/etc/alternatives', self.mounts['/etc']/'alternatives', symlinks=True)
        for filename in ['passwd','group']:
            shutil.copy2('/etc/'+filename,self.mounts['/etc']/filename)
        (self.mounts['/etc']/'passwd').write_text('root:x:0:0:root:/root:/bin/bash\n')
        localbin=self.mounts['/usr/local']/'bin'; localbin.mkdir()
        for name in ['shc','mongosh','nrich']:
            p=localbin/name;p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
        (localbin/'cstk_wrapper').write_text('preexisting wrapper\n')
        (self.mounts['/usr/share']/'man/man1').mkdir(parents=True)
        (self.mounts['/usr/share']/'nmap/scripts').mkdir(parents=True)
        (self.mounts['/root']/'.bashrc').write_text('# original rc\n')
        mock=self.mounts['/mnt/mock'];(mock/'bin').mkdir()
        for name in ['apt-get','dpkg','dpkg-query','pipx','git','go','nmap','mandb']:
            p=mock/'bin'/name;p.write_text(MOCK);p.chmod(0o755)
        (mock/'packages.json').write_text('[]')

    def run_box(self,command,env=None,input=''):
        argv=['bwrap','--ro-bind','/','/','--unshare-user','--uid','0','--gid','0',
              '--unshare-pid','--unshare-net','--proc','/proc','--dev','/dev',
              '--tmpfs','/tmp','--tmpfs','/run','--tmpfs','/mnt','--bind',str(self.base),'/mnt']
        for target,path in self.mounts.items(): argv+=['--bind',str(path),target]
        argv+=['--clearenv','--setenv','PATH','/mnt/mock/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               '--setenv','HOME','/root','--setenv','USER','root','--setenv','SHELL','/bin/bash']
        for key,value in (env or {}).items(): argv+=['--setenv',key,value]
        argv+=['--chdir','/mnt/CSTK','bash','-c',command]
        return subprocess.run(argv,input=input,text=True,capture_output=True,timeout=90)

    def install(self,**env):
        # Completion user=yes, root=yes, launcher pause, auth=no, large dataset=no.
        result=self.run_box('bash install.sh',env,input='1\n1\n\n2\nn\n')
        return result

    def test_roundtrip_reinstall_and_user_data(self):
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        self.assertEqual(set((state/'packages').read_text().split()),{'pipx','python-helper'})
        self.assertTrue((self.mounts['/opt']/'cstk/pipx/holehe').exists())
        self.assertTrue((self.mounts['/etc']/'cstk/lib_decryption.key').exists())
        self.assertTrue((self.mounts['/usr/share']/'man/man1/cstk.1.gz').exists())
        rc=self.mounts['/root']/'.bashrc'
        with rc.open('a') as f:f.write('# added after install\n')
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        user_data=self.mounts['/root']/'.local/share/cstk/Logs/report.txt'
        user_data.write_text('keep report')
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(state.exists())
        self.assertFalse((self.mounts['/opt']/'cstk').exists())
        self.assertFalse((self.mounts['/etc']/'cstk').exists())
        self.assertFalse((self.mounts['/usr/share']/'man/man1/cstk.1.gz').exists())
        self.assertFalse((self.mounts['/usr/share']/'nmap/scripts/vulscan').exists())
        self.assertEqual(rc.read_text(),'# original rc\n# added after install\n')
        self.assertEqual((self.mounts['/usr/local']/'bin/cstk_wrapper').read_text(),'preexisting wrapper\n')
        self.assertFalse((self.mounts['/usr/local']/'bin/mimipenguin.py').exists())
        self.assertTrue((self.mounts['/usr/local']/'bin/shc').exists())
        self.assertEqual(user_data.read_text(),'keep report')
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),[])
        self.assertFalse((self.checkout/'install.sh').exists())

    def test_created_shell_file_cleanup_is_retryable(self):
        rc=self.mounts['/root']/'.bashrc'; rc.unlink()
        result=self.install(); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=self.run_box('bash uninstall.sh all',{'FAIL_REMOVE':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(rc.exists())
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_state_directory_collision_is_rejected(self):
        directory=self.mounts['/opt']/'cstk';directory.mkdir()
        (directory/'unrelated').write_text('keep')
        result=self.install()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((directory/'unrelated').read_text(),'keep')
        self.assertFalse((self.mounts['/etc']/'cstk').exists())

    def test_legacy_cleanup_and_package_ownership(self):
        checks=self.checkout/'Other/SecurityChecks'
        (checks/'.github_installed_tools').write_text('katana\nmimipenguin\nshc\nmongosh-archive\nnrich\nvulscan\n')
        (checks/'.python_pipx_installed_tools').write_text('')
        (checks/'.package_management_installed_tools').write_text('pipx\n')
        (self.mounts['/mnt/mock']/'packages.json').write_text('["pipx", "nrich", "unrelated"]')
        localbin=self.mounts['/usr/local']/'bin'
        for tool in ['cstk','mimipenguin.sh','mimipenguin.py','mongosh_crypt_v1.so']:
            (localbin/tool).write_text('fixture')
        katana=self.mounts['/root']/'go/bin/katana'; katana.parent.mkdir(parents=True); katana.write_text('fixture')
        (self.mounts['/usr/share']/'man/man1/cstk.1.gz').write_text('compressed-only')
        (self.mounts['/usr/share']/'nmap/scripts/vulscan').mkdir()
        rc=self.mounts['/root']/'.bashrc'
        rc.write_text('# keep\nsource "/mnt/CSTK/scripts/lib/tab_complete.cstk"\n# keep too\n')
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(katana.exists())
        self.assertFalse((localbin/'mimipenguin.py').exists())
        self.assertFalse((self.mounts['/usr/share']/'man/man1/cstk.1.gz').exists())
        self.assertEqual(rc.read_text(),'# keep\n# keep too\n')
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),['unrelated'])

    def test_real_dpkg_and_apt_roundtrip_without_network(self):
        # Use actual package tools on a disposable dpkg database and two local
        # fixture packages; no repository metadata or downloads are necessary.
        for tool in ['apt-get','dpkg','dpkg-query']:
            (self.mounts['/mnt/mock']/'bin'/tool).unlink()
        shutil.copytree('/usr/share/dpkg',self.mounts['/usr/share']/'dpkg')
        (self.mounts['/etc']/'apt/apt.conf.d').mkdir(parents=True)
        (self.mounts['/usr/local']/'share').mkdir()
        db=self.mounts['/var']/'lib/dpkg'
        (db/'updates').mkdir(parents=True)
        (db/'status').write_text('Package: cstk-fixture-base\nStatus: install ok installed\nArchitecture: all\nVersion: 1.0\nDescription: base directory ownership fixture\n\n')
        (db/'info').mkdir()
        (db/'info/cstk-fixture-base.list').write_text('/.\n/usr\n/usr/local\n/usr/local/share\n')
        (self.mounts['/var']/'log/apt').mkdir(parents=True)
        (self.mounts['/var']/'cache/apt/archives/partial').mkdir(parents=True)
        for package,depends in [('cstk-fixture-dependency',''),('cstk-fixture-tool','cstk-fixture-dependency')]:
            build=self.base/package
            (build/'DEBIAN').mkdir(parents=True)
            control=f'Package: {package}\nVersion: 1.0\nArchitecture: all\nMaintainer: CSTK Tests <test@example.invalid>\nDescription: disposable lifecycle fixture\n'
            if depends: control+=f'Depends: {depends}\n'
            (build/'DEBIAN/control').write_text(control)
            payload=build/'usr/local/share/cstk-fixtures'
            payload.mkdir(parents=True)
            (payload/package).write_text('fixture')
            # Omit parent directories owned by the read-only sandbox base.
            # dpkg then owns only the writable fixture subtree.
            def root_owner(info):
                info.uid=info.gid=0; info.uname=info.gname='root'; return info
            with tarfile.open(build/'control.tar.gz','w:gz',format=tarfile.GNU_FORMAT) as archive:
                archive.add(build/'DEBIAN/control',arcname='./control',filter=root_owner)
            with tarfile.open(build/'data.tar.gz','w:gz',format=tarfile.GNU_FORMAT) as archive:
                archive.add(payload,arcname='./usr/local/share/cstk-fixtures',filter=root_owner)
            (build/'debian-binary').write_text('2.0\n')
            built=subprocess.run(['ar','r',str(self.base/(package+'.deb')),
                str(build/'debian-binary'),str(build/'control.tar.gz'),str(build/'data.tar.gz')],
                capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
        result=self.run_box('''set -o pipefail
home_dir=/mnt/CSTK
source scripts/lib/install_state.sh
cstk_state_init && cstk_package_transaction apt-get dpkg -i /mnt/cstk-fixture-dependency.deb /mnt/cstk-fixture-tool.deb
''')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        self.assertEqual(set((state/'packages').read_text().split()),{'cstk-fixture-dependency','cstk-fixture-tool'})
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse((self.mounts['/usr/local']/'share/cstk-fixtures').exists())
        self.assertFalse(state.exists())

    def test_kali_7zip_package_alias(self):
        functions=(self.checkout/'install.sh').read_text().split('# Main installation process')[0]
        (self.checkout/'functions.sh').write_text(functions)
        result=self.run_box('source functions.sh && package_candidates p7zip-full deb')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'7zip\np7zip-full\n')

    def test_partial_install_is_removable(self):
        result=self.install(FAIL_INSTALL='1')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('Installation complete!',result.stdout)
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),[])

    def test_failed_uninstall_retains_state_and_can_retry(self):
        result=self.install();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=self.run_box('bash uninstall.sh all',{'FAIL_REMOVE':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertTrue((self.checkout/'uninstall.sh').exists())
        self.assertTrue((self.mounts['/var']/'lib/cstk/packages').exists())
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_refuses_removing_untracked_dependents(self):
        result=self.install();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=self.run_box('bash uninstall.sh all',{'UNTRACKED_REMOVAL':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('untracked package',result.stderr)
        self.assertTrue((self.checkout/'uninstall.sh').exists())

if __name__=='__main__': unittest.main()
