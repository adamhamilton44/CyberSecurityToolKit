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
        if (os.environ.get('FORCE_ALL_MISSING') or package=='pipx' or package in os.environ.get('FORCE_MISSING','').split(',')) and package not in packages: sys.exit(1)
        print('installed',end='')
elif name=='apt-get':
    if 'install' in args:
        target=[args[-1]] if args[-1] and not args[-1].startswith('-') else []
        packages=sorted(set(packages+['pipx','python-helper']+target))
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
elif name=='go': sys.exit('unexpected automatic Go build')
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

    def test_non_c_locale_full_roundtrip(self):
        # Punctuation sorts differently in C and common desktop UTF-8 locales.
        (self.mounts['/mnt/mock']/'packages.json').write_text(
            json.dumps(['alpha:amd64', 'alpha-tools', 'zlib1g:amd64']))
        result=self.install(LC_ALL='en_US.utf8', FORCE_MISSING='apache-users,apktool,arp-scan,aria2,arjun')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertNotIn('not in sorted order',result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        self.assertEqual(set((state/'packages').read_text().split()),{'pipx','python-helper','apache-users','apktool','arp-scan','aria2','arjun'})
        for name in ['apache-users','apktool','arp-scan','aria2','arjun']:
            log=(self.checkout/'log/package_manager'/(name+'.log')).read_text()
            self.assertNotIn('not in sorted order',log)
            self.assertNotIn('Unable to record package changes',log)
        self.assertEqual(list(state.glob('packages.before.*')),[])
        result=self.run_box('bash uninstall.sh all',{'LC_ALL':'en_US.utf8'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(set(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text())),
                         {'alpha:amd64','alpha-tools','zlib1g:amd64'})

    def test_every_dependency_install_command_and_uninstall(self):
        # Exercise each dependency invocation, not only the already-installed
        # branch. Managers are doubles; this does not assert mirror availability.
        result=self.install(LC_ALL='en_US.utf8',FORCE_ALL_MISSING='1')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        packages=set(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()))
        expected=set(json.loads((ROOT/'tools/dependency_policy.json').read_text())['default_system_packages'])
        self.assertEqual(packages,expected|{'python-helper'})
        self.assertTrue({'apache-users','apktool','arp-scan','aria2','arjun','pipx'} <= packages)
        for log in (self.checkout/'log/package_manager').glob('*.log'):
            self.assertNotIn('not in sorted order',log.read_text(),str(log))
        result=self.run_box('bash uninstall.sh all',{'LC_ALL':'en_US.utf8'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),[])

    def test_updater_skips_legacy_katana_record(self):
        source=(self.checkout/'scripts/lib/cstk_update.sh').read_text()
        source=source.rsplit('main "$@"',1)[0]
        (self.checkout/'updater-functions.sh').write_text(source)
        result=self.run_box('source updater-functions.sh check /mnt/CSTK; GITHUB_TOOLS=(katana vulscan); check_github_tools && update_github_tools')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('no longer managed',result.stdout)
        self.assertIn('no Go modules will be downloaded',result.stdout)
        self.assertIn('Skipping retired Vulscan',result.stdout)
        calls=self.mounts['/mnt/mock']/'calls'
        self.assertFalse(calls.exists() and any(line.startswith('go ') for line in calls.read_text().splitlines()))

    def test_retired_optional_pipx_records_are_not_upgraded(self):
        source=(self.checkout/'scripts/lib/cstk_update.sh').read_text().rsplit('main "$@"',1)[0]
        (self.checkout/'updater-functions.sh').write_text(source)
        result=self.run_box('source updater-functions.sh check /mnt/CSTK; PYTHON_PACKAGES=(naminter bloodhound-ce); check_python_tools && update_python_tools')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Skipping retired optional pipx application: naminter',result.stdout)
        calls=self.mounts['/mnt/mock']/'calls'
        self.assertFalse(calls.exists() and 'pipx upgrade' in calls.read_text())

    def test_removed_defaults_are_not_claimed_or_purged_when_preexisting(self):
        original=['argon2','mongodb-server-core','redis','openssh-server','npm','pyenv-runtime']
        (self.mounts['/mnt/mock']/'packages.json').write_text(json.dumps(original))
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=self.run_box('bash uninstall.sh all')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(set(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text())),set(original))

    def test_snapshot_failure_propagates_without_caller_pipefail(self):
        result=self.run_box("source scripts/lib/install_state.sh; dpkg-query() { return 42; }; cstk_package_snapshot apt-get")
        self.assertNotEqual(result.returncode,0)

    def test_package_failure_preserves_status_and_dependency_ledger(self):
        result=self.run_box("source scripts/lib/install_state.sh; home_dir=/mnt/CSTK; cstk_state_init && cstk_package_transaction apt-get apt-get install pipx", {'LC_ALL':'en_US.utf8','FAIL_INSTALL':'1'})
        self.assertEqual(result.returncode,1)
        self.assertNotIn('not in sorted order',result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        self.assertEqual(set((state/'packages').read_text().split()),{'pipx','python-helper'})
        self.assertEqual(list(state.glob('packages.before.*')),[])

    def test_bad_snapshot_keeps_original_ledger_and_recovery_files(self):
        result=self.run_box("""source scripts/lib/install_state.sh
home_dir=/mnt/CSTK
cstk_state_init || exit 1
printf 'original-package\\n' > "$cstk_state_dir/packages"
cstk_package_snapshot() { printf 'zlib\\nalpha\\n'; }
cstk_package_transaction apt-get true
""")
        self.assertNotEqual(result.returncode,0)
        state=self.mounts['/var']/'lib/cstk'
        self.assertEqual((state/'packages').read_text(),'original-package\n')
        self.assertTrue(list(state.glob('packages.before.*')))
        result=self.run_box('bash uninstall.sh all')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('ledger recovery',result.stderr)

    def test_journaled_launcher_directory_is_rejected_without_modification(self):
        source=(self.checkout/'install.sh').read_text().split('# Main installation process')[0]
        (self.checkout/'functions.sh').write_text(source)
        result=self.run_box('source functions.sh; cstk_state_init && cstk_track_path /usr/local/bin/cstk')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        directory=self.mounts['/usr/local']/'bin/cstk'
        nested=directory/'usr/local/bin'; nested.mkdir(parents=True)
        (nested/'keep').write_text('preserve')
        result=self.run_box('source functions.sh; link_main_script')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('directory or special file',result.stderr)
        self.assertEqual((nested/'keep').read_text(),'preserve')
        self.assertFalse((directory/'cstk.sh').exists())

    def test_completion_banner_requires_launcher_to_remain_valid(self):
        # Simulate destination corruption after the link step, before success.
        path=self.checkout/'install.sh'
        script=path.read_text().replace('finish_setup || exit 1\n',
            'finish_setup || exit 1\nrm -f -- /usr/local/bin/cstk\nln -s /usr/bin/true /usr/local/bin/cstk\n')
        path.write_text(script)
        result=self.install()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('Installation complete!',result.stdout)
        self.assertTrue((self.mounts['/var']/'lib/cstk').exists())

    def test_launcher_check_rejects_path_without_usr_local_bin(self):
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        source=(self.checkout/'install.sh').read_text().split('# Main installation process')[0]
        (self.checkout/'functions.sh').write_text(source)
        result=self.run_box('source functions.sh; PATH=/usr/sbin:/usr/bin:/sbin:/bin; verify_installed_launcher')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Check sudo secure_path includes /usr/local/bin',result.stderr)
        result=self.run_box('/usr/local/bin/cstk --version')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('version:',result.stdout)

    def test_launcher_wrong_link_and_missing_target_fail_final_check(self):
        source=(self.checkout/'install.sh').read_text().split('# Main installation process')[0]
        (self.checkout/'functions.sh').write_text(source)
        link=self.mounts['/usr/local']/'bin/cstk'
        for target in ['/usr/bin/true','/nonexistent-cstk']:
            link.symlink_to(target)
            result=self.run_box('source functions.sh; verify_installed_launcher')
            self.assertNotEqual(result.returncode,0)
            link.unlink()

    def test_pending_journal_blocks_uninstall_before_any_artifact_removal(self):
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        (state/'packages.before.pending').write_text('base:amd64\n')
        rc=self.mounts['/root']/'.bashrc'; original=rc.read_text()
        result=self.run_box('bash uninstall.sh all')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('no uninstall changes made',result.stderr)
        self.assertTrue((self.mounts['/usr/local']/'bin/cstk').is_symlink())
        self.assertTrue((self.mounts['/opt']/'cstk/pipx/holehe').exists())
        self.assertTrue((self.mounts['/usr/share']/'man/man1/cstk.1.gz').exists())
        self.assertEqual(rc.read_text(),original)

    def test_roundtrip_reinstall_and_user_data(self):
        result=self.install()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        launcher=self.mounts['/usr/local']/'bin/cstk'
        self.assertTrue(launcher.is_symlink())
        self.assertEqual(os.readlink(launcher),'/mnt/CSTK/cstk.sh')
        result=self.run_box('/usr/local/bin/cstk --help')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('SYNOPSIS:',result.stdout)
        self.assertEqual(set((state/'packages').read_text().split()),{'pipx','python-helper'})
        self.assertTrue((self.mounts['/opt']/'cstk/pipx/holehe').exists())
        self.assertFalse((self.mounts['/opt']/'cstk/bin/katana').exists())
        calls=(self.mounts['/mnt/mock']/'calls').read_text().splitlines()
        self.assertFalse(any(line.startswith('go ') for line in calls))
        self.assertFalse((self.mounts['/usr/share']/'nmap/scripts/vulscan').exists())
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
''', {'LC_ALL':'en_US.utf8'})
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
