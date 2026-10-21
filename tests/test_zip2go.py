"""Portable archive tests: isolated local checks, archive integrity, HTTP controls."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import tarfile
import io
import time
import unittest
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / 'scripts/lib/CSTK_Zip2Go.zip'


class Zip2GoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='zip2go-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        with zipfile.ZipFile(ARCHIVE) as archive:
            for entry in archive.infolist():
                self.assertFalse(entry.flag_bits & 1, 'Assessment release must be reviewable without a password')
                self.assertTrue(entry.filename.startswith('CSTK_2Go/'))
                self.assertNotIn('..', Path(entry.filename).parts)
                archive.extract(entry, self.base)
                (self.base / entry.filename).chmod((entry.external_attr >> 16) & 0o777)
        self.kit = self.base / 'CSTK_2Go'

    def run_box(self, command, env=None):
        if not shutil.which('bwrap'):
            self.skipTest('Bubblewrap unavailable')
        args = ['bwrap', '--ro-bind', '/', '/', '--unshare-user', '--uid', '1000', '--gid', '1000',
                '--unshare-net', '--unshare-pid', '--proc', '/proc', '--dev', '/dev',
                '--tmpfs', '/tmp', '--tmpfs', '/mnt', '--bind', str(self.base), '/mnt/kit space',
                '--clearenv', '--setenv', 'HOME', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin:/usr/sbin:/sbin']
        for key, value in (env or {}).items():
            args += ['--setenv', key, value]
        args += ['--chdir', '/tmp', 'bash', '-c', command]
        return subprocess.run(args, text=True, capture_output=True, timeout=75)

    def test_capture_marks_successful_large_output_partial(self):
        result = self.run_box("KIT_ROOT='/mnt/kit space/CSTK_2Go'; source \"$KIT_ROOT/lib/common.sh\"; OUTPUT=/tmp/capture-test; init_report cap; capture fixture python3 -c 'print(\"x\"*65536)'; finish_report; cat \"$REPORT\"")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[PARTIAL] Output reached the 64 KiB cap', result.stdout)
        self.assertIn('skipped/partial: 1', result.stdout)

    def test_manifest_and_maintained_checker(self):
        files = set()
        for line in (self.kit / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((self.kit / name).read_bytes()).hexdigest(), digest, name)
            files.add(name)
        actual = {p.relative_to(self.kit).as_posix() for p in self.kit.rglob('*') if p.is_file()}
        self.assertEqual(actual - {'SHA256SUMS'}, files)
        self.assertEqual((self.kit / 'lib/web_tls_security_assessment.sh').read_bytes(),
                         (ROOT / 'scripts/bin/web_tls_security_assessment').read_bytes())
        self.assertFalse(any('BrowserThief' in x or 'LogCleaner' in x for x in files))

    def test_sources_and_binary_help_from_another_directory(self):
        for script in self.kit.glob('*.sh'):
            result = self.run_box(f'"/mnt/kit space/CSTK_2Go/{script.name}" --help')
            self.assertEqual(result.returncode, 0, result.stderr)
            source_help = result.stdout.splitlines()[0]
            binary = self.kit / 'bin/linux-x86_64' / script.stem
            self.assertTrue(binary.exists())
            result = self.run_box(f'"/mnt/kit space/CSTK_2Go/bin/linux-x86_64/{script.stem}" --help')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[0], source_help)

    def test_unprivileged_runner_and_private_reports(self):
        result = self.run_box('"/mnt/kit space/CSTK_2Go/run_me.sh" --output "/mnt/kit space/results"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        reports = list((self.base / 'results').rglob('report.txt'))
        self.assertEqual(len(reports), 5)
        for report in reports:
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
            self.assertIn('[COMPLETE]', report.read_text())
        result = self.run_box('"/mnt/kit space/CSTK_2Go/bin/linux-x86_64/system_info" --output "/mnt/kit space/binary-reports"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(list((self.base / 'binary-reports').rglob('report.txt'))), 1)

    def test_read_only_kit_and_symlink_output_refusal(self):
        result = self.run_box('chmod -R a-w "/mnt/kit space/CSTK_2Go"; "/mnt/kit space/CSTK_2Go/run_me.sh" --output "/mnt/kit space/writable"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Restore modes so unittest cleanup can remove the extracted tree.
        for directory, _, files in os.walk(self.kit):
            Path(directory).chmod(0o755)
            for name in files:
                (Path(directory) / name).chmod(0o644)
        target = self.base / 'target'; target.mkdir()
        (self.base / 'alias').symlink_to(target)
        result = self.run_box('bash "/mnt/kit space/CSTK_2Go/system_info.sh" --output "/mnt/kit space/alias"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_inventory_scope_symlinks_and_entry_limit(self):
        directory = self.base / 'sample'; directory.mkdir()
        (directory / 'picked.txt').write_text('DO_NOT_COLLECT_CONTENTS')
        (directory / 'outside').symlink_to('/etc', target_is_directory=True)
        for i in range(220): (directory / f'item-{i}').touch()
        result = self.run_box('"/mnt/kit space/CSTK_2Go/file_inventory.sh" --path "/mnt/kit space/sample" --output "/mnt/kit space/inventory"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = next((self.base / 'inventory').rglob('report.txt')).read_text()
        self.assertNotIn('DO_NOT_COLLECT_CONTENTS', text)
        self.assertNotIn('outside/passwd', text)
        summary = [json.loads(line) for line in text.splitlines() if line.startswith('{')][-1]
        self.assertLessEqual(summary['entries'], 200)
        self.assertTrue(summary['truncated'])

    def test_verify_detects_tampering(self):
        result = self.run_box('"/mnt/kit space/CSTK_2Go/verify.sh"')
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.kit / 'README.md').write_text('modified')
        result = self.run_box('"/mnt/kit space/CSTK_2Go/verify.sh"')
        self.assertNotEqual(result.returncode, 0)

    def test_server_selected_files_only_and_request_limit(self):
        selected = self.base / 'approved.txt'; selected.write_text('approved content')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        process = subprocess.Popen(['python3', str(self.kit / 'lib/serve_files.py'), '--file', str(selected),
            '--port', str(port), '--duration', '10', '--max-downloads', '1'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        base = f'http://127.0.0.1:{port}'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1): break
            except OSError: time.sleep(0.02)
        else: self.fail('File service did not start')
        for path in ['/', '/README.md', '/%2e%2e/etc/passwd', '/approved.txt?token=value']:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                opener.open(base + path, timeout=2)
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()
        with opener.open(base + '/approved.txt', timeout=2) as response:
            self.assertEqual(response.read(), b'approved content')
            self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertNotIn('token=value', stdout + stderr)
        self.assertNotIn('/etc/passwd', stdout + stderr)

    def test_web_tls_adapter_uses_explicit_output(self):
        if not shutil.which('curl'):
            self.skipTest('curl unavailable')
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'ok')
            def do_OPTIONS(self):
                self.send_response(204); self.send_header('Allow','GET, OPTIONS'); self.end_headers()
            def log_message(self, *args): pass
        server = HTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        output = self.base / 'web-output'
        legacy = self.base / 'unexpected-old-output'
        env = dict(os.environ, CSTK_LOOT_DIR=str(legacy), CSTK_USER_DATA_DIR=str(legacy), HOME=str(self.base))
        result = subprocess.run([str(self.kit/'web_tls_check.sh'),f'http://127.0.0.1:{server.server_port}/',
            '--output',str(output)],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue(list(output.rglob('report.txt')))
        self.assertFalse(legacy.exists())
        self.assertFalse((self.base/'.local/share/cstk').exists())

    def test_path_and_symlink_invocation(self):
        result = self.run_box('ln -s "/mnt/kit space/CSTK_2Go/system_info.sh" /tmp/system-link; /tmp/system-link --help; '
            'PATH="/mnt/kit space/CSTK_2Go/bin/linux-x86_64:$PATH"; system_info --help')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.count('Usage: system_info.sh'),2)

    def test_minimal_environment_skips_missing_optional_commands(self):
        minimal = self.base / 'minimal'; minimal.mkdir()
        for name in ['dirname','mkdir','mktemp','chmod','date','head','tr','uname']:
            (minimal/name).symlink_to('/usr/bin/'+name)
        result = self.run_box('PATH="/mnt/kit space/minimal"; "/mnt/kit space/CSTK_2Go/run_me.sh" --output "/mnt/kit space/minimal-results"')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        reports = list((self.base/'minimal-results').rglob('report.txt'))
        self.assertEqual(len(reports),5)
        self.assertTrue(any('timeout is unavailable' in p.read_text() for p in reports))
        self.assertTrue(all('[COMPLETE]' in p.read_text() for p in reports))

    def test_server_lifetime_bounds_incomplete_requests(self):
        selected = self.base/'selected'; selected.write_text('data')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        process = subprocess.Popen(['python3',str(self.kit/'lib/serve_files.py'),'--file',str(selected),
            '--port',str(port),'--duration','1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        for _ in range(100):
            try:
                client=socket.create_connection(('127.0.0.1',port),timeout=0.1); break
            except OSError: time.sleep(0.01)
        else: self.fail('File service did not start')
        with client:
            client.sendall(b'GET /selected HTTP/1.1\r\nX-Incomplete: ')
            stdout,stderr=process.communicate(timeout=4)
        self.assertEqual(process.returncode,0,stdout+stderr)

    def test_random_user_agent_count_and_bounds(self):
        tool=self.kit/'random_user_agent.sh'
        result=subprocess.run([str(tool),'--count','5'],capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(result.stdout.splitlines()),5)
        result=subprocess.run([str(tool),'--count','100'],capture_output=True,text=True,timeout=3)
        self.assertNotEqual(result.returncode,0)

    def test_archive_zip_roundtrip_and_overwrite_refusal(self):
        source=self.base/'sample.zip'
        with zipfile.ZipFile(source,'w') as z:z.writestr('nested/file.txt','approved content')
        tool=self.kit/'archive_helper.sh'
        listing=subprocess.run([str(tool),'list',str(source)],capture_output=True,text=True,timeout=5)
        self.assertEqual(listing.returncode,0,listing.stderr)
        self.assertEqual(json.loads(listing.stdout)['path'],'nested/file.txt')
        destination=self.base/'extracted'
        result=subprocess.run([str(tool),'extract',str(source),str(destination)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        file=destination/'nested/file.txt'
        self.assertEqual(file.read_text(),'approved content')
        self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
        result=subprocess.run([str(tool),'extract',str(source),str(destination)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(file.read_text(),'approved content')

    def test_archive_tar_roundtrip(self):
        source=self.base/'sample.tar.gz'
        with tarfile.open(source,'w:gz') as tar:
            entry=tarfile.TarInfo('.');entry.type=tarfile.DIRTYPE;tar.addfile(entry)
            entry=tarfile.TarInfo('./file.txt');data=b'test';entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
        result=subprocess.run([str(self.kit/'archive_helper.sh'),'extract',str(source),str(self.base/'tar-output')],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.base/'tar-output/file.txt').read_bytes(),b'test')

    def test_archive_traversal_links_and_entry_limit(self):
        for kind in ['traversal','symlink','too-many']:
            source=self.base/(kind+'.zip')
            with zipfile.ZipFile(source,'w') as archive:
                if kind=='traversal':archive.writestr('../outside','data')
                elif kind=='symlink':
                    info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=(0o120777<<16)
                    archive.writestr(info,'/etc/passwd')
                else:
                    for i in range(1001):archive.writestr(str(i),'')
            destination=self.base/(kind+'-output')
            result=subprocess.run([str(self.kit/'archive_helper.sh'),'extract',str(source),str(destination)],capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0,kind)
            self.assertFalse(destination.exists())
        self.assertFalse((self.base/'outside').exists())

    def test_files_of_interest_is_scoped_metadata(self):
        sample=self.base/'selected-directory'; sample.mkdir()
        (sample/'settings.conf').write_text('DO_NOT_COLLECT_SETTINGS')
        (sample/'unselected.bin').write_text('DO_NOT_COLLECT_BINARY')
        result=subprocess.run([str(self.kit/'files_of_interest.sh'),'--path',str(sample),
            '--output',str(self.base/'interest-report')],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        report=next((self.base/'interest-report').rglob('report.txt')).read_text()
        self.assertIn('settings.conf',report)
        self.assertNotIn('unselected.bin',report)
        self.assertNotIn('DO_NOT_COLLECT',report)

    def helper(self,name,*args,env=None):
        return subprocess.run([str(self.kit/(name+'.sh')),*map(str,args)],env=env,
            capture_output=True,text=True,timeout=10)

    def test_virtualization_info_is_informational(self):
        result=self.helper('am_i_on_a_vm')
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertIn('observations',value)
        self.assertIn('No action changes',value['interpretation'])

    def test_wordlist_is_local_deduplicated_and_does_not_overwrite(self):
        source=self.base/'base.txt';source.write_text('Example\nExample\n')
        output=self.base/'words.txt'
        result=self.helper('modern_wordlist_creater','--input',source,'--output',output,'--suffix','123')
        self.assertEqual(result.returncode,0,result.stderr)
        words=output.read_text().splitlines()
        self.assertEqual(len(words),len(set(words)))
        self.assertIn('Example123',words)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
        result=self.helper('modern_wordlist_creater','--input',source,'--output',output)
        self.assertNotEqual(result.returncode,0)

    def test_encoding_roundtrip_and_no_output_symlink(self):
        source=self.base/'input';source.write_bytes(b'example\x00bytes')
        for encoding in ['base64','hex']:
            encoded=self.base/(encoding+'.encoded');decoded=self.base/(encoding+'.decoded')
            result=self.helper('HideInfo','encode','--format',encoding,'--input',source,'--output',encoded)
            self.assertEqual(result.returncode,0,result.stderr)
            result=self.helper('HideInfo','decode','--format',encoding,'--input',encoded,'--output',decoded)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(decoded.read_bytes(),source.read_bytes())
        alias=self.base/'alias-output';alias.symlink_to(source)
        result=self.helper('HideInfo','encode','--format','base64','--input',source,'--output',alias)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(source.read_bytes(),b'example\x00bytes')

    def test_ping_sweep_uses_only_explicit_small_scope(self):
        mock=self.base/'mock';mock.mkdir()
        ping=mock/'ping';ping.write_text('#!/bin/sh\nprintf "%s\n" "$*" >> "$PING_CALLS"\nexit 0\n');ping.chmod(0o755)
        calls=self.base/'ping-calls'
        env=dict(os.environ,PATH=str(mock)+':'+os.environ['PATH'],PING_CALLS=str(calls))
        result=self.helper('sweeper','--network','192.0.2.0/30',env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        rows=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([x['address'] for x in rows],['192.0.2.1','192.0.2.2'])
        self.assertEqual(len(calls.read_text().splitlines()),2)
        result=self.helper('sweeper','--network','192.0.0.0/16',env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(len(calls.read_text().splitlines()),2)

    def test_keygen_only_no_ssh_directory_modifications(self):
        mock=self.base/'mock';mock.mkdir()
        keygen=mock/'ssh-keygen'
        keygen.write_text('''#!/usr/bin/python3
from pathlib import Path
import sys
assert '-N' not in sys.argv
key=Path(sys.argv[sys.argv.index('-f')+1])
key.write_text('fixture private key')
Path(str(key)+'.pub').write_text('ssh-ed25519 fixture')
''');keygen.chmod(0o755)
        home=self.base/'home';(home/'.ssh').mkdir(parents=True)
        authorized=home/'.ssh/authorized_keys';authorized.write_text('keep existing access')
        directory=self.base/'generated-keys'
        env=dict(os.environ,HOME=str(home),PATH=str(mock)+':'+os.environ['PATH'])
        result=self.helper('make_ssh_keys','--directory',directory,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(authorized.read_text(),'keep existing access')
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((directory/'id_ed25519').stat().st_mode),0o600)
        self.assertEqual(len(list(directory.iterdir())),2)

    def test_helper_inputs_reject_symlinks(self):
        original=self.base/'original';original.write_text('data')
        link=self.base/'link';link.symlink_to(original)
        result=self.helper('HideInfo','encode','--format','base64','--input',link,'--output',self.base/'not-created')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.base/'not-created').exists())

    def test_encoding_maximum_payload_roundtrip(self):
        source=self.base/'maximum';source.write_bytes(b'A'*(1024*1024))
        encoded=self.base/'hex-maximum';decoded=self.base/'decoded-maximum'
        result=self.helper('HideInfo','encode','--format','hex','--input',source,'--output',encoded)
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.helper('HideInfo','decode','--format','hex','--input',encoded,'--output',decoded)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(decoded.read_bytes(),source.read_bytes())

    def test_enumeration_rejects_extra_flags_and_source_tampering(self):
        result=self.helper('enumeration','--tool','les','--fetch-binaries')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.kit/'reports').exists())
        (self.kit/'vendor/les.sh').write_text('# changed')
        result=self.helper('enumeration','--tool','les','--output',self.base/'enum-output')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('source has changed',result.stderr)

    def test_les_reports_candidates_for_synthetic_kernel(self):
        result=self.run_box('timeout 15 bash "/mnt/kit space/CSTK_2Go/vendor/les.sh" --kernel 4.4.0 --skip-more-checks')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('CVE-2016-5195',result.stdout)

    def test_enumeration_runner_preserves_incomplete_status(self):
        result=self.run_box('"/mnt/kit space/CSTK_2Go/enumeration.sh" --tool linpeas --seconds 1 --output "/mnt/kit space/enumeration"')
        metadata=next((self.base/'enumeration').rglob('assessment.json'))
        value=json.loads(metadata.read_text())
        self.assertIn(value['status'],['completed_unverified','incomplete_timeout','incomplete_tool_error'])
        self.assertNotIn('safe',value['status'])
        self.assertIn('-n',value['command'])
        self.assertNotIn('-a',value['command'])
        self.assertEqual(stat.S_IMODE(metadata.stat().st_mode),0o600)
        self.assertTrue(value['source']['omissions'])
        self.assertEqual(result.returncode,0 if value['status']=='completed_unverified' else 1)

    def test_upc_finds_inert_writable_config_and_leaves_it_unchanged(self):
        etc=self.base/'etc';etc.mkdir()
        shutil.copytree('/etc/alternatives',etc/'alternatives',symlinks=True)
        (etc/'passwd').write_text('root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n')
        (etc/'group').write_text('root:x:0:\nusers:x:1000:user\n')
        (etc/'nsswitch.conf').write_text('passwd: files\ngroup: files\n')
        (etc/'crontab').write_text('# inert fixture; no scheduled commands\n')
        (etc/'crontab').chmod(0o666)
        for destination in ['root','home','var']:(self.base/destination).mkdir()
        mock=self.base/'mock';mock.mkdir()
        for command in ['psql','curl','wget','su','strace','ldd']:
            file=mock/command;file.write_text('#!/bin/sh\nprintf "%s\n" "$0 $*" >> "/mnt/kit space/blocked-calls"\nexit 97\n');file.chmod(0o755)
        args=['bwrap','--ro-bind','/','/','--unshare-user','--uid','0','--gid','0','--unshare-net',
            '--unshare-pid','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/mnt',
            '--bind',str(self.base),'/mnt/kit space','--ro-bind',str(etc),'/etc']
        for destination in ['root','home','var']:args+=['--ro-bind',str(self.base/destination),'/'+destination]
        command='timeout -k 1 15 sh "/mnt/kit space/CSTK_2Go/vendor/unix-privesc-check.sh" standard'
        args+=['--clearenv','--setenv','PATH','/mnt/kit space/mock:/usr/bin:/bin:/usr/sbin:/sbin',
               '--setenv','HOME','/root','bash','-c',command]
        result=subprocess.run(args,capture_output=True,text=True,timeout=20)
        self.assertIn('World write is set for /etc/crontab',result.stdout)
        self.assertFalse((self.base/'blocked-calls').exists(),result.stdout+result.stderr)
        self.assertEqual((etc/'crontab').read_text(),'# inert fixture; no scheduled commands\n')
        (etc/'crontab').chmod(0o644)
        result=subprocess.run(args,capture_output=True,text=True,timeout=20)
        self.assertNotIn('World write is set for /etc/crontab',result.stdout)

    def test_server_symlinks_rejected(self):
        real = self.base / 'real'; real.write_text('data')
        link = self.base / 'link'; link.symlink_to(real)
        result = subprocess.run(['python3', str(self.kit / 'lib/serve_files.py'), '--file', str(link)],
                                capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
