"""Offline tests: never call Docker, download images, or open a real browser."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('containers', ROOT/'scripts/source/container_tools/cstk_containers.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class ContainerTests(unittest.TestCase):
    def test_web_check_only_publishes_on_loopback_and_is_reused(self):
        response=SimpleNamespace(status=200, __enter__=lambda self:self, __exit__=lambda *args:None)
        from unittest.mock import MagicMock
        opener=MagicMock(); opener.open.return_value.__enter__.return_value.status=200
        with patch.object(module,'inspect_web',return_value=None), patch.object(module,'docker') as docker, patch.object(module.urllib.request,'build_opener',return_value=opener), patch.object(module,'open_browser') as browser:
            self.assertEqual(module.web_check('start'),0)
            args=docker.call_args.args
            self.assertIn('127.0.0.1:3000:3000',args)
            self.assertNotIn('--privileged',args)
            browser.assert_called_once()
        with patch.object(module,'inspect_web',return_value={'State':{'Running':True}}), patch.object(module,'docker') as docker, patch.object(module.urllib.request,'build_opener',return_value=opener), patch.object(module,'open_browser'):
            module.web_check('start'); docker.assert_not_called()
    def test_refuses_foreign_or_public_existing_container(self):
        for labels,ip in [({},'127.0.0.1'),({'io.cstk.component':'web-check'},'0.0.0.0')]:
            item={'Config':{'Labels':labels},'HostConfig':{'PortBindings':{'3000/tcp':[{'HostIp':ip,'HostPort':'3000'}]}}}
            with patch.object(module,'docker',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([item]))):
                with self.assertRaises(RuntimeError): module.inspect_web()
    def test_project_audit_read_only_operator_identity_no_socket(self):
        with tempfile.TemporaryDirectory(prefix='cstk project ') as directory, patch.object(module,'docker',return_value=SimpleNamespace(returncode=1)) as docker, patch.object(module.os,'geteuid',return_value=1000), patch.object(module,'invoking_user',return_value=SimpleNamespace(pw_uid=1000,pw_gid=1000)):
            self.assertEqual(module.project_audit(directory),1)
            args=docker.call_args.args
            self.assertIn(f'type=bind,src={directory},dst=/project,readonly',args)
            self.assertIn('1000:1000',args)
            self.assertIn('vuln,secret,misconfig,license',args)
            self.assertNotIn('/var/run/docker.sock',' '.join(args))
    def test_browser_runs_as_desktop_user_with_user_home(self):
        with patch.object(module,'invoking_user',return_value=SimpleNamespace(pw_uid=1000,pw_name='operator',pw_dir='/home/operator')), patch.dict(module.os.environ,{'DISPLAY':':0'}), patch.object(module.os,'geteuid',return_value=0), patch.object(module.shutil,'which',return_value='/usr/bin/xdg-open'), patch.object(module.subprocess,'Popen') as launch:
            module.open_browser()
            args=launch.call_args.args[0]
            self.assertEqual(args[:4],['runuser','-u','operator','--'])
            self.assertIn('HOME=/home/operator',args)
    def test_main_menu_options_are_ordered_without_blank_lines(self):
        source=(ROOT/'cstk.sh').read_text(); body=source[source.index('main_menu() {'):source.index('\nhandle_input() {')]
        body=body[body.index("    printf '%b\\n'"):body.index('    read -r -p')]
        command='O= B= g= Y= R= X= AUTH_ENABLED=on FONTS_ENABLED=on; '+body
        result=subprocess.run(['bash','-c',command],capture_output=True,text=True,check=True)
        lines=result.stdout.splitlines()
        self.assertNotIn('',lines)
        keys=[line.split(' -')[0].strip() for line in lines if ' -' in line]
        self.assertEqual(keys,list('12345678GLTUX'))
    def test_linux_audit_falls_back_to_lynis_with_private_report_paths(self):
        source=(ROOT/'cstk.sh').read_text()
        function=source[source.index('linux_security_assessment() {'):source.index('# Web Check accepts arbitrary targets')]
        command='''bin=/not-installed; CSTK_LOG_DIR='/private logs'; Loot='/private loot'
defense_linux_audit_frame() { :; }
engagement_dispatch_guard() { return 0; }
lynis() { printf '<%s>\\n' "$@"; }
run_as_cstk_user() { "$@"; }
'''+function+'\nlinux_security_assessment\n'
        result=subprocess.run(['bash','-c',command],capture_output=True,text=True,check=True)
        self.assertIn('<audit>\n<system>',result.stdout)
        self.assertIn('</private logs/lynis-',result.stdout)
        self.assertIn('</private loot/lynis-',result.stdout)

    def test_defense_menu_uses_theme_colors_and_preserves_options(self):
        source=(ROOT/'cstk.sh').read_text()
        function=source[source.index('defense_menu() {'):source.index('######################### MAIN SCRIPT')]
        import os
        env=dict(os.environ,C='\x1b[36m',Y='\x1b[33m',G='\x1b[32m',B='\x1b[34m',R='\x1b[31m',X='\x1b[0m')
        result=subprocess.run(['bash','-c',function+'\ndefense_menu'],input='X\n',env=env,capture_output=True,text=True,check=True)
        self.assertIn('\x1b[36mDEFENSE\x1b[0m',result.stdout)
        self.assertIn('\x1b[32mWeb/TLS Security Assessment',result.stdout)
        for key in ('1','2','3','4','X'):
            self.assertIn('\x1b[33m'+key+'\x1b[0m - ',result.stdout)
