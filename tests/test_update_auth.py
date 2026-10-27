"""Unprivileged updater auth/diagnostic fixtures; never fetch or install anything."""
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
UPDATER=ROOT/'scripts/lib/cstk_update.sh'

class UpdateAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.capture=self.base/'sudo-args'
        self.owner=pwd.getpwuid(os.getuid()).pw_name
    def run_shell(self,body,agent=None):
        env=dict(os.environ,fixture_capture=str(self.capture),fixture_root=str(self.base),fixture_owner=self.owner)
        env.pop('SSH_AUTH_SOCK',None)
        if agent is not None:env['SSH_AUTH_SOCK']=str(agent)
        return subprocess.run(['bash','-c','source "$1"; sudo() { printf "%s\\0" "$@" > "$fixture_capture"; }; '+body,'fixture',str(UPDATER)],env=env,capture_output=True,text=True)
    def test_valid_owned_agent_is_forwarded_after_sudo_boundary(self):
        with socket.socket(socket.AF_UNIX) as agent:
            path=self.base/'agent';agent.bind(str(path))
            r=self.run_shell('repo_git_as_owner "$fixture_owner" "$fixture_root" fetch --quiet --prune',path)
        self.assertEqual(r.returncode,0,r.stderr)
        args=self.capture.read_bytes().split(b'\0')[:-1]
        self.assertEqual(args[:4],[b'-H',b'-u',self.owner.encode(),b'env'])
        self.assertEqual(args[4],('SSH_AUTH_SOCK='+str(path)).encode())
        self.assertIn(b'fetch',args)
    def test_missing_agent_does_not_fabricate_an_agent(self):
        r=self.run_shell('repo_git_as_owner "$fixture_owner" "$fixture_root" status')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn(b'SSH_AUTH_SOCK=',self.capture.read_bytes())
    def test_symlink_or_missing_agent_is_refused(self):
        with socket.socket(socket.AF_UNIX) as agent:
            path=self.base/'agent';agent.bind(str(path));link=self.base/'link';link.symlink_to(path)
            for candidate in (link,self.base/'absent'):
                r=self.run_shell('repo_git_as_owner "$fixture_owner" "$fixture_root" fetch',candidate)
                self.assertNotEqual(r.returncode,0)
                self.assertFalse(self.capture.exists())
    def test_fetch_auth_failure_explains_agent_and_log_path(self):
        (self.base/'.git').mkdir()
        r=self.run_shell('''log_dir="$fixture_root"
repo_git() {
    case "$2" in
        status) return 0 ;;
        rev-parse) echo origin/main ;;
        fetch) echo 'git@github.com: Permission denied (publickey).' >&2; return 128 ;;
    esac
}
check_git_repo CSTK "$fixture_root"
rc=$?
printf '\\nstate=%s rc=%s\\n' "$REPO_STATE" "$rc"
''')
        self.assertIn('state=fetch-failed rc=1',r.stdout)
        self.assertIn('--preserve-env=SSH_AUTH_SOCK',r.stdout)
        self.assertIn(str(self.base/'CSTK_fetch.log'),r.stdout)
    def test_summary_reports_the_actual_block_reason(self):
        r=self.run_shell('self_update_blocked=1; self_update_reason=fetch-failed; print_summary')
        self.assertIn('blocked (fetch-failed)',r.stdout)
        self.assertNotIn('until this installation has an authenticated Git checkout',r.stdout)
    def test_failed_self_update_check_is_not_a_successful_check_exit(self):
        r=self.run_shell('''mode=check
require_root() { :; }; validate_home() { :; }; prepare_update_environment() { :; }
load_registries() { :; }; print_scope() { :; }
check_system_packages() { :; }; check_python_tools() { :; }; check_github_tools() { :; }
check_cstk_self_update() { self_update_blocked=1; self_update_reason=fetch-failed; }
main
''')
        self.assertNotEqual(r.returncode,0,r.stdout+r.stderr)
    def test_retired_and_archive_tools_have_explicit_handling(self):
        r=self.run_shell('GITHUB_TOOLS=(mongosh-archive katana vulscan); check_github_tools')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertNotIn('No verified update recipe',r.stdout)
        self.assertIn('verified archive',r.stdout)
