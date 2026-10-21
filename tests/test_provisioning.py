"""Unprivileged provisioning regression tests; never touches /etc/cstk."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        arch = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
        self.helper = ROOT / 'scripts/provision' / ('cstk-provision-' + arch)
        if not self.helper.exists():
            self.skipTest('No helper for host architecture')

    def run_helper(self, directory):
        result = subprocess.run([str(self.helper), str(directory)], capture_output=True)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')
        return result.returncode

    def test_key_permissions_and_all_resources(self):
        self.assertEqual(self.run_helper(self.base), 0)
        key = self.base / 'lib_decryption.key'
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.stat().st_uid, os.geteuid())
        for probe in (ROOT / 'scripts/lib').glob('*.enc'):
            result = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc',
                '-salt', '-pbkdf2', '-in', str(probe), '-out', os.devnull,
                '-pass', 'file:' + str(key)], capture_output=True)
            self.assertEqual(result.returncode, 0)
        self.assertNotEqual(self.run_helper(self.base), 0)

    def test_arm64_helper_with_qemu(self):
        emulator = shutil.which('qemu-aarch64')
        if not emulator:
            self.skipTest('qemu-aarch64 unavailable')
        helper = ROOT / 'scripts/provision/cstk-provision-aarch64'
        result = subprocess.run([emulator, str(helper), str(self.base)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, b'')
        key = self.base / 'lib_decryption.key'
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        for probe in (ROOT / 'scripts/lib').glob('*.enc'):
            result = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc',
                '-salt', '-pbkdf2', '-in', str(probe), '-out', os.devnull,
                '-pass', 'file:' + str(key)], capture_output=True)
            self.assertEqual(result.returncode, 0)

    def test_unsafe_destinations(self):
        victim = self.base / 'victim'
        victim.write_text('unchanged')
        (self.base / 'lib_decryption.key').symlink_to(victim)
        self.assertNotEqual(self.run_helper(self.base), 0)
        self.assertEqual(victim.read_text(), 'unchanged')
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        self.assertNotEqual(self.run_helper(alias), 0)
        self.base.chmod(0o755)
        self.assertNotEqual(self.run_helper(self.base), 0)

    def test_installer_fresh_repeat_and_invalid_key(self):
        checkout = self.base / 'checkout'
        shutil.copytree(ROOT / 'scripts/provision', checkout / 'scripts/provision')
        (checkout / 'scripts/lib').mkdir()
        for probe in (ROOT / 'scripts/lib').glob('*.enc'):
            shutil.copy2(probe, checkout / 'scripts/lib' / probe.name)
        functions = (ROOT / 'install.sh').read_text().split(
            '# Main installation process')[0]
        functions = functions.replace('source \"$home_dir/scripts/lib/install_state.sh\" || exit 1', ':')
        # Strip root ownership flags only for this unprivileged sandbox.
        harness = functions + r'''
install() {
    local -a args=()
    while (( $# )); do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
chown() { :; }
home_dir="$1"
lib_key_dir="$2"
lib_decryption_key="$2/lib_decryption.key"
install_lib_decryption_key
'''
        keydir = self.base / 'keys'
        script = self.base / 'test.sh'
        script.write_text(harness)
        def run():
            env = dict(os.environ)
            env.pop('CSTK_LIB_KEY_SOURCE', None)
            return subprocess.run(['bash', str(script), str(checkout), str(keydir)],
                                  env=env, capture_output=True)
        for _ in range(2):
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')
            self.assertEqual(list((checkout / 'scripts/provision').glob('cstk-provision-*')), [])
            self.assertEqual(list(keydir.glob('.provision.*')), [])
        (keydir / 'lib_decryption.key').write_text('invalid\n')
        self.assertNotEqual(run().returncode, 0)
        self.assertEqual((keydir / 'lib_decryption.key').read_text(), 'invalid\n')

if __name__ == '__main__':
    unittest.main()
