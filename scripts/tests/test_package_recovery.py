"""Conservative journal reconstruction and isolated recovery application."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

import test_install_lifecycle as lifecycle

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('recovery', ROOT/'scripts/tools/recover_package_ledger.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryAnalysisTests(unittest.TestCase):
    def test_protect_baseline_and_preserve_successful_later_additions(self):
        candidate, protected = recovery.reconstruct({'base'}, {'base','tool','later'},
            [b'base\n',b'base\ntool\n'],[b'base\ntool\n',b'base\ndependency\ntool\n'])
        self.assertEqual(candidate, {'tool','dependency','later'})
        self.assertEqual(protected, {'base'})

    def test_discontinuous_window_and_removals_require_manual_review(self):
        for before, after in [([b'other\n'],[b'other\ntool\n']),
            ([b'base\n'],[b'tool\n']),
            ([b'base\n',b'base\nunknown\n'],[b'base\ntool\n',b'base\nunknown\nx\n'])]:
            with self.assertRaises(ValueError):
                recovery.reconstruct({'base'},set(),before,after)

    def test_package_names_reject_options_and_shell_text(self):
        for data in [b'--purge\n',b'a;id\n',b'a b\n',b'../base\n']:
            with self.assertRaises(ValueError): recovery.names(data)


class RecoveryLifecycleTests(unittest.TestCase):
    # Reuse isolated mounts without inheriting/rerunning every lifecycle test.
    setUp = lifecycle.LifecycleTests.setUp
    run_box = lifecycle.LifecycleTests.run_box

    def fixture(self):
        state=self.mounts['/var']/'lib/cstk'
        state.mkdir(parents=True,mode=0o700)
        (state/'checkout').write_text('/mnt/CSTK\n')
        (state/'package-manager').write_text('apt-get\n')
        (state/'packages').write_text('base:amd64\nfixture-tool\npipx\n')
        (state/'packages.before.first').write_text('base:amd64\npython3:amd64\n')
        (state/'packages.after.first').write_text('base:amd64\nfixture-tool\npython3:amd64\n')
        baseline=self.base/'baseline.list'
        baseline.write_bytes((state/'packages.before.first').read_bytes())
        (self.mounts['/mnt/mock']/'packages.json').write_text('["fixture-tool", "pipx"]')
        command='python3 scripts/tools/recover_package_ledger.py --baseline /mnt/baseline.list --baseline-sha256 '+hashlib.sha256(baseline.read_bytes()).hexdigest()+' --report /mnt/review.json --backup-parent /mnt'
        return state, command

    def test_read_only_then_apply_preserves_originals_without_purging(self):
        state, command=self.fixture()
        result=self.run_box(command)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue((state/'packages.before.first').exists())
        self.assertIn('base:amd64',(state/'packages').read_text())
        report=json.loads((self.base/'review.json').read_text())
        self.assertEqual(report['protected_baseline_ledger_entries'],['base:amd64'])
        result=self.run_box(command+' --apply')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual((state/'packages').read_text(),'fixture-tool\npipx\n')
        self.assertFalse((state/'packages.before.first').exists())
        backups=list(self.base.glob('cstk-package-journal-*'))
        self.assertEqual(len(backups),1)
        self.assertIn('base:amd64',(backups[0]/'packages').read_text())
        self.assertTrue((backups[0]/'packages.before.first').exists())
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),['fixture-tool','pipx'])

    def test_reviewed_shared_runner_repairs_then_uninstalls_with_transcript(self):
        result=lifecycle.LifecycleTests.install(self)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        state=self.mounts['/var']/'lib/cstk'
        before=b'base:amd64\npython3:amd64\n'
        (state/'packages.before.pending').write_bytes(before)
        (state/'packages.after.pending').write_text('base:amd64\npipx\npython-helper\npython3:amd64\n')
        with (state/'packages').open('a') as handle: handle.write('base:amd64\n')
        (self.base/'baseline.list').write_bytes(before)
        for source in ['scripts/tools/recover_package_ledger.py','uninstall.sh','scripts/tools/run_uninstall_test.sh']:
            import shutil
            shutil.copyfile(ROOT/source,self.base/Path(source).name)
        (self.base/'check-uninstall.sh').write_text(
            'python3 /mnt/recover_package_ledger.py --baseline /mnt/baseline.list --baseline-sha256 '+hashlib.sha256(before).hexdigest()+
            ' --report /mnt/review.json --backup-parent /mnt "$@"\n')
        data=self.mounts['/root']/'.local/share/cstk/Logs/keep.txt'
        data.write_text('preserve')
        result=self.run_box('bash /mnt/run_uninstall_test.sh')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(state.exists())
        self.assertFalse((self.checkout/'install.sh').exists())
        self.assertEqual(data.read_text(),'preserve')
        self.assertTrue(list(self.base.glob('cstk-package-journal-*')))
        self.assertTrue(list(self.base.glob('uninstall-original.*.sh')))
        transcript=list(self.base.glob('uninstall-test.*.log'))
        self.assertEqual(len(transcript),1)
        self.assertIn('CSTK removed.',transcript[0].read_text())
        self.assertEqual(json.loads((self.mounts['/mnt/mock']/'packages.json').read_text()),[])

    def test_extra_apt_removal_blocks_apply_and_keeps_journal(self):
        state,command=self.fixture()
        original=(state/'packages').read_bytes()
        result=self.run_box(command+' --apply',{'UNTRACKED_REMOVAL':'1'})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((state/'packages').read_bytes(),original)
        self.assertTrue((state/'packages.before.first').exists())
        self.assertEqual(json.loads((self.base/'review.json').read_text())['blocked_removals'],['base:amd64'])


if __name__ == '__main__':
    unittest.main()
