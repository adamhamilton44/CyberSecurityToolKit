from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ("CSTK_GAPS.md", "DEPENDENCY_APT_SIMULATION.log", "DEPENDENCY_AUDIT.json", "DEPENDENCY_AUDIT.md", "INSTALL_APT_FRESH_SIMULATION.log", "INSTALL_UNINSTALL_AUDIT.md", "KALI_APT_SIMULATION.log", "ZIP2GO_BUILD_REPORT.md")

class ReleaseHygieneTests(unittest.TestCase):
    def test_generated_reports_are_absent_and_ignored(self):
        for name in REPORTS:
            self.assertFalse((ROOT/name).exists(), name)
            # --no-index also covers a developer's tracked index during cleanup.
            result = subprocess.run(["git", "check-ignore", "--no-index", name], cwd=ROOT, capture_output=True)
            self.assertEqual(result.returncode, 0, name)
    def test_dependency_report_can_be_regenerated_outside_release(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"reports"/"audit.md"
            result=subprocess.run(["python3",str(ROOT/"scripts/tools/audit_dependencies.py"),"--reference",str(Path(directory)/"no-external-source"),"--output",str(output)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(output.is_file());self.assertTrue(output.with_suffix(".json").is_file())
