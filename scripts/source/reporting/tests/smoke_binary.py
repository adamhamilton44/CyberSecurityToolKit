import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pexpect

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "tests"))
import argparse

from cstk_reporting.report import verify_bundle
from cstk_reporting.service import Notebook
from test_notebook import PASSWORD, PROFILE, scope

parser = argparse.ArgumentParser(
    description="Offline compiled CLI capture and report smoke test"
)
parser.add_argument("--binary", type=Path, default=root / "bin/cstk-reporting")
parser.add_argument("--soffice", required=True)
args = parser.parse_args()
binary = args.binary.absolute()
soffice = args.soffice
for args in (["--version"], ["--help"], ["questions"]):
    result = subprocess.run(
        [str(binary), *args], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
with tempfile.TemporaryDirectory(prefix="cstk-reporting-binary-smoke-") as directory:
    base = Path(directory)
    os.chmod(base, 0o700)
    parent = base / "exports"
    parent.mkdir(mode=0o700)
    with Notebook.create(base / "vault", PASSWORD, scope(), 1, "a" * 64) as book:
        book.set_profile(PROFILE)
        with book.capture("Fixture tool", "192.0.2.10") as result:
            result.update(
                outcome="completed",
                summary="A fixture check completed; no target was contacted.",
            )
        transcript = io.StringIO()
        child = pexpect.spawn(
            str(binary),
            ["--vault", str(base / "vault"), "--soffice", soffice, "shell"],
            encoding="utf-8",
            timeout=60,
            dimensions=(40, 140),
        )
        child.logfile_read = transcript
        child.expect_exact("Notebook passphrase:")
        child.waitnoecho(timeout=10)
        child.sendline(PASSWORD)
        for prompt, answer in [
            ("Select", "2"),
            ("Note title", "Binary fixture note"),
            ("Asset", ""),
            ("Note kind", "operator"),
            ("Include this context", "n"),
            (
                "finish with a line containing only a period",
                "BINARY_PRIVATE_NOTE_5192\n.",
            ),
            ("Select", "7"),
            ("Create an unencrypted", "y"),
            ("Private report output parent", str(parent)),
            ("Select", "X"),
        ]:
            child.expect_exact(prompt)
            child.sendline(answer)
        child.expect(pexpect.EOF)
        child.close()
        assert child.exitstatus == 0, transcript.getvalue()
        assert PASSWORD not in transcript.getvalue()
        notes = book.snapshot()["notes"]
        assert notes[-1]["body"] == "BINARY_PRIVATE_NOTE_5192"
        assert (
            b"BINARY_PRIVATE_NOTE_5192"
            not in (base / "vault/notebook.enc").read_bytes()
        )
        reports = book.snapshot()["reports"]
        assert len(reports) == 1, transcript.getvalue()
        assert verify_bundle(reports[0]["directory"], reports[0]["manifest"])
        assert (
            b"BINARY_PRIVATE_NOTE_5192"
            not in (Path(reports[0]["directory"]) / "report.md").read_bytes()
        )
print(
    "Compiled CLI help/questions/version, passphrase unlock, encrypted note capture, and actual DOCX/PDF draft export passed."
)
