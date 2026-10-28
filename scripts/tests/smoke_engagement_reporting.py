"""Offline interactive packaged-runtime test; requires pexpect in the test Python."""

import argparse
import io
import os
import sys
import tempfile
from pathlib import Path

import pexpect

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "scripts/source/cstk_ai"),
    str(ROOT / "scripts/source/reporting"),
    str(ROOT / "scripts/source/reporting/tests"),
    str(ROOT / "scripts/tests"),
]
import cstk_engagement as policy
from cstk_reporting.report import verify_bundle
from cstk_reporting.service import Notebook
from test_engagement_manager import valid_config
from test_notebook import PASSWORD, PROFILE

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, default=ROOT / "scripts/bin/Etc_engagement")
parser.add_argument("--soffice", required=True)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="cstk-integrated-smoke-") as temporary:
    base = Path(temporary)
    directory = policy.create_engagement(base / "Engagements", valid_config())
    policy.transition(base / "Engagements", "example-assessment", "ready")
    policy.transition(base / "Engagements", "example-assessment", "active")
    config, revision, sha = policy.load_current_config(directory)
    path = directory / "reporting-notebook"
    with Notebook.create(path, PASSWORD, config, revision, sha) as book:
        book.set_profile(PROFILE)
        with book.capture(
            "Offline fixture review", "fixture://documentation", origin="operator"
        ) as result:
            result.update(
                outcome="completed",
                summary="Fictional manual documentation review; no target contacted.",
            )
    transcript = io.StringIO()
    env = dict(
        os.environ,
        CSTK_SCOPE_SHA256=sha,
        CSTK_LOGGING_ENABLED="off",
        CSTK_LOGGING_LEVEL="off",
    )

    def launch(command):
        child = pexpect.spawn(
            str(args.binary),
            ["--root", str(base / "Engagements"), *command],
            env=env,
            encoding="utf-8",
            timeout=60,
            dimensions=(40, 140),
        )
        child.logfile_read = transcript
        child.expect_exact("Notebook passphrase:")
        child.waitnoecho(timeout=10)
        child.sendline(PASSWORD)
        return child

    # Denied TCP destination: no routing, DNS or target transport occurs.
    child = launch(
        [
            "run",
            "example-assessment",
            "--adapter",
            "tcp",
            "--target",
            "192.0.2.5",
            "--ports",
            "443",
            "--confirm",
        ]
    )
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 3, transcript.getvalue()
    with Notebook.open(path, PASSWORD) as book:
        assert book.snapshot()["activities"], transcript.getvalue()
        activity = book.snapshot()["activities"][-1]
        assert activity["outcome"] == "error"
        assert "192.0.2.5" not in activity["target"]
        assert "SHA256=" in activity["target"]
    exports = base / "Reports"
    exports.mkdir(mode=0o700)
    # Use the converter's real directory; its wrapper resolves resources relative to itself.
    env["PATH"] = (
        str(Path(args.soffice).absolute().parent) + os.pathsep + env.get("PATH", "")
    )
    env.pop("CSTK_SCOPE_SHA256", None)
    child = launch(["report", "example-assessment"])
    for prompt, answer in [
        ("Select", "T"),
        ("Explicit IP/CIDR", "192.0.2.5"),
        ("Comma separated TCP ports", "443"),
        ("Authorize this bounded operation", "RUN"),
        ("Select", "2"),
        ("Note title", "Integrated private note"),
        ("Asset", ""),
        ("Note kind", "operator"),
        ("Include this context", "n"),
        (
            "finish with a line containing only a period",
            "INTEGRATED_PRIVATE_NOTE_0826\n.",
        ),
        ("Select", "7"),
        ("Create an unencrypted", "y"),
        ("Private report output parent", str(exports)),
    ]:
        child.expect_exact(prompt)
        child.sendline(answer)
    child.expect_exact("Select")
    with Notebook.open(path, PASSWORD) as book:
        assert book.snapshot()["reports"], transcript.getvalue()
        draft = book.snapshot()["reports"][-1]
        assert verify_bundle(draft["directory"], draft["manifest"])
    child.sendline("8")
    for prompt, answer in [
        ("Reviewed draft reference", draft["id"]),
        ("Final reviewer name", "Fixture Reviewer"),
        ("Type FINALIZE", "FINALIZE"),
        ("Private report output parent", str(exports)),
        ("Select", "X"),
    ]:
        child.expect_exact(prompt)
        child.sendline(answer)
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0, transcript.getvalue()
    with Notebook.open(path, PASSWORD) as book:
        assert book.snapshot()["notes"][-1]["body"] == "INTEGRATED_PRIVATE_NOTE_0826"
        assert book.snapshot()["reports"], transcript.getvalue()
        assert book.snapshot()["lifecycle"] == "finalized", transcript.getvalue()
        report = book.snapshot()["reports"][-1]
        assert verify_bundle(report["directory"], report["manifest"])
        assert (
            "INTEGRATED_PRIVATE_NOTE_0826"
            not in (Path(report["directory"]) / "report.md").read_text()
        )
    assert PASSWORD not in transcript.getvalue()
    assert b"INTEGRATED_PRIVATE_NOTE_0826" not in (path / "notebook.enc").read_bytes()
print(
    "Integrated binary unlock, denied guarded run, encrypted note capture, and actual Word/PDF draft/final export passed with logging off."
)
