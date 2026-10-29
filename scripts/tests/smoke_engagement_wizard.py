"""Offline interactive packaged wizard: save, resume, choose, review, import."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pexpect

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/tests"))
from engagement_wizard_fixture import fixture_answerer
from test_engagement_manager import engagement as engine

binary = ROOT / "scripts/bin/Etc_engagement"
with tempfile.TemporaryDirectory(prefix="cstk-wizard-smoke-") as temporary:
    base = Path(temporary)
    trace = []
    with (
        contextlib.redirect_stdout(io.StringIO()),
        patch("builtins.input", side_effect=fixture_answerer(engine, trace)),
    ):
        assert engine.wizard_create(base / "fixture-source") == 0
    root = base / "Engagements"
    transcript = io.StringIO()

    def launch(command):
        child = pexpect.spawn(
            str(binary),
            ["--root", str(root), *command],
            encoding="utf-8",
            timeout=30,
            dimensions=(40, 140),
        )
        child.logfile_read = transcript
        return child

    child = launch(["create"])
    for prompt, answer in trace:
        child.expect_exact(prompt)
        child.sendline(answer)
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0, transcript.getvalue()
    directory = engine.engagement_candidates(root)[0]
    config, _, _ = engine.load_current_config(directory)
    assert config["name"] == "Wizard Practice"
    assert engine.load_state(directory) == "draft"
    assert "SAVED: engagement draft created" in transcript.getvalue()
    assert config["engagement_id"] in transcript.getvalue()
    assert len(list((root / ".drafts").glob("*.form.json"))) == 1
    child = launch(["pick"])
    child.expect_exact("Number (0 returns): ")
    child.sendline("1")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0
    child = launch(["prepare", config["engagement_id"]])
    child.expect_exact("Type REVIEW after checking written permission and this scope: ")
    child.sendline("REVIEW")
    child.expect_exact("Type ACTIVATE to enable only the recorded authorized checks: ")
    child.sendline("ACTIVATE")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0, transcript.getvalue()
    assert engine.load_state(directory) == "active"
    # A second unfinished questionnaire keeps earlier answers through resume.
    child = launch(["create"])
    child.expect_exact("Engagement name: ")
    child.sendline("Paused Practice")
    child.expect_exact("Client/system owner name: ")
    child.sendline(":save")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0
    child = launch(["resume"])
    child.expect_exact("Choose a file number (0 returns): ")
    child.sendline("1")
    child.expect_exact("Client/system owner name: ")
    child.sendline(":save")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0
    assert "restored saved answer" in transcript.getvalue()
    result = subprocess.run(
        [str(binary), "--root", str(root), "form-template"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    template = next((root / ".drafts").glob("engagement-form-*.json"))
    assert template.stat().st_mode & 0o777 == 0o600
    assert json.loads(template.read_text())["actions"]["allow"] == []
    form = base / "offline.json"
    config["name"] = "Offline Practice"
    config["slug"] = "offline-practice"
    config.pop("_wizard_checkpoint", None)
    form.write_text(json.dumps(config))
    os.chmod(form, 0o600)
    result = subprocess.run(
        [str(binary), "--root", str(root), "create", "--config", str(form)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    imported = engine.resolve_engagement(root, "offline-practice")
    assert engine.load_state(imported) == "draft"
print(
    "Packaged full questionnaire, saved identity, numbered selection, explicit activation, pause/resume, offline template and import passed. No target contacted."
)
