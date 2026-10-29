"""Exercise the real Bash engagement menu without launcher/root/integrity startup."""

import io
import os
import sys
import tempfile
from pathlib import Path

import pexpect

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/tests"))
from test_engagement_manager import engagement as engine
from test_engagement_manager import valid_config

source = (ROOT / "cstk.sh").read_text()
menu = source[
    source.index("engagement_manager_menu() {") : source.index(
        "\nopen_engagement_reporting()"
    )
]
with tempfile.TemporaryDirectory(prefix="cstk-menu-smoke-") as temporary:
    base = Path(temporary)
    root = base / "Engagements"
    directory = engine.create_engagement(root, valid_config())
    identity = engine.load_current_config(directory)[0]["engagement_id"]
    script = base / "menu.sh"
    script.write_text(
        """#!/bin/bash
C=$'\\e[1;36m'; Y=$'\\e[1;33m'; g=''; X=$'\\e[0m'
clear() { :; }
show_engagement_status() { echo 'Fixture session: no tool execution'; }
run_engagement_helper() { "$fixture_binary" --root "$fixture_root" "$@"; }
apply_engagement_selection() { printf 'SELECTED: %s\\n' "$1"; }
open_engagement_reporting() { printf 'REPORT PICK: %s\\n' "$1"; }
run_guarded_operation() { echo 'No transport permitted in this menu fixture'; return 1; }
cstk_ai_analyst() { return 0; }
"""
        + menu
        + "\nengagement_manager_menu\n"
    )
    transcript = io.StringIO()
    child = pexpect.spawn(
        "bash",
        ["--noprofile", "--norc", str(script)],
        env=dict(
            os.environ,
            fixture_binary=str(ROOT / "scripts/bin/Etc_engagement"),
            fixture_root=str(root),
        ),
        encoding="utf-8",
        timeout=30,
        dimensions=(45, 140),
    )
    child.logfile_read = transcript
    child.expect_exact("Engagement ==> ")
    text = transcript.getvalue()
    names = ["6 - OSINT", "7 - PAYLOADS", "8 - POST EXPLOIT", "9 - ETC", "10 - DEFENSE"]
    assert [text.index(v) for v in names] == sorted(text.index(v) for v in names)
    child.sendline("3")
    child.expect_exact("Number (0 returns): ")
    child.sendline("1")
    child.expect_exact("Type REVIEW after checking written permission and this scope: ")
    child.sendline("REVIEW")
    child.expect_exact("Type ACTIVATE to enable only the recorded authorized checks: ")
    child.sendline("ACTIVATE")
    child.expect_exact("Press Enter to continue...")
    child.sendline("")
    child.expect_exact("Engagement ==> ")
    child.sendline("2")
    child.expect_exact("Number (0 returns): ")
    child.sendline("1")
    child.expect_exact("SELECTED: " + identity)
    child.expect_exact("Press Enter to continue...")
    child.sendline("")
    child.expect_exact("Engagement ==> ")
    child.sendline("4")
    child.expect_exact("Number (0 returns): ")
    child.sendline("1")
    child.expect_exact("REPORT PICK: " + identity)
    child.expect_exact("Press Enter to continue...")
    child.sendline("")
    child.expect_exact("Engagement ==> ")
    child.sendline("5")
    child.expect_exact("Offline engagement forms - choose a number: ")
    child.sendline("1")
    child.expect_exact("Offline JSON form saved")
    child.expect_exact("Press Enter to continue...")
    child.sendline("")
    child.expect_exact("Engagement ==> ")
    child.sendline("X")
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus == 0, transcript.getvalue()
    assert engine.load_state(directory) == "active"
    assert list((root / ".drafts").glob("engagement-form-*.json"))
    assert "Engagement slug or ID:" not in transcript.getvalue()
print(
    "Bash setup menu order, numbered review/activation/selection/report choice and offline export passed without entering a slug or starting a target tool."
)
