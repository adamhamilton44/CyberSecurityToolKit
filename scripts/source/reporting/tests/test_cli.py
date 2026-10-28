import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cstk_reporting import cli
from cstk_reporting.service import Notebook
from cstk_reporting.storage import NotebookError
from rich.console import Console
from test_notebook import PASSWORD, scope


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)
        self.buffer = io.StringIO()
        self.console = Console(file=self.buffer, force_terminal=False, width=110)

    def test_questions_do_not_need_a_passphrase_or_vault(self):
        with (
            patch.object(cli, "console", self.console),
            patch.object(cli, "passphrase") as secret,
        ):
            self.assertEqual(cli.main(["questions"]), 0)
            secret.assert_not_called()
        self.assertIn("business_context", self.buffer.getvalue())
        self.assertIn("legal_hold", self.buffer.getvalue())

    def test_init_questions_then_status_and_private_persistence(self):
        config = scope()
        source = self.base / "scope.json"
        source.write_text(json.dumps(config))
        vault = self.base / "vault"
        with (
            patch.object(cli, "console", self.console),
            patch.object(cli, "passphrase", return_value=PASSWORD),
            patch.object(
                cli.Prompt, "ask", side_effect=lambda label, default="": default
            ),
        ):
            self.assertEqual(
                cli.main(
                    [
                        "--vault",
                        str(vault),
                        "init",
                        "--scope",
                        str(source),
                        "--revision",
                        "1",
                    ]
                ),
                0,
            )
            self.assertEqual(cli.main(["--vault", str(vault), "status"]), 0)
        self.assertNotIn(PASSWORD, self.buffer.getvalue())
        with Notebook.open(vault, PASSWORD) as notebook:
            self.assertEqual(
                notebook.snapshot()["engagement_id"], config["engagement_id"]
            )

    def test_passphrase_refuses_echo_fallback(self):
        with patch.object(
            cli.getpass,
            "getpass",
            side_effect=cli.getpass.GetPassWarning("echo enabled"),
        ):
            with self.assertRaises(NotebookError):
                cli.passphrase()

    def test_guarded_menu_callback_returns_without_invalid_option_message(self):
        from unittest.mock import Mock

        with Notebook.create(
            self.base / "guarded-menu", PASSWORD, scope(), 1, "a" * 64
        ) as book:
            callback = Mock()
            with (
                patch.object(cli, "console", self.console),
                patch.object(cli.Prompt, "ask", side_effect=["T", "X"]),
            ):
                cli.shell(book, None, guarded_operation=callback)
            callback.assert_called_once_with("T", book)
            self.assertNotIn("Choose a listed option", self.buffer.getvalue())

    def test_password_flag_is_not_supported(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["--password", "secret", "status"])

    def test_cli_can_record_manual_activity_with_logs_off(self):
        with Notebook.create(
            self.base / "vault", PASSWORD, scope(), 1, "a" * 64
        ) as book:
            with (
                patch.object(cli, "console", self.console),
                patch.dict(os.environ, {"CSTK_LOGGING_ENABLED": "off"}),
                patch.object(
                    cli.Prompt,
                    "ask",
                    side_effect=[
                        "A",
                        "Manual test",
                        "portal.example.test",
                        "completed",
                        "X",
                    ],
                ),
                patch.object(
                    cli,
                    "multiline",
                    return_value="Manual configuration check completed.",
                ),
            ):
                cli.shell(book, None)
            activity = book.snapshot()["activities"][0]
            self.assertEqual(activity["origin"], "operator")
            self.assertEqual(activity["outcome"], "completed")

    def test_cli_closes_interrupted_capture_without_claiming_success(self):
        with Notebook.create(
            self.base / "vault", PASSWORD, scope(), 1, "a" * 64
        ) as book:
            record = book.start_activity("Interrupted tool", "portal.example.test")
            with (
                patch.object(cli, "console", self.console),
                patch.object(
                    cli.Prompt, "ask", side_effect=["C", record, "error", "X"]
                ),
                patch.object(
                    cli,
                    "multiline",
                    return_value="Process interrupted; no usable result.",
                ),
            ):
                cli.shell(book, None)
            self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")

    def test_invalid_secret_does_not_echo_passphrase(self):
        with Notebook.create(self.base / "vault", PASSWORD, scope(), 1, "a" * 64):
            pass
        with (
            patch.object(cli, "console", self.console),
            patch.object(
                cli, "passphrase", return_value="Another wrong unique passphrase"
            ),
        ):
            self.assertEqual(
                cli.main(["--vault", str(self.base / "vault"), "status"]), 2
            )
        self.assertNotIn("Another wrong unique passphrase", self.buffer.getvalue())


class GuardBindingTests(unittest.TestCase):
    def test_guarded_capture_refuses_denial_wrong_engagement_or_missing_revision(self):
        from cstk_reporting.adapters import capture_authorized_operation

        with tempfile.TemporaryDirectory() as directory:
            with Notebook.create(
                Path(directory) / "vault", PASSWORD, scope(), 1, "a" * 64
            ) as book:
                correct = {
                    "allowed": True,
                    "engagement_id": book.snapshot()["engagement_id"],
                    "scope_revision": 1,
                    "scope_sha256": "a" * 64,
                    "target": "192.0.2.10",
                }
                for changes in (
                    {"allowed": False},
                    {"engagement_id": "another-engagement"},
                    {"scope_revision": None},
                    {"scope_sha256": "b" * 64},
                ):
                    with self.assertRaises(NotebookError):
                        with capture_authorized_operation(
                            book, dict(correct, **changes), "Fixture"
                        ):
                            pass
                self.assertEqual(book.snapshot()["activities"], [])
                with capture_authorized_operation(book, correct, "Fixture") as result:
                    result.update(
                        outcome="completed", summary="Bounded test completed."
                    )
                self.assertEqual(
                    book.snapshot()["activities"][0]["outcome"], "completed"
                )
