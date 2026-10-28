"""Real policy and encrypted notebook; only transports are substituted."""

import argparse
import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "scripts/source/cstk_ai"),
    str(ROOT / "scripts/source/reporting"),
]
import engagement_runtime as runtime
import test_engagement_manager as baseline
from cstk_reporting.integration import Capture, bind, unlock_notebook
from cstk_reporting.service import Notebook
from cstk_reporting.storage import NotebookError

PASSWORD = "Fixture notebook unique passphrase 2026"


class ReportingIntegrationTests(unittest.TestCase):
    setUp = baseline.EngagementManagerTests.setUp
    tearDown = baseline.EngagementManagerTests.tearDown
    create_active = baseline.EngagementManagerTests.create_active

    def setup_book(self):
        directory = self.create_active()
        config, revision, sha = runtime.policy.load_current_config(directory)
        book = Notebook.create(
            directory / "reporting-notebook", PASSWORD, config, revision, sha
        )
        self.addCleanup(book.close)
        return directory, book, sha

    def run_tcp(self, book, sha, target="192.0.2.4", operation=None):
        args = argparse.Namespace(
            root=self.root,
            identifier="example-assessment",
            adapter="tcp",
            target=target,
            ports="443",
            confirm=True,
        )
        with (
            patch.dict(
                os.environ,
                CSTK_SCOPE_SHA256=sha,
                CSTK_LOGGING_LEVEL="off",
                CSTK_LOGGING_ENABLED="off",
            ),
            patch.object(runtime, "render"),
            patch.object(runtime, "route_source", return_value="198.51.100.10"),
            patch.object(runtime, "pinned_socket", side_effect=operation) as transport,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = runtime.run_adapter(args, book)
        return rc, transport

    def test_capture_independent_of_logging_and_no_automatic_finding(self):
        directory, book, sha = self.setup_book()
        rc, transport = self.run_tcp(book, sha)
        self.assertEqual(rc, 0)
        transport.assert_called_once()
        state = book.snapshot()
        self.assertEqual(state["activities"][0]["outcome"], "completed")
        self.assertEqual(len(state["notes"]), 1)
        self.assertEqual(state["findings"], [])
        self.assertNotIn(
            b"192.0.2.4",
            (directory / "reporting-notebook" / "notebook.enc").read_bytes(),
        )

    def test_denied_target_is_error_without_connection(self):
        _, book, sha = self.setup_book()
        rc, transport = self.run_tcp(book, sha, "192.0.2.5")
        self.assertEqual(rc, 3)
        transport.assert_not_called()
        self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")

    def test_capture_unwritable_before_operation(self):
        _, book, sha = self.setup_book()
        with patch.object(
            book, "start_activity", side_effect=NotebookError("disk full")
        ):
            with patch.object(runtime, "tcp_probe") as operation:
                with self.assertRaises(NotebookError):
                    self.run_tcp(book, sha)
            operation.assert_not_called()

    def test_capture_write_failure_before_connection(self):
        _, book, sha = self.setup_book()
        real = book._edit

        def edit(kind, change):
            if kind == "guarded_destination_authorized":
                raise NotebookError("storage unavailable")
            return real(kind, change)

        with patch.object(book, "_edit", side_effect=edit):
            rc, transport = self.run_tcp(book, sha)
        self.assertEqual(rc, 3)
        transport.assert_not_called()
        self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")

    def test_wrong_engagement_and_changed_revision_rejected(self):
        _, book, sha = self.setup_book()
        other = self.create_active("Other engagement")
        config, revision, digest = runtime.policy.load_current_config(other)
        with self.assertRaises(NotebookError):
            bind(book, config, revision, digest)
        item = runtime.snapshot(self.root, "example-assessment")
        with self.assertRaises(NotebookError):
            bind(book, item["config"], item["revision"] + 1, sha)

    def test_pause_during_tcp_check_marks_incomplete(self):
        _, book, sha = self.setup_book()

        def pause(*args):
            runtime.policy.transition(self.root, "example-assessment", "paused")
            return contextlib.nullcontext()

        rc, _ = self.run_tcp(book, sha, operation=pause)
        self.assertEqual(rc, 3)
        self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")
        self.assertEqual(book.snapshot()["notes"], [])

    def test_expiry_during_check_stops_and_records_error(self):
        _, book, sha = self.setup_book()
        expired = [False]
        original = runtime.policy.authorization_current

        def current(config, now=None):
            return False if expired[0] else original(config, now)

        def expire(*args):
            expired[0] = True
            return contextlib.nullcontext()

        with patch.object(runtime.policy, "authorization_current", side_effect=current):
            rc, _ = self.run_tcp(book, sha, operation=expire)
        self.assertEqual(rc, 3)
        self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")

    def test_scope_revision_during_check_stops_capture(self):
        _, book, sha = self.setup_book()

        def revise(*args):
            config = baseline.valid_config()
            config["notes"] = "Revised fixture scope"
            runtime.policy.revise_engagement(self.root, "example-assessment", config)
            return contextlib.nullcontext()

        rc, _ = self.run_tcp(book, sha, operation=revise)
        self.assertEqual(rc, 3)
        self.assertEqual(book.snapshot()["activities"][0]["outcome"], "error")

    def test_missing_notebook_does_not_prompt_or_create(self):
        directory = self.create_active()
        with patch("cstk_reporting.cli.passphrase") as prompt:
            with self.assertRaises(NotebookError):
                with unlock_notebook(self.root, "example-assessment"):
                    self.fail("unlocked missing notebook")
        prompt.assert_not_called()
        self.assertFalse((directory / "reporting-notebook").exists())

    def test_result_allowlist_drops_headers_and_url_query(self):
        _, book, sha = self.setup_book()
        guard = runtime.Guard(self.root, "example-assessment", sha, True)
        guard.capture = Capture(
            book,
            guard.item,
            "web",
            "https://app.example.test/?token=TOPSECRET",
            guard.run_id,
        )
        guard.decision(
            "https://app.example.test/",
            ["192.0.2.4"],
            443,
            "198.51.100.10",
            "web.active",
        )
        guard.record(
            {
                "url": "https://app.example.test/?token=TOPSECRET",
                "status": 200,
                "authorization": "SECRET_HEADER",
                "body": "PRIVATE_RESPONSE",
            }
        )
        note = book.snapshot()["notes"][0]
        self.assertNotIn("TOPSECRET", note["body"])
        self.assertNotIn("SECRET_HEADER", note["body"])
        self.assertNotIn("PRIVATE_RESPONSE", note["body"])


if __name__ == "__main__":
    unittest.main()
