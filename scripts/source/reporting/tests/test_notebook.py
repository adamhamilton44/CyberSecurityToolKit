import base64
import copy
import hashlib
import json
import multiprocessing
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from cstk_reporting.adapters import import_web_tls_report
from cstk_reporting.model import QUESTIONS, content_digest, redact
from cstk_reporting.report import report_blocks, verify_bundle
from cstk_reporting.service import Notebook
from cstk_reporting.storage import NotebookError, Vault, canonical

PASSWORD = "Test only unique notebook passphrase 2026"
PROFILE = {
    "client": "Example Client",
    "engagement_name": "Web perimeter assessment",
    "engagement_reference": "EXAMPLE-2026-042",
    "assessment_type": "External configuration assessment",
    "author": "Example Security Team",
    "audience": "Business and technical owners",
    "recipients": "Example Client security lead",
    "classification": "Confidential",
    "objectives": "Review publicly exposed web configuration",
    "business_context": "The client portal supports customer access.",
    "testing_start": "2026-10-28",
    "testing_end": "2026-10-28",
    "methodology": "Bounded HTTP header checks and TCP connectivity checks.",
    "limitations": "No authenticated application or business-logic testing.",
    "delivery_method": "Approved encrypted client portal",
    "evidence_policy": "Sanitized excerpts only; no credentials or cookies.",
    "retention_days": "30",
    "legal_hold": "no",
}


def scope():
    return {
        "engagement_id": str(uuid.uuid4()),
        "name": "Example assessment",
        "client": "Example Client",
        "authorization": {
            "reference": "EXAMPLE-ROE-042",
            "valid_from": "2026-10-28T00:00:00Z",
            "valid_until": "2026-10-29T00:00:00Z",
        },
        "scope": {
            "include": [{"type": "url", "value": "https://portal.example.test/"}],
            "exclude": [{"type": "hostname", "value": "payments.example.test"}],
        },
    }


def parallel(path, body):
    with Notebook.open(path, PASSWORD) as book:
        book.add_note("Concurrent note", body)


def fake_bundle(state, directory, *, status, report_id, **kwargs):
    path = Path(directory)
    path.mkdir(mode=0o700)
    files = {}
    for name in ("report.docx", "report.pdf", "report.md"):
        data = (name + status + content_digest(state)).encode()
        (path / name).write_bytes(data)
        os.chmod(path / name, 0o600)
        files[name] = hashlib.sha256(data).hexdigest()
    result = {
        "format": "cstk-report-1",
        "id": report_id,
        "status": status,
        "files": files,
        "content_sha256": content_digest(state),
    }
    (path / "manifest.json").write_bytes(canonical(result))
    os.chmod(path / "manifest.json", 0o600)
    return result


class NotebookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)
        self.config = scope()
        self.path = self.base / "vault"
        self.book = Notebook.create(self.path, PASSWORD, self.config, 1, "a" * 64)
        self.addCleanup(self.book.close)

    def ready(self):
        self.book.set_profile(PROFILE)
        with self.book.capture("Guarded TCP fixture", "192.0.2.10") as result:
            result.update(
                outcome="completed",
                summary="One TCP connection accepted; no application security claim.",
                exit_code=0,
            )

    def finding(self, severity="Medium"):
        note = self.book.add_note(
            "Header evidence",
            "Content-Security-Policy absent from the selected response.",
            kind="evidence",
        )
        finding = self.book.add_finding(
            "Content Security Policy absent",
            "https://portal.example.test/",
            "The response had no enforcing CSP.",
            evidence_ids=[note],
            proposed_severity=severity,
        )
        return note, finding

    def confirm(self, finding):
        self.book.review_finding(
            finding,
            "confirmed",
            "Example Reviewer",
            impact="Application-specific browser protection may be reduced.",
            remediation="Design and test an appropriate CSP.",
            validation="Analyst reviewed headers and selected route.",
            severity_reason="Defense in depth; no exploit demonstrated.",
        )

    def test_encrypted_compact_no_plaintext_or_cleartext_key(self):
        sentinel = "CONFIDENTIAL_FINDING_72b4"
        self.book.add_note("Internal", sentinel * 500)
        data = (self.path / "notebook.enc").read_bytes()
        self.assertNotIn(sentinel.encode(), data)
        self.assertNotIn(b"Example Client", data)
        self.assertLess(len(data), len(sentinel * 500))
        self.assertEqual(
            {p.name for p in self.path.iterdir()}, {"notebook.enc", ".lock"}
        )
        self.assertEqual((self.path / "notebook.enc").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)

    def test_roundtrip_wrong_passphrase_no_mutation(self):
        self.book.add_note("A", "Retained note")
        before = (self.path / "notebook.enc").read_bytes()
        with self.assertRaises(NotebookError):
            Notebook.open(self.path, "Wrong password that is long enough")
        self.assertEqual(before, (self.path / "notebook.enc").read_bytes())
        with Notebook.open(self.path, PASSWORD) as other:
            self.assertEqual(other.snapshot()["notes"][0]["body"], "Retained note")

    def test_payload_tamper_detected(self):
        data = json.loads((self.path / "notebook.enc").read_bytes())
        cipher = bytearray(base64.b64decode(data["ciphertext"]))
        cipher[-1] ^= 1
        data["ciphertext"] = base64.b64encode(cipher).decode()
        (self.path / "notebook.enc").write_bytes(canonical(data))
        with self.assertRaises(NotebookError):
            self.book.snapshot()

    def test_header_tamper_detected(self):
        data = json.loads((self.path / "notebook.enc").read_bytes())
        data["header"]["salt"] = base64.b64encode(b"x" * 16).decode()
        (self.path / "notebook.enc").write_bytes(canonical(data))
        with self.assertRaises(NotebookError):
            Notebook.open(self.path, PASSWORD)

    def test_kdf_parameter_tamper_refused_before_derive(self):
        data = json.loads((self.path / "notebook.enc").read_bytes())
        data["header"]["kdf"]["n"] = 2**40
        (self.path / "notebook.enc").write_bytes(canonical(data))
        with patch("cstk_reporting.storage._derive") as derive:
            with self.assertRaises(NotebookError):
                Notebook.open(self.path, PASSWORD)
            derive.assert_not_called()

    def test_symlink_directory_and_lock_refused(self):
        link = self.base / "link"
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            Vault(link)
        (self.path / ".lock").unlink()
        (self.path / ".lock").symlink_to(self.base / "other")
        with self.assertRaises(OSError):
            self.book.snapshot()

    def test_world_readable_file_and_hardlink_refused(self):
        os.chmod(self.path / "notebook.enc", 0o644)
        with self.assertRaises(NotebookError):
            self.book.snapshot()
        os.chmod(self.path / "notebook.enc", 0o600)
        os.link(self.path / "notebook.enc", self.base / "hardlink")
        with self.assertRaises(NotebookError):
            self.book.snapshot()

    def test_traverse_only_parent_allows_private_notebook_without_following_links(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = Path(directory) / "traversable"
            parent.mkdir(mode=0o700)
            (parent / "vault").mkdir(mode=0o700)
            os.chmod(parent, 0o111)
            try:
                with Notebook.create(parent / "vault", PASSWORD, scope(), 1, "a" * 64) as book:
                    book.add_note("Saved", "Private notebook below a non-listable parent")
                    self.assertEqual(len(book.snapshot()["notes"]), 1)
                self.assertEqual((parent / "vault").stat().st_mode & 0o777, 0o700)
            finally:
                os.chmod(parent, 0o700)

    def test_directory_permissions_rechecked(self):
        os.chmod(self.path, 0o755)
        with self.assertRaises(NotebookError):
            self.book.snapshot()

    def test_failed_atomic_write_keeps_original(self):
        before = (self.path / "notebook.enc").read_bytes()
        with patch(
            "cstk_reporting.storage.os.replace", side_effect=OSError("interruption")
        ):
            with self.assertRaises(OSError):
                self.book.add_note("Failure", "Do not persist")
        self.assertEqual(before, (self.path / "notebook.enc").read_bytes())
        self.assertFalse(list(self.path.glob(".pending-*")))

    def test_parallel_writers_do_not_lose_notes(self):
        ctx = multiprocessing.get_context("fork")
        children = [
            ctx.Process(target=parallel, args=(self.path, str(i))) for i in range(2)
        ]
        for child in children:
            child.start()
        for child in children:
            child.join(20)
            self.assertEqual(child.exitcode, 0)
        self.assertEqual({n["body"] for n in self.book.snapshot()["notes"]}, {"0", "1"})

    def test_key_rotation_invalidates_old_passphrase_and_sessions(self):
        other = Notebook.open(self.path, PASSWORD)
        try:
            self.book.vault.rotate("New independent secure notebook passphrase")
            with self.assertRaises(NotebookError):
                other.snapshot()
            with self.assertRaises(NotebookError):
                Notebook.open(self.path, PASSWORD)
            with Notebook.open(
                self.path, "New independent secure notebook passphrase"
            ) as reopened:
                self.assertEqual(
                    reopened.snapshot()["engagement_id"], self.config["engagement_id"]
                )
        finally:
            other.close()

    def test_event_chain_corruption_cannot_be_saved(self):
        before = (self.path / "notebook.enc").read_bytes()

        def corrupt(state):
            state["events"][0]["details"]["forged"] = "value"

        with self.assertRaises(NotebookError):
            self.book.vault.update(corrupt)
        self.assertEqual(before, (self.path / "notebook.enc").read_bytes())

    def test_reporting_answers_cannot_change_scope(self):
        before = copy.deepcopy(self.book.snapshot()["scope_history"])
        self.book.set_profile(PROFILE)
        self.assertEqual(before, self.book.snapshot()["scope_history"])
        with self.assertRaises(NotebookError):
            self.book.set_profile({"scope.include": "*"})

    def test_scope_mismatch_and_cross_engagement_refused(self):
        with self.assertRaises(NotebookError):
            self.book.start_activity(
                "tool", "target", scope_revision=2, scope_sha256="b" * 64
            )
        with self.assertRaises(NotebookError):
            self.book.revise_scope_snapshot(scope(), 2, "b" * 64)
        self.book.revise_scope_snapshot(self.config, 2, "b" * 64)
        self.assertEqual(len(self.book.snapshot()["scope_history"]), 2)

    def test_capture_ignores_logging_off_records_failure(self):
        with patch.dict(os.environ, {"CSTK_LOGGING_ENABLED": "off"}):
            with self.assertRaises(RuntimeError):
                with self.book.capture(
                    "Fixture", "https://portal.example.test/?token=SECRET"
                ):
                    raise RuntimeError("Private error content")
        record = self.book.snapshot()["activities"][0]
        self.assertEqual(record["outcome"], "error")
        self.assertNotIn("SECRET", str(record))
        self.assertNotIn("Private error", str(record))

    def test_capture_without_summary_is_partial(self):
        with self.book.capture("tool", "target"):
            pass
        self.assertEqual(self.book.snapshot()["activities"][0]["outcome"], "partial")

    def test_incomplete_profile_and_candidate_block_finalization(self):
        self.assertTrue(self.book.readiness())
        self.ready()
        self.finding()
        self.assertTrue(any("disposition" in e for e in self.book.readiness()))
        with self.assertRaises(NotebookError):
            self.book.finalize("missing", "Reviewer", self.base / "final")

    def test_confirmation_requires_evidence_and_review_fields(self):
        finding = self.book.add_finding("Observation", "asset", "Unconfirmed statement")
        with self.assertRaises(NotebookError):
            self.confirm(finding)
        _, finding = self.finding()
        with self.assertRaises(NotebookError):
            self.book.review_finding(finding, "confirmed", "Reviewer")
        self.confirm(finding)
        self.assertEqual(self.book.snapshot()["findings"][-1]["status"], "confirmed")

    def test_evidence_revision_invalidates_confirmation(self):
        note, finding = self.finding()
        self.confirm(finding)
        self.book.update_note(note, body="Corrected observation")
        self.assertEqual(self.book.snapshot()["findings"][0]["status"], "candidate")

    def test_withdraw_confirmed_evidence_refused(self):
        note, finding = self.finding()
        self.confirm(finding)
        with self.assertRaises(NotebookError):
            self.book.update_note(note, withdrawn=True)
        self.book.review_finding(
            finding, "excluded", "Reviewer", disposition_reason="Not applicable"
        )
        self.book.update_note(note, withdrawn=True)
        self.assertTrue(self.book.snapshot()["notes"][0]["withdrawn"])

    def test_import_redacted_atomic_never_automatically_confirmed(self):
        source = "[HIGH] HSTS missing token=TOPSECRET\n[SKIP] TLS 1.0 could not be negotiated\n[PASS] Certificate verified"
        ids = import_web_tls_report(
            self.book,
            source,
            "https://alice:password@portal.example.test/?token=TOPSECRET",
        )
        self.assertEqual(len(ids), 1)
        state = self.book.snapshot()
        self.assertNotIn("TOPSECRET", str(state))
        self.assertNotIn("alice:password", str(state))
        self.assertEqual(state["findings"][0]["status"], "candidate")
        self.assertEqual(state["activities"][0]["outcome"], "partial")
        before = content_digest(state)
        with self.assertRaises(NotebookError):
            import_web_tls_report(self.book, source, "target")
        self.assertEqual(content_digest(self.book.snapshot()), before)

    def test_critical_requires_notification_reference(self):
        self.ready()
        _, finding = self.finding("Critical")
        self.confirm(finding)
        self.assertTrue(any("notification" in e for e in self.book.readiness()))

    @patch("cstk_reporting.report.export_bundle", side_effect=fake_bundle)
    def test_stale_or_edited_draft_cannot_be_finalized(self, _):
        self.ready()
        draft = self.book.export_draft(self.base / "draft")
        self.book.add_note("New material", "Changed source")
        with self.assertRaises(NotebookError):
            self.book.finalize(draft["id"], "Reviewer", self.base / "final")
        draft = self.book.export_draft(self.base / "draft2")
        (self.base / "draft2/report.md").write_text("edited")
        with self.assertRaises(NotebookError):
            self.book.finalize(draft["id"], "Reviewer", self.base / "final")

    @patch("cstk_reporting.report.export_bundle", side_effect=fake_bundle)
    def test_finalize_freezes_reopen_preserves_historical_reports(self, _):
        self.ready()
        draft = self.book.export_draft(self.base / "draft")
        final = self.book.finalize(draft["id"], "Reviewer", self.base / "final")
        self.assertEqual(self.book.snapshot()["lifecycle"], "finalized")
        with self.assertRaises(NotebookError):
            self.book.add_note("Late", "Not allowed")
        self.book.reopen("New evidence")
        self.assertIsNone(self.book.snapshot()["final_report_id"])
        self.assertEqual(len(self.book.snapshot()["reports"]), 2)
        self.assertTrue(verify_bundle(final["directory"], final["manifest"]))

    @patch("cstk_reporting.report.export_bundle", side_effect=fake_bundle)
    def test_purge_checks_confirmation_retention_and_legal_hold(self, _):
        self.ready()
        draft = self.book.export_draft(self.base / "draft")
        self.book.finalize(draft["id"], "Reviewer", self.base / "final")
        confirm = "DELETE NOTES " + self.config["engagement_id"]
        with self.assertRaises(NotebookError):
            self.book.purge("DELETE NOTES wrong", override_reason="Test")
        with self.assertRaises(NotebookError):
            self.book.purge(confirm)
        self.book.reopen("Hold requested")
        self.book.set_profile({"legal_hold": "yes"})
        draft = self.book.export_draft(self.base / "draft2")
        self.book.finalize(draft["id"], "Reviewer", self.base / "final2")
        with self.assertRaises(NotebookError):
            self.book.purge(confirm, override_reason="Test")

    @patch("cstk_reporting.report.export_bundle", side_effect=fake_bundle)
    def test_purge_removes_notes_preserves_reports_and_receipt(self, _):
        self.ready()
        self.book.set_profile({"retention_days": "0"})
        draft = self.book.export_draft(self.base / "draft")
        self.book.finalize(draft["id"], "Reviewer", self.base / "final")
        receipt = self.book.purge("DELETE NOTES " + self.config["engagement_id"])
        self.assertFalse((self.path / "notebook.enc").exists())
        self.assertTrue((self.base / "final/report.pdf").exists())
        self.assertNotIn("Example Client", str(receipt))
        self.assertTrue((self.path / "deleted.json").is_file())
        with self.assertRaises(NotebookError):
            Notebook.create(self.path, PASSWORD, self.config, 1, "a" * 64)

    def test_private_notes_and_excluded_observations_not_exported(self):
        self.ready()
        self.book.add_note("Internal", "INTERNAL_SENSITIVE_SENTINEL")
        _, finding = self.finding()
        self.book.review_finding(
            finding, "excluded", "Reviewer", disposition_reason="Not applicable"
        )
        blocks = report_blocks(self.book.snapshot(), "Draft for review", "R-example")
        self.assertNotIn("INTERNAL_SENSITIVE_SENTINEL", str(blocks))
        self.assertNotIn("The response had no enforcing CSP.", str(blocks))
        self.assertIn("does not establish that vulnerabilities are absent", str(blocks))


class RedactionTests(unittest.TestCase):
    def test_known_secret_patterns_redacted(self):
        value = "Authorization: Bearer TOPSECRET\nSet-Cookie: session=COOKIESECRET\npassword=PASSSECRET\nhttps://user:PASSSECRET@example.test/path?key=QUERYSECRET#FRAGMENTSECRET\n-----BEGIN PRIVATE KEY-----\nKEYSECRET\n-----END PRIVATE KEY-----"
        result = redact(value)
        for secret in (
            "TOPSECRET",
            "COOKIESECRET",
            "PASSSECRET",
            "QUERYSECRET",
            "FRAGMENTSECRET",
            "KEYSECRET",
        ):
            self.assertNotIn(secret, result)

    def test_questionnaire_reporting_only(self):
        keys = {q[0] for q in QUESTIONS}
        self.assertNotIn("actions.allow", keys)
        self.assertNotIn("scope.include", keys)
        self.assertTrue(
            {"business_context", "evidence_policy", "retention_days"} <= keys
        )
