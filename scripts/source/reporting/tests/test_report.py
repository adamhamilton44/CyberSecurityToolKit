import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from cstk_reporting.model import redact
from cstk_reporting.report import verify_bundle
from cstk_reporting.service import Notebook
from cstk_reporting.storage import NotebookError
from lxml import etree
from pypdf import PdfReader
from test_notebook import PASSWORD, PROFILE, scope

SOFFICE = os.environ.get("CSTK_REPORT_SOFFICE")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        os.chmod(self.base, 0o700)
        config = scope()
        self.book = Notebook.create(self.base / "vault", PASSWORD, config, 1, "a" * 64)
        self.addCleanup(self.book.close)
        self.book.set_profile(PROFILE)
        with self.book.capture(
            "Test adapter", "https://portal.example.test/"
        ) as result:
            result.update(outcome="completed", summary="Header review completed.")
        evidence = self.book.add_note(
            "Reviewed response",
            "No enforcing CSP observed on the selected HTML response.",
            kind="evidence",
        )
        finding = self.book.add_finding(
            "Missing Content Security Policy",
            "https://portal.example.test/",
            "No CSP header observed.",
            evidence_ids=[evidence],
            proposed_severity="Low",
        )
        self.book.review_finding(
            finding,
            "confirmed",
            "Reviewer",
            impact="Defense in depth is reduced.",
            remediation="Design and validate an appropriate policy.",
            validation="Response reviewed by the analyst.",
            severity_reason="No injection exploit demonstrated.",
        )
        self.book.add_note("Internal", "DO_NOT_EXPORT_INTERNAL_918a")

    def test_failed_pdf_removes_partial_plaintext_and_does_not_register_report(self):
        with patch(
            "cstk_reporting.report._pdf", side_effect=NotebookError("Renderer failed")
        ):
            with self.assertRaises(NotebookError):
                self.book.export_draft(self.base / "failed", soffice="/not-used")
        self.assertEqual(list((self.base / "failed").iterdir()), [])
        self.assertEqual(self.book.snapshot()["reports"], [])

    def test_missing_converter_refuses_export_without_finalizing(self):
        with self.assertRaises(NotebookError):
            self.book.export_draft(self.base / "missing")
        self.assertEqual(self.book.snapshot()["lifecycle"], "open")
        self.assertEqual(self.book.snapshot()["reports"], [])

    @unittest.skipUnless(
        SOFFICE, "Set CSTK_REPORT_SOFFICE to an explicit LibreOffice executable"
    )
    def test_actual_docx_pdf_draft_to_final_consistency_and_privacy(self):
        draft = self.book.export_draft(self.base / "draft", soffice=SOFFICE)
        final = self.book.finalize(
            draft["id"], "Report Reviewer", self.base / "final", soffice=SOFFICE
        )
        self.assertTrue(verify_bundle(final["directory"], final["manifest"]))
        directory = self.base / "final"
        reader = PdfReader(directory / "report.pdf")
        text = "\n".join(page.extract_text() for page in reader.pages)
        self.assertNotIn("DO_NOT_EXPORT_INTERNAL_918a", text)
        self.assertNotIn("Draft review status", text)
        for heading in (
            "Executive summary",
            "Scope and assessment context",
            "Findings summary",
            "Remediation plan",
            "Supporting evidence",
        ):
            self.assertIn(heading, text)
        self.assertIn("Report Reviewer", text)
        self.assertGreaterEqual(len(reader.pages), 4)
        with ZipFile(directory / "report.docx") as archive:
            styles = etree.fromstring(archive.read("word/styles.xml"))
            document = etree.fromstring(archive.read("word/document.xml"))
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            self.assertFalse(
                styles.xpath(
                    '//w:style[@w:styleId="Title"]/w:pPr/w:pBdr', namespaces=ns
                )
            )
            self.assertTrue(document.xpath("//w:tblHeader", namespaces=ns))
            self.assertNotIn(
                b"DO_NOT_EXPORT_INTERNAL_918a", archive.read("word/document.xml")
            )
        for file in directory.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        # Deletion also checks hashes of the final files, not only their existence.
        (directory / "report.md").write_text("Changed report")
        with self.assertRaises(NotebookError):
            self.book.purge(
                "DELETE NOTES " + self.book.snapshot()["engagement_id"],
                override_reason="test",
            )

    def test_policies_and_quoted_json_redaction(self):
        self.assertEqual(
            redact("Never retain bearer tokens or passwords."),
            "Never retain bearer tokens or passwords.",
        )
        self.assertNotIn("JSON_SECRET_123", redact('{"api_key": "JSON_SECRET_123"}'))
        self.assertNotIn("PRIVATE_TOKEN_123", redact("Bearer PRIVATE_TOKEN_123"))


class AdditionalSafetyTests(unittest.TestCase):
    def test_unicode_bidi_and_terminal_controls_removed(self):
        self.assertEqual(redact("Normal\u202eevil\x85\x1b[31mtext"), "Normaleviltext")


class InputValidationTests(unittest.TestCase):
    def test_malformed_selected_scope_does_not_create_a_vault(self):
        for change in (
            {"scope": []},
            {"authorization": []},
            {"reporting": "bad"},
            {"client": 123},
            {"engagement_id": 123},
        ):
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "vault"
                with self.assertRaises(NotebookError):
                    Notebook.create(
                        destination, PASSWORD, dict(scope(), **change), 1, "a" * 64
                    )
                self.assertFalse(destination.exists())


class RendererTimeoutTests(unittest.TestCase):
    def test_timeout_stops_converter_process_group_before_cleanup(self):
        import subprocess
        from unittest.mock import MagicMock

        from cstk_reporting.report import _pdf

        process = MagicMock()
        process.pid = 12345
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 90),
            ("", ""),
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("cstk_reporting.report.subprocess.Popen", return_value=process),
            patch("cstk_reporting.report.os.killpg") as kill,
        ):
            with self.assertRaises(NotebookError):
                _pdf(Path(directory) / "input.docx", Path(directory), "/bin/true")
            kill.assert_called_once()
            self.assertEqual(kill.call_args.args[0], 12345)
            self.assertFalse(list(Path(directory).glob(".render-*")))


class InternalNotePrivacyTests(unittest.TestCase):
    def test_client_report_does_not_expose_a_digest_of_hidden_notes(self):
        from cstk_reporting.report import report_blocks

        with tempfile.TemporaryDirectory() as directory:
            with Notebook.create(
                Path(directory) / "vault", PASSWORD, scope(), 1, "a" * 64
            ) as book:
                book.set_profile(PROFILE)
                note = book.add_note("Internal", "PRIVATE_VALUE_ONE")
                first = report_blocks(book.snapshot(), "Final", "R-same")
                book.update_note(note, body="PRIVATE_VALUE_TWO")
                second = report_blocks(book.snapshot(), "Final", "R-same")
                self.assertEqual(first, second)


class ReportRegistrationTests(unittest.TestCase):
    def test_failed_notebook_registration_removes_uncommitted_export(self):
        from test_notebook import fake_bundle

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with Notebook.create(
                base / "vault", PASSWORD, scope(), 1, "a" * 64
            ) as book:
                book.set_profile(PROFILE)
                with book.capture("Fixture", "target") as result:
                    result.update(outcome="completed", summary="Fixture completed.")
                with patch(
                    "cstk_reporting.report.export_bundle", side_effect=fake_bundle
                ):
                    with patch.object(
                        book.vault, "_save", side_effect=OSError("Disk failure")
                    ):
                        with self.assertRaises(NotebookError):
                            book.export_draft(base / "failed-draft")
                    self.assertFalse((base / "failed-draft").exists())
                    self.assertEqual(book.snapshot()["reports"], [])
                    draft = book.export_draft(base / "draft")
                    with patch.object(
                        book.vault, "_save", side_effect=OSError("Disk failure")
                    ):
                        with self.assertRaises(NotebookError):
                            book.finalize(
                                draft["id"], "Reviewer", base / "failed-final"
                            )
                    self.assertFalse((base / "failed-final").exists())
                    self.assertEqual(book.snapshot()["lifecycle"], "open")

    def test_primary_finding_change_invalidates_duplicate_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            with Notebook.create(
                Path(directory) / "vault", PASSWORD, scope(), 1, "a" * 64
            ) as book:
                book.set_profile(PROFILE)
                with book.capture("Fixture", "target") as result:
                    result.update(outcome="completed", summary="Fixture completed.")
                evidence = book.add_note(
                    "Evidence", "A reviewed configuration observation.", kind="evidence"
                )
                primary = book.add_finding(
                    "Primary", "target", "Observation", evidence_ids=[evidence]
                )
                book.review_finding(
                    primary,
                    "confirmed",
                    "Reviewer",
                    impact="Impact",
                    validation="Validated",
                    severity_reason="Reason",
                    remediation="Action",
                )
                duplicate = book.add_finding(
                    "Duplicate", "target", "Same observation", evidence_ids=[evidence]
                )
                book.review_finding(
                    duplicate,
                    "duplicate",
                    "Reviewer",
                    duplicate_of=primary,
                    disposition_reason="Same root cause",
                )
                self.assertEqual(book.readiness(), [])
                book.review_finding(
                    primary, "excluded", "Reviewer", disposition_reason="Not applicable"
                )
                self.assertTrue(
                    any(
                        "duplicate reference" in message for message in book.readiness()
                    )
                )
