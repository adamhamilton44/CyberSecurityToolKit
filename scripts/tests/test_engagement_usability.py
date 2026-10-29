"""No target traffic: beginner UI, recoverable forms and explicit activation."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_engagement_manager import engagement as engine
from test_engagement_manager import valid_config


class EngagementUsabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Engagements"
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()
        self.addCleanup(self.capture.__exit__, None, None, None)
        self.addCleanup(setattr, engine, "_WIZARD", None)

    def test_choices_use_numbers_and_friendly_labels(self):
        with patch("builtins.input", side_effect=["bad", "2"]):
            self.assertEqual(engine.choice("Type", ("lab", "wireless")), "wireless")
        self.assertIn("Wireless network", self.output.getvalue())
        self.assertNotIn("lab/wireless", self.output.getvalue())

    def test_multi_choice_and_numeric_validation(self):
        with patch("builtins.input", side_effect=["999", "1,3"]):
            self.assertEqual(
                engine.multi_choice("Days", ("mon", "tue", "wed"), required=True),
                ["mon", "wed"],
            )
        with patch("builtins.input", side_effect=["wrong", "nan", "-1", "3"]):
            self.assertEqual(engine.numeric_prompt("Limit", integer=True, minimum=1), 3)

    def test_dates_and_time_zones_retry_instead_of_aborting(self):
        with patch(
            "builtins.input", side_effect=["yesterday", "2026-10-29T09:00:00-05:00"]
        ):
            self.assertEqual(
                engine.prompt("Authorization starts (ISO 8601 with offset)"),
                "2026-10-29T09:00:00-05:00",
            )
        with patch("builtins.input", side_effect=["nonsense", "UTC"]):
            self.assertEqual(engine.prompt("Engagement time zone"), "UTC")

    def test_pause_keeps_each_answer_and_resume_replays_it(self):
        with patch("builtins.input", side_effect=["Fixture client", ":save"]):
            self.assertEqual(engine.wizard_create(self.root), 0)
        path = next((self.root / ".drafts").glob("*.answers.json"))
        saved = json.loads(path.read_text())
        self.assertEqual(saved["answers"][0]["value"], "Fixture client")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(engine.engagement_candidates(self.root), [])
        with patch("builtins.input", side_effect=[":save"]) as ask:
            self.assertEqual(engine.wizard_create(self.root, path), 0)
        self.assertEqual(ask.call_count, 1)
        self.assertIn("restored saved answer", self.output.getvalue())

    def test_invalid_final_config_keeps_editable_form_and_no_false_success(self):
        config = valid_config()
        config["authorization"]["valid_from"] = "not a date"
        with patch.object(engine, "interactive_config", return_value=config):
            self.assertEqual(engine.wizard_create(self.root), 2)
        forms = list((self.root / ".drafts").glob("*.form.json"))
        self.assertEqual(len(forms), 1)
        self.assertEqual(
            json.loads(forms[0].read_text())["authorization"]["valid_from"],
            "not a date",
        )
        self.assertEqual(engine.engagement_candidates(self.root), [])
        self.assertNotIn("SAVED: engagement draft created", self.output.getvalue())

    def test_success_shows_name_id_path_and_does_not_activate(self):
        with patch.object(
            engine, "interactive_config", return_value=valid_config("My Lab")
        ):
            self.assertEqual(engine.wizard_create(self.root), 0)
        directory = engine.engagement_candidates(self.root)[0]
        config, _, _ = engine.load_current_config(directory)
        self.assertEqual(engine.load_state(directory), "draft")
        for value in (
            "My Lab",
            "my-lab",
            config["engagement_id"],
            str(directory),
            "Saved scope JSON:",
        ):
            self.assertIn(value, self.output.getvalue())

    def test_completed_engagement_is_not_duplicated_after_missing_resume_marker(self):
        with patch.object(engine, "interactive_config", return_value=valid_config()):
            engine.wizard_create(self.root)
        path = next((self.root / ".drafts").glob("*.answers.json"))
        data = json.loads(path.read_text())
        data.pop("saved_engagement")
        path.write_text(json.dumps(data))
        os.chmod(path, 0o600)
        with patch.object(engine, "interactive_config") as wizard:
            engine.wizard_create(self.root, path)
        wizard.assert_not_called()
        self.assertEqual(len(engine.engagement_candidates(self.root)), 1)

    def test_offline_template_is_private_safe_and_never_overwritten(self):
        path = engine.export_form(self.root)
        data = json.loads(path.read_text())
        self.assertEqual(data["actions"]["allow"], [])
        self.assertEqual(data["actions"]["confirm_each_run"], [])
        self.assertEqual(set(data["actions"]["deny"]), set(engine.ACTIONS))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(engine.EngagementError):
            engine.export_form(self.root, path)
        self.assertEqual(engine.engagement_candidates(self.root), [])

    def test_import_preserves_bad_forms_and_good_forms_stay_draft(self):
        self.root.mkdir(mode=0o700)
        source = Path(self.temp.name) / "form.json"
        source.write_text(json.dumps({"name": "Incomplete"}))
        self.assertEqual(engine.import_form(self.root, source), 2)
        self.assertTrue(list((self.root / ".drafts").glob("import-*.json")))
        source.write_text(json.dumps(valid_config()))
        self.assertEqual(engine.import_form(self.root, source), 0)
        self.assertEqual(
            engine.load_state(engine.engagement_candidates(self.root)[0]), "draft"
        )

    def test_malformed_duplicate_and_symlink_forms_rejected(self):
        source = Path(self.temp.name) / "form.json"
        for text in ("[1,2]", '{"name":"one","name":"two"}', "{invalid"):
            source.write_text(text)
            with self.assertRaises(engine.EngagementError):
                engine.load_form(source)
        link = source.with_name("link.json")
        link.symlink_to(source)
        with self.assertRaises(OSError):
            engine.load_form(link)

    def test_picker_returns_only_id_on_stdout(self):
        directory = engine.create_engagement(self.root, valid_config())
        config, _, _ = engine.load_current_config(directory)
        with (
            patch("builtins.input", return_value="1"),
            contextlib.redirect_stderr(io.StringIO()) as menu,
        ):
            result = engine.pick_engagement(self.root)
        self.assertEqual(result, config["engagement_id"])
        self.assertIn("1. Example Assessment [draft]", menu.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(engine.pick_engagement(self.root, active_only=True))

    def test_activation_requires_explicit_review_and_checks_scope_unchanged(self):
        directory = engine.create_engagement(self.root, valid_config())
        with patch("builtins.input", return_value=""):
            engine.review_activate(self.root, "example-assessment")
        self.assertEqual(engine.load_state(directory), "draft")
        with patch("builtins.input", side_effect=["REVIEW", "ACTIVATE"]):
            self.assertEqual(engine.review_activate(self.root, "example-assessment"), 0)
        self.assertEqual(engine.load_state(directory), "active")

    def test_scope_change_after_review_never_activates(self):
        directory = engine.create_engagement(self.root, valid_config())
        answers = iter(["REVIEW", "ACTIVATE"])

        def answer(*args):
            value = next(answers)
            if value == "ACTIVATE":
                revised = valid_config()
                revised["notes"] = "Changed during review"
                engine.revise_engagement(self.root, "example-assessment", revised)
            return value

        with patch("builtins.input", side_effect=answer):
            with self.assertRaises(engine.EngagementError):
                engine.review_activate(self.root, "example-assessment")
        self.assertNotEqual(engine.load_state(directory), "active")

    def test_complete_questionnaire_is_saved_and_manual_policy_does_not_grant_denied_action(
        self,
    ):
        from engagement_wizard_fixture import fixture_answerer

        trace = []
        with patch("builtins.input", side_effect=fixture_answerer(engine, trace)):
            self.assertEqual(engine.wizard_create(self.root), 0)
        self.assertGreater(len(trace), 60)
        directory = engine.engagement_candidates(self.root)[0]
        config, _, _ = engine.load_current_config(directory)
        self.assertIn("exploit.validation", config["actions"]["deny"])
        self.assertNotIn("exploit.validation", config["actions"]["confirm_each_run"])
        self.assertEqual(engine.validation_errors(config, activation=True), [])
        self.assertEqual(engine.load_state(directory), "draft")

    def test_failed_checkpoint_write_stops_before_questionnaire(self):
        with (
            patch.object(engine, "atomic_write", side_effect=OSError("disk full")),
            patch.object(engine, "interactive_config") as wizard,
        ):
            with self.assertRaises(OSError):
                engine.wizard_create(self.root)
        wizard.assert_not_called()
