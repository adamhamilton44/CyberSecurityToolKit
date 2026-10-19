import json,tempfile,unittest
from datetime import datetime,timezone
from pathlib import Path
from engagement_phase2 import BridgeError,Phase2Bridge

HERE=Path(__file__).resolve().parents[1]
ENGINE=HERE/"cstk_engagement.py"
FIXTURE=HERE/"tests"/"engagement-example.json"

class Phase2BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)/"Engagements"; self.root.mkdir(mode=0o700)
        self.bridge=Phase2Bridge(self.root,ENGINE); source=json.loads(FIXTURE.read_text())
        self.created=self.bridge.engine.create_engagement(self.root,source)
    def tearDown(self): self.temp.cleanup()
    def test_draft_never_becomes_ai_authorization_context(self):
        with self.assertRaisesRegex(BridgeError,"not active"): self.bridge.ai_context(self.created.name)
    def test_ai_candidate_is_allowlisted_and_non_authorizing(self):
        path=self.bridge.capture_ai_candidate(self.created.name,{"scope.include":[],"status":"active"})
        candidate=json.loads(path.read_text()); self.assertEqual(candidate["status"],"review_required"); self.assertNotIn("status",candidate["fields"])
        self.assertEqual(self.bridge.detail(self.created.name)["state"],"draft")
    def test_candidate_is_audited(self):
        self.bridge.capture_ai_candidate(self.created.name,{"notes":"review me"})
        audit=(self.created/"Audit"/"events.jsonl").read_text(); self.assertIn("ai_engagement_candidate_captured",audit)
    def test_questionnaire_progress_starts_with_all_mandatory_questions(self):
        progress=self.bridge.questionnaire_progress(self.created.name)
        self.assertEqual(progress["answered"],0); self.assertEqual(progress["total"],23)
        self.assertEqual(progress["remaining"][0]["tag"],"TARGET_LIST")
    def test_questionnaire_answer_is_review_only_revision_bound_and_audited(self):
        path=self.bridge.capture_questionnaire_answer(self.created.name,"target_list","example.test")
        candidate=json.loads(path.read_text())
        self.assertEqual(candidate["status"],"review_required")
        self.assertEqual(candidate["answers"]["TARGET_LIST"]["source"],"operator")
        self.assertEqual(candidate["base_revision"],self.bridge.detail(self.created.name)["revision"])
        self.assertEqual(self.bridge.detail(self.created.name)["state"],"draft")
        self.assertEqual(self.bridge.questionnaire_progress(self.created.name)["answered"],1)
        audit=(self.created/"Audit"/"events.jsonl").read_text()
        self.assertIn("ai_questionnaire_answer_captured",audit); self.assertNotIn("example.test",audit)
    def test_questionnaire_rejects_unknown_or_empty_answer(self):
        with self.assertRaisesRegex(BridgeError,"unknown questionnaire tag"):
            self.bridge.capture_questionnaire_answer(self.created.name,"NOT_REAL","answer")
        with self.assertRaisesRegex(BridgeError,"cannot be empty"):
            self.bridge.capture_questionnaire_answer(self.created.name,"TARGET_LIST","  ")
    def test_hud_reports_time_scope_actions_and_contact(self):
        hud=self.bridge.hud_snapshot(self.created.name,datetime(2026,10,15,tzinfo=timezone.utc))
        self.assertEqual(hud["state"],"DRAFT"); self.assertEqual(hud["timing"],"17 DAYS LEFT")
        self.assertGreater(hud["included_targets"],0); self.assertGreater(hud["denied_actions"],0)
        self.assertNotEqual(hud["emergency_contact"],"NOT SET"); self.assertFalse(hud["operational"])

if __name__=="__main__": unittest.main()
