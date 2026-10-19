import unittest
import os
from cstk_ai import CSTKAnalystV2, CredentialScreen, Palette
from engagement_phase2 import BridgeError

class FakeBridge:
    def list(self): return [{"slug":"draft-one","state":"draft","name":"Draft One"}]
    def detail(self,identifier):
        return {"config":{"slug":identifier,"scope":{"include":[{"value":"example.test"}]}},"state":"draft","revision":1,"sha256":"a"*64,"activation_errors":["not ready"]}
    def ai_context(self,identifier): raise BridgeError("engagement is not active; AI authorization context withheld")
    def hud_snapshot(self,identifier):
        return {"operational":False,"state":"DRAFT","timing":"10 DAYS LEFT","slug":identifier,"client":"Example","valid_from":"2026-10-20T13:00:00Z","valid_until":"2026-10-30T03:00:00Z","inside_testing_window":False,"timezone":"America/Chicago","included_targets":1,"excluded_targets":0,"allowed_actions":1,"confirm_actions":0,"denied_actions":22,"max_rps":2,"max_concurrency":1,"source_ip_rules":1,"emergency_contact":"Owner","emergency_method":"phone"}
    def questionnaire_progress(self,identifier):
        return {"answered":1,"total":23,"status":"review_required","complete":False,"remaining":[{"tag":"OUT_OF_SCOPE","question":"What is excluded?"}]}
    def capture_questionnaire_answer(self,identifier,tag,answer,source):
        self.captured=(identifier,tag,answer,source); return "/tmp/review-only.json"

class V2ContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_v2_mounts_and_palette_opens(self):
        app=CSTKAnalystV2(); app.engagements=FakeBridge()
        async with app.run_test(size=(140,40)) as pilot:
            self.assertIsNotNone(app.query_one("#chat")); self.assertIsNotNone(app.query_one("#prompt"))
            await pilot.press("ctrl+k"); await pilot.pause(); self.assertIsInstance(app.screen,Palette)
    async def test_credential_dialog_is_hidden_and_session_only(self):
        app=CSTKAnalystV2(); app.engagements=FakeBridge()
        async with app.run_test(size=(140,40)) as pilot:
            app._credential(["CSTK_TEST_KEY"]); await pilot.pause()
            self.assertIsInstance(app.screen,CredentialScreen)
            field=app.screen.query_one("#secret")
            self.assertTrue(field.password)
            app.screen.dismiss("temporary-secret"); await pilot.pause()
            self.assertEqual(os.environ.get("CSTK_TEST_KEY"),"temporary-secret")
            self.assertIn("CSTK_TEST_KEY",app._session_credentials)
        self.assertNotIn("CSTK_TEST_KEY",os.environ)
    async def test_draft_engagement_context_is_withheld(self):
        app=CSTKAnalystV2(); app.engagements=FakeBridge(); app.engagement_id="draft-one"
        async with app.run_test(size=(140,40)):
            expanded=app._expand("Review @engagement")
            self.assertIn("context withheld",expanded); self.assertNotIn("example.test",expanded)
    async def test_engagement_use_selects_real_record_without_activating(self):
        app=CSTKAnalystV2(); app.engagements=FakeBridge()
        async with app.run_test(size=(140,40)):
            app._engagement(["use","draft-one"])
            self.assertEqual(app.engagement_id,"draft-one"); self.assertEqual(app.scope,"example.test")
            panel=str(app.query_one("#right").render()); self.assertIn("10 DAYS LEFT",panel); self.assertIn("WINDOW CLOSED",panel)
    async def test_model_change_resets_outbound_history_and_records_event(self):
        from provider_client import ChatMessage
        from provider_config import ProviderConfig
        app=CSTKAnalystV2(); app.engagements=FakeBridge(); app.provider=ProviderConfig("Local","http://127.0.0.1:11434/v1","old")
        app.messages=[ChatMessage("user","private prior context")]
        async with app.run_test(size=(140,40)):
            app._change_model("new")
            self.assertEqual(app.messages,[]); self.assertEqual(app.provider.model,"new")
            self.assertEqual(app.connection_state,"READY")
    async def test_provider_change_resets_outbound_history(self):
        from provider_client import ChatMessage
        from provider_config import ProviderConfig
        app=CSTKAnalystV2(); app.engagements=FakeBridge(); app.provider=ProviderConfig("One","https://one.example/v1","m1")
        app.messages=[ChatMessage("user","do not forward")]
        async with app.run_test(size=(140,40)):
            app._activate_provider(ProviderConfig("Two","https://two.example/v1","m2"),"configured")
            self.assertEqual(app.messages,[]); self.assertEqual(app.connection_state,"READY")
    async def test_questionnaire_next_and_operator_answer_are_review_only(self):
        app=CSTKAnalystV2(); bridge=FakeBridge(); app.engagements=bridge; app.engagement_id="draft-one"
        async with app.run_test(size=(140,40)):
            app._engagement(["next"])
            app._engagement(["answer","OUT_OF_SCOPE","admin.example.test"])
            self.assertEqual(bridge.captured,("draft-one","OUT_OF_SCOPE","admin.example.test","operator"))
    async def test_narrow_layout_keeps_compact_safety_status(self):
        app=CSTKAnalystV2(); app.engagements=FakeBridge(); app.engagement_id="draft-one"
        async with app.run_test(size=(80,28)):
            app._panels(); strip=str(app.query_one("#safety-strip").render())
            self.assertIn("draft-one",strip); self.assertIn("STOP / REVIEW",strip)

if __name__=="__main__": unittest.main()
