import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cstk_ai


class CSTKAITests(unittest.TestCase):
    def test_remote_plain_http_is_rejected(self):
        with self.assertRaises(cstk_ai.CSTKAIError):
            cstk_ai.validate_endpoint("http://example.com/v1/messages")

    def test_local_plain_http_is_allowed(self):
        self.assertEqual(
            cstk_ai.validate_endpoint("http://127.0.0.1:4000/v1/messages"),
            "http://127.0.0.1:4000/v1/messages",
        )

    def test_endpoint_must_not_embed_credentials(self):
        with self.assertRaises(cstk_ai.CSTKAIError):
            cstk_ai.validate_endpoint("https://user:pass@example.com/v1/messages")

    def test_prompt_redacts_secret_and_attaches_text(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.txt"
            path.write_text("token = very-secret-value\nfinding: missing CSP\n", encoding="utf-8")
            prompt = cstk_ai.build_prompt("Review this", [path], 4096)
        self.assertIn("finding: missing CSP", prompt)
        self.assertIn("token = [REDACTED]", prompt)
        self.assertNotIn("very-secret-value", prompt)

    def test_binary_attachment_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.bin"
            path.write_bytes(b"abc\x00def")
            with self.assertRaises(cstk_ai.CSTKAIError):
                cstk_ai.read_text_file(path, 4096)

    def test_extract_text_ignores_non_text_blocks(self):
        value = cstk_ai.extract_text({"content": [{"type": "tool_use"}, {"type": "text", "text": "safe"}]})
        self.assertEqual(value, "safe")

    def test_request_contains_no_tools(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"content": [{"type": "text", "text": "answer"}]}
        ).encode()
        settings = cstk_ai.Settings("https://example.com/v1/messages", "model", "key", 10, 100)
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch("urllib.request.build_opener", return_value=opener):
            answer, _ = cstk_ai.request_analysis(settings, "question")
        request = opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(answer, "answer")
        self.assertNotIn("tools", payload)
        self.assertNotIn("tool_choice", payload)

    def test_redirects_are_disabled(self):
        handler = cstk_ai.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "found", {}, "https://other.example"))

    def test_saved_session_is_private_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(os.environ, {"XDG_DATA_HOME": temp}):
            path = cstk_ai.save_session("password=hunter2", "ok", "model")
            mode = stat.S_IMODE(path.stat().st_mode)
            content = path.read_text(encoding="utf-8")
        self.assertEqual(mode, 0o600)
        self.assertNotIn("hunter2", content)
        self.assertIn("[REDACTED]", content)

    def test_cstk_runtime_root_is_preferred_for_sessions(self):
        with mock.patch.dict(os.environ, {"CSTK_USER_DATA_DIR": "/tmp/cstk-user"}):
            self.assertEqual(cstk_ai.private_data_dir(), Path("/tmp/cstk-user/AI/Sessions"))


if __name__ == "__main__":
    unittest.main()
