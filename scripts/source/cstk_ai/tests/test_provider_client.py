import json
import unittest

from provider_client import ChatMessage, prepare_chat_request
from provider_config import ProviderConfig


class ProviderClientTests(unittest.TestCase):
    def setUp(self):
        self.config = ProviderConfig(
            "Example",
            "https://api.example.test/v1/",
            "example-model",
            "CSTK_AI_KEY",
        )

    def test_prepares_compatible_chat_request_without_network(self):
        request = prepare_chat_request(
            self.config,
            [ChatMessage("user", "Analyze this authorized log")],
            environ={"CSTK_AI_KEY": "secret-value"},
        )
        self.assertEqual(request.url, "https://api.example.test/v1/chat/completions")
        payload = json.loads(request.body)
        self.assertEqual(payload["model"], "example-model")
        self.assertTrue(payload["stream"])

    def test_safe_summary_redacts_key_and_message_text(self):
        request = prepare_chat_request(
            self.config,
            [ChatMessage("user", "sensitive investigation text")],
            environ={"CSTK_AI_KEY": "secret-value"},
        )
        summary = json.dumps(request.safe_summary())
        self.assertNotIn("secret-value", summary)
        self.assertNotIn("sensitive investigation text", summary)
        self.assertIn("[REDACTED]", summary)

    def test_empty_conversation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            prepare_chat_request(
                self.config, [], environ={"CSTK_AI_KEY": "secret-value"}
            )


if __name__ == "__main__":
    unittest.main()
