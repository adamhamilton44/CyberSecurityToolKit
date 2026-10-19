import json
import stat
import tempfile
import unittest
from pathlib import Path

from provider_config import (
    ProviderConfig,
    ProviderConfigError,
    load_provider,
    save_provider,
)


class ProviderConfigTests(unittest.TestCase):
    def test_remote_provider_requires_https(self):
        config = ProviderConfig("Example", "http://api.example.test/v1", "model")
        with self.assertRaisesRegex(ProviderConfigError, "HTTPS"):
            config.validate()

    def test_local_provider_may_use_http(self):
        ProviderConfig("Local", "http://127.0.0.1:11434/v1", "local-model").validate()

    def test_secret_value_is_never_serialized(self):
        config = ProviderConfig(
            "Example", "https://api.example.test/v1", "model", "CSTK_AI_KEY"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.json"
            save_provider(config, path)
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("top-secret", serialized)
            self.assertEqual(load_provider(path), config)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_key_is_resolved_only_at_runtime(self):
        config = ProviderConfig(
            "Example", "https://api.example.test/v1", "model", "CSTK_AI_KEY"
        )
        self.assertEqual(config.resolve_api_key({"CSTK_AI_KEY": "top-secret"}), "top-secret")
        public = json.dumps(config.to_public_dict())
        self.assertNotIn("top-secret", public)

    def test_missing_named_credential_is_reported(self):
        config = ProviderConfig(
            "Example", "https://api.example.test/v1", "model", "CSTK_AI_KEY"
        )
        with self.assertRaisesRegex(ProviderConfigError, "CSTK_AI_KEY"):
            config.resolve_api_key({})


if __name__ == "__main__":
    unittest.main()
