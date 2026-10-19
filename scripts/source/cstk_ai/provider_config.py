"""Provider-neutral configuration and credential resolution for CSTK AI.

This module deliberately performs no network requests.  It keeps provider
selection separate from the Textual interface and never stores API-key values
in the saved configuration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


class ProviderConfigError(ValueError):
    """Raised when a provider configuration is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Connection details that are safe to persist.

    ``api_key_env`` stores only the environment-variable name.  The secret is
    resolved at runtime and is never returned by ``to_public_dict``.
    """

    name: str
    base_url: str
    model: str
    api_key_env: str = ""
    protocol: str = "openai-compatible"
    timeout_seconds: int = 60

    def validate(self, *, allow_local_http: bool = True) -> None:
        if not self.name.strip():
            raise ProviderConfigError("provider name is required")
        if not self.model.strip():
            raise ProviderConfigError("model is required")
        if self.protocol not in {"openai-compatible"}:
            raise ProviderConfigError(f"unsupported protocol: {self.protocol}")
        if not 1 <= self.timeout_seconds <= 600:
            raise ProviderConfigError("timeout must be between 1 and 600 seconds")

        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ProviderConfigError("base URL must be an absolute HTTP(S) URL")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (
            allow_local_http and parsed.hostname in local_hosts
        ):
            raise ProviderConfigError("remote providers must use HTTPS")

    def resolve_api_key(self, environ: Mapping[str, str] | None = None) -> str:
        """Resolve a key without placing it in persisted configuration."""

        if not self.api_key_env:
            return ""
        source = os.environ if environ is None else environ
        value = source.get(self.api_key_env, "")
        if not value:
            raise ProviderConfigError(
                f"credential environment variable is not set: {self.api_key_env}"
            )
        return value

    def to_public_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["credential"] = "configured" if self.api_key_env else "not required"
        return data


def save_provider(config: ProviderConfig, destination: Path) -> None:
    """Save non-secret provider metadata with private-user permissions."""

    config.validate()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(asdict(config), indent=2, sort_keys=True) + "\n"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
    destination.chmod(0o600)


def load_provider(source: Path) -> ProviderConfig:
    data = json.loads(source.read_text(encoding="utf-8"))
    config = ProviderConfig(**data)
    config.validate()
    return config
