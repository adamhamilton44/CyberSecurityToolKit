"""Transport-neutral request preparation for CSTK AI providers.

The prototype returns a prepared request object; it does not open sockets.  A
later transport can submit this object after the operator confirms the target.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Iterable, Mapping

from provider_config import ProviderConfig


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: str
    content: str

    def validate(self) -> None:
        if self.role not in {"system", "user", "assistant"}:
            raise ValueError(f"unsupported chat role: {self.role}")
        if not self.content.strip():
            raise ValueError("chat message cannot be empty")


@dataclass(frozen=True, slots=True)
class PreparedRequest:
    url: str
    headers: Mapping[str, str]
    body: bytes

    def safe_summary(self) -> dict[str, object]:
        """Return diagnostics that cannot disclose an authorization value."""

        headers = {
            name: "[REDACTED]" if name.lower() == "authorization" else value
            for name, value in self.headers.items()
        }
        payload = json.loads(self.body.decode("utf-8"))
        return {
            "url": self.url,
            "headers": headers,
            "model": payload.get("model", ""),
            "message_count": len(payload.get("messages", [])),
        }


def prepare_chat_request(
    config: ProviderConfig,
    messages: Iterable[ChatMessage],
    *,
    environ: Mapping[str, str] | None = None,
) -> PreparedRequest:
    """Validate and serialize an OpenAI-compatible chat request."""

    config.validate()
    validated = list(messages)
    if not validated:
        raise ValueError("at least one chat message is required")
    for message in validated:
        message.validate()

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = config.resolve_api_key(environ)
    if key:
        headers["Authorization"] = f"Bearer {key}"

    payload = {
        "model": config.model,
        "messages": [
            {"role": message.role, "content": message.content}
            for message in validated
        ],
        "stream": True,
    }
    return PreparedRequest(
        url=f"{config.base_url.rstrip('/')}/chat/completions",
        headers=headers,
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
