"""Explicit network transport for prepared CSTK AI requests."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from provider_client import PreparedRequest

MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ProviderTransportError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep credentials and request bodies on the configured endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "provider redirect refused", headers, fp)


def _read_bounded(response) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared:
        try:
            if int(declared) > MAX_RESPONSE_BYTES:
                raise ProviderTransportError("provider response exceeded the 4 MiB safety limit")
        except ValueError:
            pass
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderTransportError("provider response exceeded the 4 MiB safety limit")
    return raw


def send_prepared_request(request: PreparedRequest, timeout_seconds: int) -> str:
    """Submit one operator-approved request and return its response text.

    Both ordinary JSON and OpenAI-compatible server-sent streaming responses
    are accepted. Authorization values are never included in raised errors.
    """

    outbound = urllib.request.Request(
        request.url,
        data=request.body,
        headers=dict(request.headers),
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(outbound, timeout=timeout_seconds) as response:
            content_type = response.headers.get("Content-Type", "")
            raw = _read_bounded(response).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if 300 <= code < 400:
            raise ProviderTransportError(f"provider redirect refused (HTTP {code})") from None
        # Provider bodies are intentionally omitted: they may echo credentials,
        # prompts, internal URLs, or other engagement data.
        raise ProviderTransportError(f"provider returned HTTP {code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ProviderTransportError(f"provider connection failed: {error}") from None

    if "text/event-stream" in content_type.lower() or raw.lstrip().startswith("data:"):
        pieces: list[str] = []
        for line in raw.splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            try:
                chunk = json.loads(data)
                pieces.append(chunk["choices"][0]["delta"].get("content", ""))
            except (KeyError, IndexError, TypeError, json.JSONDecodeError):
                continue
        return "".join(pieces).strip()

    try:
        payload = json.loads(raw)
        return str(payload["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        raise ProviderTransportError("provider returned an unsupported response") from error
