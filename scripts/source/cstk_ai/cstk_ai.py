#!/usr/bin/env python3
"""CSTK AI Analyst: a non-agentic, defensive analysis client."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.1.0"
DEFAULT_ENDPOINT = "http://127.0.0.1:4000/v1/messages"
DEFAULT_MAX_FILE_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 120

SYSTEM_PROMPT = """You are CSTK AI Analyst, a defensive cybersecurity assistant.
Analyze only the information the operator supplies. Give evidence-based explanations,
safe remediation, and clearly label uncertainty. Never claim that a vulnerability is
confirmed without evidence. Do not provide credential theft, phishing, destructive
actions, persistence, malware deployment, denial of service, safety bypasses, or steps
to compromise third parties. You cannot execute commands, browse, edit files, or take
actions; say so plainly. Redact secrets and unnecessary personal data in your answer.
"""

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\b(\s*[:=]\s*)[^\s,;]+"), r"\1\2[REDACTED]"),
    (re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
)


class CSTKAIError(RuntimeError):
    """A user-facing validation or transport failure."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep credentials on the endpoint the operator explicitly selected."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class Settings:
    endpoint: str
    model: str
    api_key: str | None
    timeout: int
    max_tokens: int


def redact(text: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def validate_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CSTKAIError("endpoint must be a complete http:// or https:// URL")
    if parsed.username or parsed.password:
        raise CSTKAIError("credentials are not allowed inside the endpoint URL")
    local_hosts = {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme == "http" and parsed.hostname not in local_hosts:
        raise CSTKAIError("unencrypted HTTP is allowed only for a local endpoint")
    return endpoint


def read_text_file(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CSTKAIError(f"cannot inspect {path}: {exc}") from exc
    if not path.is_file():
        raise CSTKAIError(f"not a regular file: {path}")
    if size > max_bytes:
        raise CSTKAIError(f"file exceeds {max_bytes} byte limit: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CSTKAIError(f"cannot read {path}: {exc}") from exc
    if b"\x00" in raw:
        raise CSTKAIError(f"binary files are not accepted: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CSTKAIError(f"file is not UTF-8 text: {path}") from exc


def build_prompt(question: str, paths: Iterable[Path], max_file_bytes: int) -> str:
    sections = [question.strip()]
    if not sections[0]:
        raise CSTKAIError("a non-empty question is required")
    for path in paths:
        content = redact(read_text_file(path, max_file_bytes))
        sections.append(f"\n--- BEGIN ATTACHMENT: {path.name} ---\n{content}\n--- END ATTACHMENT ---")
    return redact("\n".join(sections))


def extract_text(response: dict[str, Any]) -> str:
    blocks = response.get("content")
    if not isinstance(blocks, list):
        raise CSTKAIError("model response did not contain a content list")
    text = "\n".join(
        block.get("text", "")
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()
    if not text:
        raise CSTKAIError("model response contained no text")
    return redact(text)


def request_analysis(settings: Settings, prompt: str) -> tuple[str, dict[str, Any]]:
    body = json.dumps(
        {
            "model": settings.model,
            "max_tokens": settings.max_tokens,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
    if settings.api_key:
        headers["x-api-key"] = settings.api_key
        headers["authorization"] = f"Bearer {settings.api_key}"
    request = urllib.request.Request(settings.endpoint, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=settings.timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = redact(exc.read(2048).decode("utf-8", errors="replace"))
        raise CSTKAIError(f"model endpoint returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CSTKAIError(f"model endpoint unavailable: {exc.reason}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CSTKAIError(f"model response exceeded {MAX_RESPONSE_BYTES} byte limit")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CSTKAIError("model endpoint returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise CSTKAIError("model endpoint returned an unexpected JSON value")
    return extract_text(decoded), decoded


def private_data_dir() -> Path:
    cstk_data = os.environ.get("CSTK_USER_DATA_DIR")
    if cstk_data:
        return Path(cstk_data) / "AI" / "Sessions"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "cstk" / "ai" / "sessions"


def save_session(question: str, answer: str, model: str) -> Path:
    directory = private_data_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"analysis-{timestamp}-{os.getpid()}.json"
    payload = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "question": redact(question),
        "answer": redact(answer),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cstk-ai",
        description="CSTK defensive AI analyst (no autonomous tools or shell access).",
    )
    parser.add_argument("question", nargs="?", help="analysis question; stdin is used when omitted")
    parser.add_argument("-f", "--file", action="append", default=[], type=Path, help="UTF-8 text file to attach")
    parser.add_argument("--endpoint", default=os.environ.get("CSTK_AI_ENDPOINT", DEFAULT_ENDPOINT))
    parser.add_argument("--model", default=os.environ.get("CSTK_AI_MODEL"), help="model id or CSTK_AI_MODEL")
    parser.add_argument("--api-key-env", default="CSTK_AI_API_KEY", help="environment variable containing the API key")
    parser.add_argument("--prompt-key", action="store_true", help="securely prompt for an optional API key")
    parser.add_argument("--prompt-config", action="store_true", help="prompt for endpoint, model, and optional API key")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--save-session", action="store_true", help="save a redacted private transcript")
    parser.add_argument("--print-request", action="store_true", help="print the redacted prompt without network access")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.question is not None:
            question = args.question
        elif sys.stdin.isatty():
            question = input("CSTK AI question: ")
        else:
            question = sys.stdin.read()
        prompt = build_prompt(question, args.file, args.max_file_bytes)
        if args.print_request:
            print(prompt)
            return 0
        endpoint = args.endpoint
        if args.prompt_config and sys.stdin.isatty():
            entered_endpoint = input(f"Endpoint [{endpoint}]: ").strip()
            if entered_endpoint:
                endpoint = entered_endpoint
        model = args.model
        if not model and sys.stdin.isatty():
            model = input("Model id: ").strip()
        if not model:
            raise CSTKAIError("model is required; use --model or set CSTK_AI_MODEL")
        endpoint = validate_endpoint(endpoint)
        api_key = os.environ.get(args.api_key_env)
        if (args.prompt_key or args.prompt_config) and not api_key and sys.stdin.isatty():
            api_key = getpass.getpass("API key (leave blank for a keyless/local endpoint): ").strip() or None
        settings = Settings(endpoint, model, api_key, args.timeout, args.max_tokens)
        answer, _response = request_analysis(settings, prompt)
        print(answer)
        if args.save_session:
            path = save_session(prompt, answer, model)
            print(f"\nSaved private transcript: {path}", file=sys.stderr)
        return 0
    except CSTKAIError as exc:
        print(f"cstk-ai: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
