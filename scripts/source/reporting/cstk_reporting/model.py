"""Reporting-only metadata and review policy; never changes testing authorization."""

from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from .storage import NotebookError, digest, event, now

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
DISPOSITIONS = ("candidate", "confirmed", "false_positive", "duplicate", "excluded")
QUESTIONS = (
    ("client", "Client organization", "required"),
    ("engagement_name", "Engagement name", "required"),
    ("engagement_reference", "Contract or engagement reference", "required"),
    ("assessment_type", "Assessment type and approach", "required"),
    ("author", "Report author or assessment team", "required"),
    ("audience", "Intended audience and technical depth", "required"),
    ("recipients", "Approved report recipients", "required"),
    ("classification", "Report classification and handling label", "required"),
    ("objectives", "What business questions should this assessment answer", "required"),
    ("business_context", "Which services and business impacts matter most", "required"),
    ("priority_assets", "Which approved assets are most important and why", "optional"),
    ("testing_start", "Actual testing start date YYYY-MM-DD", "required"),
    ("testing_end", "Actual testing end date YYYY-MM-DD", "required"),
    ("methodology", "Testing approach and techniques actually used", "required"),
    (
        "limitations",
        "Access gaps, unavailable roles, time limits, and checks not performed",
        "required",
    ),
    ("delivery_method", "Approved secure delivery channel", "required"),
    (
        "evidence_policy",
        "What evidence may appear in the report and what must be masked",
        "required",
    ),
    (
        "retention_days",
        "Notebook retention days after finalization (no automatic deletion)",
        "required",
    ),
    ("legal_hold", "Is evidence subject to a legal hold yes or no", "required"),
    (
        "escalation_reference",
        "Critical finding notification and acknowledgement references",
        "optional",
    ),
    (
        "remediation_context",
        "Remediation owners and agreed response targets",
        "optional",
    ),
    ("executive_context", "Optional operator-written executive narrative", "optional"),
)
PROFILE_KEYS = {row[0] for row in QUESTIONS}
REQUIRED = {row[0] for row in QUESTIONS if row[2] == "required"}
TEXT_LIMIT = 24000


def text(value, limit=TEXT_LIMIT, empty=True):
    if not isinstance(value, str):
        raise NotebookError("Text fields must be strings.")
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = "".join(
        c
        for c in value
        if c in "\n\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs")
    )
    if len(value) > limit:
        raise NotebookError(f"Text exceeds {limit} characters.")
    if not empty and not value.strip():
        raise NotebookError("Required text is missing.")
    return value.strip()


def safe_url(match):
    raw = match.group(0)
    try:
        url = urlsplit(raw)
        host = url.hostname or ""
        if ":" in host:
            host = "[" + host + "]"
        if url.port:
            host += ":" + str(url.port)
        clean = urlunsplit((url.scheme, host, url.path, "", ""))
        if url.query:
            clean += "?[redacted]"
        return clean
    except ValueError:
        return "[redacted URL]"


def redact(value):
    value = text(value)
    value = re.sub(
        r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)",
        "[REDACTED PRIVATE KEY]",
        value,
        flags=re.S,
    )
    value = re.sub(
        r"(?im)^\s*(authorization|proxy-authorization|cookie|set-cookie)\s*:[^\n]*",
        r"\1: [REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_=.-]{12,}",
        "[REDACTED AUTHENTICATION]",
        value,
    )
    value = re.sub(
        r'(?i)\b(password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|token|secret)[\"\']?\s*([=:])\s*(?:"[^"\n]*"|\'[^\'\n]*\'|[^\s,;]+)',
        r"\1\2[REDACTED]",
        value,
    )
    value = re.sub(r'https?://[^\s<>"\']+', safe_url, value)
    return value


def clean(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [clean(x) for x in value]
    if isinstance(value, dict):
        return {text(k, 100): clean(v) for k, v in value.items()}
    if value is None or isinstance(value, (int, bool)):
        return value
    raise NotebookError("Unsupported input value.")


def profile_errors(profile):
    errors = [
        f"Missing reporting answer: {key}"
        for key in sorted(REQUIRED)
        if not str(profile.get(key, "")).strip()
    ]
    for key in ("testing_start", "testing_end"):
        if profile.get(key):
            try:
                datetime.strptime(profile[key], "%Y-%m-%d")
            except (ValueError, TypeError):
                errors.append(f"{key} must be YYYY-MM-DD")
    if (
        profile.get("testing_start")
        and profile.get("testing_end")
        and profile["testing_start"] > profile["testing_end"]
    ):
        errors.append("Testing end precedes testing start.")
    try:
        if (
            str(int(profile.get("retention_days", "")))
            != str(profile.get("retention_days"))
            or not 0 <= int(profile["retention_days"]) <= 3650
        ):
            raise ValueError
    except (ValueError, TypeError):
        errors.append("Retention days must be an integer between 0 and 3650.")
    if profile.get("legal_hold") not in ("yes", "no"):
        errors.append("Legal hold must be yes or no.")
    return errors


def scope_snapshot(config, revision, sha256):
    """Copy a whitelisted snapshot; it is report context, never execution authority."""
    if not isinstance(config, dict):
        raise NotebookError("Engagement configuration must be an object.")
    try:
        identity = str(uuid.UUID(str(config["engagement_id"])))
    except (KeyError, ValueError, TypeError):
        raise NotebookError("Engagement ID must be a UUID.")
    if (
        type(revision) is not int
        or revision < 1
        or not isinstance(sha256, str)
        or not re.fullmatch("[a-f0-9]{64}", sha256)
    ):
        raise NotebookError(
            "A positive scope revision and lowercase SHA-256 are required."
        )
    scope = config.get("scope", {})
    if not isinstance(scope, dict):
        raise NotebookError("Scope must be an object.")
    for field in ("name", "client", "engagement_type"):
        if config.get(field) is not None and not isinstance(config[field], str):
            raise NotebookError("Engagement metadata must be text.")
    for field in ("authorization", "reporting", "data_handling"):
        if field in config and not isinstance(config[field], dict):
            raise NotebookError("Engagement policy metadata must be objects.")
    for field in ("reference", "valid_from", "valid_until"):
        if field in config.get("authorization", {}) and not isinstance(
            config["authorization"][field], str
        ):
            raise NotebookError("Authorization references and dates must be text.")
    for key in ("include", "exclude"):
        if not isinstance(scope.get(key), list):
            raise NotebookError("Scope include/exclude must be arrays.")
        for entry in scope[key]:
            if (
                not isinstance(entry, dict)
                or entry.get("type")
                not in (
                    "ip",
                    "cidr",
                    "dns",
                    "wildcard_dns",
                    "hostname",
                    "domain",
                    "url",
                    "api",
                    "cloud",
                    "mobile_app",
                    "wireless",
                    "identity",
                    "repository",
                    "physical_location",
                )
                or not isinstance(entry.get("value"), str)
                or not entry["value"].strip()
            ):
                raise NotebookError("Invalid scope entry.")
    authorization = config.get("authorization", {})
    return clean(
        {
            "engagement_id": identity,
            "revision": revision,
            "scope_sha256": sha256,
            "name": config.get("name", ""),
            "client": config.get("client") or "",
            "authorization_reference": authorization.get("reference", ""),
            "valid_from": authorization.get("valid_from", ""),
            "valid_until": authorization.get("valid_until", ""),
            "scope": {
                key: [
                    {"type": entry["type"], "value": entry["value"]}
                    for entry in scope[key]
                ]
                for key in ("include", "exclude")
            },
            "captured_at": now(),
            "provenance": "operator_imported_snapshot",
        }
    )


def new_state(scope):
    state = {
        "schema": 1,
        "engagement_id": scope["engagement_id"],
        "created_at": now(),
        "lifecycle": "open",
        "scope_history": [scope],
        "profile": {},
        "notes": [],
        "activities": [],
        "findings": [],
        "reports": [],
        "events": [],
        "final_report_id": None,
    }
    event(
        state,
        "notebook_created",
        {"scope_revision": scope["revision"], "scope_sha256": scope["scope_sha256"]},
    )
    return state


def content(state):
    return {
        key: state[key]
        for key in (
            "engagement_id",
            "scope_history",
            "profile",
            "notes",
            "activities",
            "findings",
        )
    }


def content_digest(state):
    return digest(content(state))


def readiness(state):
    errors = profile_errors(state["profile"])
    if not state["scope_history"][-1]["scope"]["include"]:
        errors.append("No included scope snapshot is recorded.")
    if not state["activities"]:
        errors.append(
            "No assessment activities recorded; coverage cannot be established."
        )
    for finding in state["findings"]:
        if finding["status"] == "candidate":
            errors.append(f"{finding['id']}: finding needs a disposition.")
        if finding["status"] == "confirmed":
            for field in (
                "impact",
                "remediation",
                "validation",
                "reviewer",
                "severity_reason",
            ):
                if not finding.get(field):
                    errors.append(f"{finding['id']}: confirmed finding lacks {field}.")
            if not finding.get("evidence_ids"):
                errors.append(f"{finding['id']}: confirmed finding needs evidence.")
        elif not finding.get("disposition_reason"):
            errors.append(
                f"{finding['id']}: non-confirmed finding needs a disposition reason."
            )
        if finding["status"] == "duplicate":
            original = next(
                (
                    f
                    for f in state["findings"]
                    if f["id"] == finding.get("duplicate_of")
                ),
                None,
            )
            if original is None or original["status"] != "confirmed":
                errors.append(
                    f"{finding['id']}: duplicate reference needs a confirmed primary finding."
                )
    if not any(
        run["outcome"] in ("completed", "partial") for run in state["activities"]
    ):
        errors.append("No completed or partial assessment activity is recorded.")
    if any(run["outcome"] == "running" for run in state["activities"]):
        errors.append("One or more captured activities are still running.")
    if any(
        f["status"] == "confirmed" and f["severity"] == "Critical"
        for f in state["findings"]
    ) and not state["profile"].get("escalation_reference"):
        errors.append(
            "Confirmed Critical findings require a notification/acknowledgement reference; this tool does not notify anyone."
        )
    return errors


def require_open(state):
    if state["lifecycle"] != "open":
        raise NotebookError(
            "Notebook is finalized; explicitly reopen it before adding or editing records."
        )


def identifier(prefix):
    return prefix + "-" + uuid.uuid4().hex[:12]


def get_record(state, collection, record_id):
    for record in state[collection]:
        if record["id"] == record_id:
            return record
    raise NotebookError("Record not found.")
