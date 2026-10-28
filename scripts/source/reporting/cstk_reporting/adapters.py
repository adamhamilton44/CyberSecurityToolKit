"""Explicit reporting inputs, not target authorization or raw command execution."""

from __future__ import annotations

import hashlib
import re

from .model import identifier, redact, text
from .storage import NotebookError, now

REMEDIATIONS = (
    (
        "Strict-Transport-Security",
        "Assess HSTS applicability, deploy an appropriate max-age on HTTPS responses, and validate deployment before adding includeSubDomains or preload.",
    ),
    (
        "Content-Security-Policy",
        "Define and test an application-specific Content Security Policy. Evaluate required origins and framing behavior before enforcing it.",
    ),
    (
        "X-Content-Type-Options",
        "Return X-Content-Type-Options: nosniff with correct response Content-Type values and verify affected routes.",
    ),
    (
        "SameSite",
        "Review session cookie use and choose an appropriate SameSite policy together with Secure and HttpOnly attributes.",
    ),
    (
        "TLS 1.0",
        "Disable legacy TLS versions where compatible with documented client requirements and retest supported protocols.",
    ),
    (
        "TLS 1.1",
        "Disable legacy TLS versions where compatible with documented client requirements and retest supported protocols.",
    ),
)


def import_web_tls_report(notebook, report_text, target):
    """Atomically import selected CSTK text as unverified operator observations.

    Original file is not copied, encrypted, removed, or vouched for by this API.
    Nothing is automatically confirmed and no CLI logging setting is consulted.
    """
    if not isinstance(report_text, str) or len(report_text.encode()) > 1024 * 1024:
        raise NotebookError("Selected Web/TLS report exceeds the one MiB import limit.")
    target = redact(text(target, 1000, False))
    fingerprint = hashlib.sha256(report_text.encode()).hexdigest()
    parsed = []
    for line in report_text.splitlines():
        match = re.fullmatch(r"\[(HIGH|MEDIUM|LOW|PASS|SKIP|INFO)\] (.{1,4096})", line)
        if match:
            parsed.append((match[1], redact(match[2])))
    if not parsed:
        raise NotebookError(
            "Selected text contains no recognized CSTK Web/TLS records."
        )
    if len(parsed) > 500:
        raise NotebookError(
            "Split reports containing more than 500 records for explicit review."
        )

    def apply(state):
        if any(a.get("source_sha256") == fingerprint for a in state["activities"]):
            raise NotebookError("This report has already been imported.")
        scope = state["scope_history"][-1]
        activity_id = identifier("A")
        ids = []
        stamp = now()
        for severity, observation in parsed:
            if severity in ("HIGH", "MEDIUM", "LOW"):
                note_id = identifier("N")
                state["notes"].append(
                    {
                        "id": note_id,
                        "at": stamp,
                        "title": "Imported Web/TLS observation",
                        "body": f"[{severity}] {observation}",
                        "asset": target,
                        "kind": "evidence",
                        "report_include": False,
                        "withdrawn": False,
                    }
                )
                remediation = next(
                    (
                        advice
                        for token, advice in REMEDIATIONS
                        if token.lower() in observation.lower()
                    ),
                    "",
                )
                finding_id = identifier("F")
                ids.append(finding_id)
                state["findings"].append(
                    {
                        "id": finding_id,
                        "at": stamp,
                        "title": observation[:160],
                        "asset": target,
                        "observation": observation,
                        "severity": severity.title(),
                        "status": "candidate",
                        "evidence_ids": [note_id],
                        "activity_id": activity_id,
                        "scope_revision": scope["revision"],
                        "scope_sha256": scope["scope_sha256"],
                        "impact": "",
                        "remediation": remediation,
                        "validation": "",
                        "reviewer": "",
                        "severity_reason": "",
                        "disposition_reason": "",
                        "owner": "",
                        "target_date": "",
                        "references": "",
                    }
                )
            elif severity == "SKIP":
                state["notes"].append(
                    {
                        "id": identifier("N"),
                        "at": stamp,
                        "title": "Imported check limitation",
                        "body": observation,
                        "asset": target,
                        "kind": "limitation",
                        "report_include": True,
                        "withdrawn": False,
                    }
                )
        outcome = (
            "partial" if any(level == "SKIP" for level, _ in parsed) else "completed"
        )
        state["activities"].append(
            {
                "id": activity_id,
                "tool": "Web/TLS Security Assessment import",
                "target": target,
                "started_at": stamp,
                "finished_at": stamp,
                "outcome": outcome,
                "exit_code": None,
                "origin": "operator",
                "scope_revision": scope["revision"],
                "scope_sha256": scope["scope_sha256"],
                "source_sha256": fingerprint,
                "summary": f"Operator imported {len(parsed)} recognized Web/TLS records; {len(ids)} candidate findings require review. Source authenticity, original execution time, and tool execution have not been independently verified.",
            }
        )
        return ids

    return notebook._edit("web_tls_report_imported", apply)


from contextlib import contextmanager


@contextmanager
def capture_authorized_operation(notebook, decision, tool):
    """Hook for a trusted guard adapter AFTER its own current authorization check.

    This checks reporting binding only. It does not validate scope, resolve a
    hostname, authorize a redirect, or execute a tool. The caller still owns all
    engine authorization and destination enforcement.
    """
    if not isinstance(decision, dict) or decision.get("allowed") is not True:
        raise NotebookError(
            "A denied or missing decision cannot start a guarded capture."
        )
    if decision.get("engagement_id") != notebook.snapshot()["engagement_id"]:
        raise NotebookError("Guarded capture belongs to a different engagement.")
    if type(decision.get("scope_revision")) is not int or not isinstance(
        decision.get("scope_sha256"), str
    ):
        raise NotebookError(
            "Guarded capture requires an explicit scope revision and hash."
        )
    if not isinstance(decision.get("target"), str):
        raise NotebookError("Guarded capture requires a target.")
    with notebook.capture(
        tool,
        decision["target"],
        scope_revision=decision.get("scope_revision"),
        scope_sha256=decision.get("scope_sha256"),
    ) as result:
        yield result
