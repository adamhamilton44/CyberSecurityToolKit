"""Build a fictional report for layout QA; never contacts an assessment target."""

import argparse
import hashlib
import json
import secrets
import tempfile
from pathlib import Path

from cstk_reporting.adapters import import_web_tls_report
from cstk_reporting.service import Notebook


def build(output, soffice):
    profile = json.loads(Path(__file__).with_name("reporting_answers.json").read_text())
    config = json.loads(Path(__file__).with_name("scope_revision.json").read_text())
    with tempfile.TemporaryDirectory(prefix="cstk-reporting-demo-") as temporary:
        base = Path(temporary)
        with Notebook.create(
            base / "vault",
            secrets.token_urlsafe(36),
            config,
            1,
            hashlib.sha256(
                Path(__file__).with_name("scope_revision.json").read_bytes()
            ).hexdigest(),
        ) as notebook:
            notebook.set_profile(profile)
            ids = import_web_tls_report(
                notebook,
                "[MEDIUM] Session cookie on the login response is missing the Secure attribute.\n"
                "[LOW] Content-Security-Policy is absent from the selected HTML response.\n"
                "[LOW] Referrer-Policy is absent from the redirect response.\n"
                "[PASS] Certificate trust and hostname checks completed.\n"
                "[SKIP] Legacy TLS probe was inconclusive under local client policy.",
                "https://portal.example.test/login",
            )
            note = notebook.add_note(
                "Reviewed session cookie attributes",
                "Selected response: GET /login over HTTPS.\nCookie name: portal_session.\nObserved flags: HttpOnly present; SameSite=Lax; Secure absent.\nCookie value was not retained.",
                asset="https://portal.example.test/login",
                kind="evidence",
            )
            notebook.review_finding(
                ids[0],
                "confirmed",
                "Jordan Example",
                severity="Medium",
                title="Session cookie lacks the Secure attribute",
                evidence_ids=[note],
                impact="A browser may send this cookie over an HTTP connection to a matching host and path. Exposure depends on network conditions and application transport controls; account compromise was not demonstrated.",
                remediation="Set Secure on the session cookie at its point of issuance, preserve HttpOnly, and verify that session-bearing routes require HTTPS. Test all session issuance and renewal paths before deployment.",
                validation="The reviewer inspected the selected login response and confirmed the absent Secure flag. No cookie value was retained or replayed.",
                severity_reason="Medium reflects a plausible transport exposure of a session identifier. No successful interception or account access was performed.",
                owner="Application platform team",
                target_date="2026-11-11",
            )
            notebook.review_finding(
                ids[1],
                "confirmed",
                "Jordan Example",
                severity="Low",
                title="Content Security Policy is not enforced",
                impact="The selected HTML response lacks a browser-enforced content policy. This reduces defense in depth but does not demonstrate an injection vulnerability.",
                remediation="Inventory required script, style, and connection origins. Test an application-specific policy in report-only mode, then enforce a validated policy. Set an explicit frame-ancestors directive where appropriate.",
                validation="The reviewer checked the selected response headers. Authenticated routes and application injection paths were not tested.",
                severity_reason="Low reflects a defense-in-depth configuration gap without a demonstrated exploit.",
                owner="Web application team",
                target_date="2026-11-25",
            )
            notebook.review_finding(
                ids[2],
                "excluded",
                "Jordan Example",
                disposition_reason="The observed redirect does not establish the policy of the destination HTML document. Capture and review the final response in a separately approved check.",
            )
            notebook.add_note(
                "Observed positive controls",
                "The selected HTTPS endpoint presented a trusted certificate matching its hostname. This result applies to the captured endpoint and assessment time only.",
                kind="positive_control",
                report_include=True,
            )
            notebook.add_note(
                "Internal scheduling discussion",
                "Internal note intentionally excluded from the client report.",
            )
            with notebook.capture(
                "Guarded TCP connectivity example", "192.0.2.10:443"
            ) as result:
                result.update(
                    outcome="completed",
                    summary="A bounded TCP connection completed. No application payload, vulnerability test, or authentication attempt was performed.",
                    exit_code=0,
                )
            errors = notebook.readiness()
            if errors:
                raise RuntimeError("; ".join(errors))
            draft = notebook.export_draft(base / "reviewed-draft", soffice=soffice)
            final = notebook.finalize(
                draft["id"], "Jordan Example", output, soffice=soffice
            )
            # Public verification receipt only; no passphrase, client evidence, or vault key.
            (Path(output) / "sample-verification.json").write_text(
                json.dumps(
                    {
                        "fictional_example": True,
                        "readiness_issues": 0,
                        "lifecycle": notebook.snapshot()["lifecycle"],
                        "encrypted_notebook_bytes": (base / "vault/notebook.enc")
                        .stat()
                        .st_size,
                        "report_id": final["id"],
                        "notes": len(notebook.snapshot()["notes"]),
                        "findings": len(notebook.snapshot()["findings"]),
                        "activities": len(notebook.snapshot()["activities"]),
                    },
                    indent=2,
                )
            )
            __import__("os").chmod(Path(output) / "sample-verification.json", 0o600)
            return final


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--soffice", required=True)
    args = parser.parse_args()
    build(args.output, args.soffice)
