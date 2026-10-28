"""Notebook operations and report-review lifecycle; independent of optional tool logs."""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model import (
    DISPOSITIONS,
    PROFILE_KEYS,
    SEVERITIES,
    clean,
    content_digest,
    get_record,
    identifier,
    new_state,
    readiness,
    redact,
    require_open,
    scope_snapshot,
    text,
)
from .storage import NotebookError, Vault, canonical, digest, event, now


class Notebook:
    def __init__(self, vault):
        self.vault = vault

    @classmethod
    def create(cls, path, passphrase, config, revision, scope_sha256):
        scope = scope_snapshot(config, revision, scope_sha256)
        state = new_state(scope)
        defaults = {
            "client": config.get("client") or "",
            "engagement_name": config.get("name") or "",
            "engagement_reference": config.get("authorization", {}).get("reference")
            or "",
            "assessment_type": config.get("engagement_type") or "",
            "delivery_method": config.get("reporting", {}).get("delivery_method") or "",
        }
        retention = config.get("data_handling", {}).get("retention_days")
        if type(retention) is int:
            defaults["retention_days"] = str(retention)
        state["profile"] = {key: redact(text(value)) for key, value in defaults.items()}
        return cls(Vault.create(path, passphrase, state))

    @classmethod
    def open(cls, path, passphrase):
        vault = Vault(path)
        try:
            return cls(vault.unlock(passphrase))
        except Exception:
            vault.close()
            raise

    def close(self):
        self.vault.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def snapshot(self):
        return self.vault.read()

    def _edit(self, kind, change):
        def apply(state):
            require_open(state)
            result = change(state)
            event(
                state, kind, {"record_id": result if isinstance(result, str) else None}
            )
            return result

        return self.vault.update(apply)

    def set_profile(self, answers):
        if not isinstance(answers, dict) or set(answers) - PROFILE_KEYS:
            raise NotebookError("Unknown reporting questionnaire fields.")
        answers = {key: redact(str(value)) for key, value in answers.items()}
        self._edit(
            "reporting_profile_updated", lambda state: state["profile"].update(answers)
        )

    def revise_scope_snapshot(self, config, revision, scope_sha256):
        scope = scope_snapshot(config, revision, scope_sha256)

        def apply(state):
            if scope["engagement_id"] != state["engagement_id"]:
                raise NotebookError("Cross-engagement snapshot refused.")
            current = state["scope_history"][-1]
            if scope["revision"] <= current["revision"]:
                raise NotebookError("Scope snapshot revisions must increase.")
            state["scope_history"].append(scope)

        self._edit("scope_snapshot_added", apply)

    def add_note(self, title, body, *, asset="", kind="operator", report_include=False):
        if kind not in ("operator", "evidence", "limitation", "positive_control"):
            raise NotebookError("Invalid note kind.")
        note = clean(
            {
                "id": identifier("N"),
                "at": now(),
                "title": text(title, 200, False),
                "body": text(body, empty=False),
                "asset": text(asset, 1000),
                "kind": kind,
                "report_include": bool(report_include),
                "withdrawn": False,
            }
        )

        def apply(state):
            state["notes"].append(note)
            return note["id"]

        return self._edit("note_added", apply)

    def update_note(self, note_id, *, body=None, report_include=None, withdrawn=None):
        def apply(state):
            note = get_record(state, "notes", note_id)
            if body is not None:
                revised = redact(text(body, empty=False))
                if revised != note["body"]:
                    note["body"] = revised
                    for finding in state["findings"]:
                        if (
                            note_id in finding["evidence_ids"]
                            and finding["status"] == "confirmed"
                        ):
                            finding.update(
                                status="candidate",
                                reviewer="",
                                severity_reason="",
                                disposition_reason="Evidence changed; review required.",
                            )
            if report_include is not None:
                if report_include and note["kind"] == "evidence":
                    raise NotebookError(
                        "Evidence is included only through a confirmed finding."
                    )
                note["report_include"] = bool(report_include)
            if withdrawn is not None:
                if withdrawn and any(
                    note_id in f["evidence_ids"] and f["status"] == "confirmed"
                    for f in state["findings"]
                ):
                    raise NotebookError(
                        "Evidence supports a confirmed finding; revise that finding first."
                    )
                note["withdrawn"] = bool(withdrawn)
            note["updated_at"] = now()
            return note_id

        self._edit("note_revised", apply)

    def add_finding(
        self,
        title,
        asset,
        observation,
        *,
        proposed_severity="Informational",
        evidence_ids=(),
        activity_id=None,
        remediation="",
    ):
        if proposed_severity not in SEVERITIES:
            raise NotebookError("Invalid proposed severity.")
        finding = clean(
            {
                "id": identifier("F"),
                "at": now(),
                "title": text(title, 200, False),
                "asset": text(asset, 1000, False),
                "observation": text(observation, empty=False),
                "severity": proposed_severity,
                "status": "candidate",
                "evidence_ids": list(evidence_ids),
                "activity_id": activity_id,
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

        def apply(state):
            for note_id in finding["evidence_ids"]:
                note = get_record(state, "notes", note_id)
                if note["withdrawn"]:
                    raise NotebookError("Withdrawn evidence cannot support a finding.")
            if activity_id:
                get_record(state, "activities", activity_id)
            finding["scope_revision"] = state["scope_history"][-1]["revision"]
            finding["scope_sha256"] = state["scope_history"][-1]["scope_sha256"]
            state["findings"].append(finding)
            return finding["id"]

        return self._edit("finding_candidate_added", apply)

    def review_finding(self, finding_id, status, reviewer, **updates):
        allowed = {
            "title",
            "asset",
            "observation",
            "severity",
            "impact",
            "remediation",
            "validation",
            "severity_reason",
            "disposition_reason",
            "owner",
            "target_date",
            "references",
            "duplicate_of",
            "evidence_ids",
        }
        if status not in DISPOSITIONS or set(updates) - allowed:
            raise NotebookError("Invalid review fields or disposition.")
        if updates.get("severity") and updates["severity"] not in SEVERITIES:
            raise NotebookError("Invalid severity.")

        def apply(state):
            finding = get_record(state, "findings", finding_id)
            for key, value in updates.items():
                if key == "evidence_ids":
                    if not isinstance(value, list) or len(value) > 100:
                        raise NotebookError("Invalid evidence references.")
                    for note_id in value:
                        note = get_record(state, "notes", note_id)
                        if note["withdrawn"]:
                            raise NotebookError(
                                "Withdrawn evidence cannot support a finding."
                            )
                    finding[key] = list(dict.fromkeys(value))
                else:
                    finding[key] = redact(text(value))
            finding.update(
                status=status,
                reviewer=redact(text(reviewer, 200, False)),
                reviewed_at=now(),
            )
            if status == "confirmed":
                if not finding["evidence_ids"]:
                    raise NotebookError("Confirm only findings with evidence.")
                for key in (
                    "title",
                    "asset",
                    "observation",
                    "impact",
                    "remediation",
                    "validation",
                    "severity_reason",
                ):
                    if not finding[key].strip():
                        raise NotebookError(f"Confirmed finding requires {key}.")
            elif (
                status in ("false_positive", "excluded", "duplicate")
                and not finding["disposition_reason"]
            ):
                raise NotebookError("A disposition reason is required.")
            if status == "duplicate":
                other = get_record(state, "findings", finding.get("duplicate_of", ""))
                if other["id"] == finding_id or other["status"] != "confirmed":
                    raise NotebookError(
                        "Duplicate must reference another confirmed finding."
                    )
            return finding_id

        return self._edit("finding_reviewed", apply)

    def start_activity(
        self, tool, target, *, origin="adapter", scope_revision=None, scope_sha256=None
    ):
        if origin not in ("adapter", "operator"):
            raise NotebookError("Invalid capture origin.")

        def apply(state):
            scope = state["scope_history"][-1]
            revision = scope["revision"] if scope_revision is None else scope_revision
            sha = scope["scope_sha256"] if scope_sha256 is None else scope_sha256
            if revision != scope["revision"] or sha != scope["scope_sha256"]:
                raise NotebookError(
                    "Capture scope differs from notebook snapshot; import the current scope revision first."
                )
            record = clean(
                {
                    "id": identifier("A"),
                    "tool": text(tool, 200, False),
                    "target": text(target, 1000, False),
                    "started_at": now(),
                    "finished_at": None,
                    "outcome": "running",
                    "summary": "",
                    "origin": origin,
                    "scope_revision": revision,
                    "scope_sha256": sha,
                    "exit_code": None,
                }
            )
            state["activities"].append(record)
            return record["id"]

        return self._edit("activity_started", apply)

    def finish_activity(self, activity_id, outcome, summary, *, exit_code=None):
        if outcome not in ("completed", "partial", "error", "skipped"):
            raise NotebookError("Invalid activity outcome.")
        if exit_code is not None and (
            type(exit_code) is not int or not -255 <= exit_code <= 255
        ):
            raise NotebookError("Invalid exit code.")

        def apply(state):
            record = get_record(state, "activities", activity_id)
            if record["outcome"] != "running":
                raise NotebookError("Activity already has a terminal outcome.")
            record.update(
                outcome=outcome,
                summary=redact(text(summary, empty=False)),
                exit_code=exit_code,
                finished_at=now(),
            )
            return activity_id

        self._edit("activity_finished", apply)

    @contextmanager
    def capture(self, tool, target, **scope):
        """Future tool hook. Capture starts before tool execution; failures are visible."""
        record_id = self.start_activity(tool, target, **scope)
        result = {
            "id": record_id,
            "outcome": "partial",
            "summary": "Tool returned without a structured assessment summary.",
            "exit_code": None,
        }
        try:
            yield result
        except BaseException:
            self.finish_activity(
                record_id,
                "error",
                "Tool did not complete; inspect the operator incident record.",
                exit_code=1,
            )
            raise
        else:
            self.finish_activity(
                record_id,
                result["outcome"],
                result["summary"],
                exit_code=result["exit_code"],
            )

    def readiness(self):
        return readiness(self.snapshot())

    def _register_export(self, state, record):
        import json

        from .report import discard_uncommitted_bundle

        try:
            self.vault._save(state)
        except Exception as error:
            try:
                saved = self.vault._decode(
                    json.loads(self.vault._read(self.vault.NAME))
                )
                committed = any(r["id"] == record["id"] for r in saved["reports"])
            except Exception:
                raise NotebookError(
                    "Notebook save could not be verified; the private export was retained. Check notebook and report integrity before relying on it."
                ) from error
            if committed:
                raise NotebookError(
                    "Notebook write occurred but durability could not be confirmed. The private export was retained; reopen and verify status before relying on it."
                ) from error
            try:
                discard_uncommitted_bundle(record["directory"], record["manifest"])
            except Exception:
                raise NotebookError(
                    "Notebook registration failed and export cleanup could not be verified. An unregistered private export may remain."
                ) from error
            raise NotebookError(
                "Notebook registration failed; the newly created report bundle was removed. No report was finalized."
            ) from error

    def export_draft(self, output_directory, *, soffice=None):
        from .report import export_bundle

        with self.vault.lock():
            state = self.vault._decode(
                __import__("json").loads(self.vault._read(self.vault.NAME))
            )
            require_open(state)
            report_id = identifier("R")
            manifest = export_bundle(
                state,
                output_directory,
                status="Draft for review",
                report_id=report_id,
                soffice=soffice,
            )
            record = {
                "id": report_id,
                "status": "draft",
                "created_at": now(),
                "content_sha256": content_digest(state),
                "directory": str(Path(output_directory).absolute()),
                "manifest": manifest,
            }
            state["reports"].append(record)
            event(
                state,
                "report_draft_created",
                {"report_id": report_id, "content_sha256": record["content_sha256"]},
            )
            self._register_export(state, record)
            return record

    def finalize(self, candidate_id, reviewer, output_directory, *, soffice=None):
        from .model import readiness
        from .report import export_bundle, verify_bundle

        with self.vault.lock():
            state = self.vault._decode(
                __import__("json").loads(self.vault._read(self.vault.NAME))
            )
            require_open(state)
            errors = readiness(state)
            if errors:
                raise NotebookError("Report is not ready: " + "; ".join(errors))
            candidate = get_record(state, "reports", candidate_id)
            if candidate["status"] != "draft" or candidate[
                "content_sha256"
            ] != content_digest(state):
                raise NotebookError(
                    "Draft is stale. Regenerate and review the current report."
                )
            verify_bundle(candidate["directory"], candidate["manifest"])
            reviewer = redact(text(reviewer, 200, False))
            report_id = identifier("R")
            finalized_at = now()
            manifest = export_bundle(
                state,
                output_directory,
                status="Final",
                report_id=report_id,
                reviewer=reviewer,
                finalized_at=finalized_at,
                soffice=soffice,
            )
            record = {
                "id": report_id,
                "status": "final",
                "created_at": finalized_at,
                "reviewer": reviewer,
                "content_sha256": content_digest(state),
                "reviewed_candidate": candidate_id,
                "directory": str(Path(output_directory).absolute()),
                "manifest": manifest,
            }
            state["reports"].append(record)
            state["lifecycle"] = "finalized"
            state["final_report_id"] = report_id
            event(
                state,
                "report_finalized",
                {
                    "report_id": report_id,
                    "reviewer": reviewer,
                    "content_sha256": record["content_sha256"],
                },
            )
            self._register_export(state, record)
            return record

    def reopen(self, reason):
        reason = redact(text(reason, empty=False))

        def apply(state):
            if state["lifecycle"] != "finalized":
                raise NotebookError("Only a finalized notebook can be reopened.")
            state["lifecycle"] = "open"
            state["final_report_id"] = None
            event(state, "notebook_reopened", {"reason": reason})

        self.vault.update(apply)

    def purge(self, confirmation, *, override_reason=""):
        import json

        from .report import verify_bundle

        with self.vault.lock():
            state = self.vault._decode(json.loads(self.vault._read(self.vault.NAME)))
            if confirmation != "DELETE NOTES " + state["engagement_id"]:
                raise NotebookError(
                    "Deletion confirmation does not match the engagement."
                )
            if state["lifecycle"] != "finalized":
                raise NotebookError(
                    "Finalize and verify the report before deleting notes."
                )
            if state["profile"].get("legal_hold") != "no":
                raise NotebookError("Legal hold blocks notebook deletion.")
            final = get_record(state, "reports", state["final_report_id"])
            verify_bundle(final["directory"], final["manifest"])
            due = datetime.fromisoformat(
                final["created_at"].replace("Z", "+00:00")
            ) + timedelta(days=int(state["profile"]["retention_days"]))
            if datetime.now(timezone.utc) < due and not text(override_reason):
                raise NotebookError(
                    "Retention period has not elapsed. An explicit override reason is required."
                )
            # Receipt has no client name, targets, findings, or passphrase.
            receipt = {
                "format": "cstk-notebook-deletion-1",
                "engagement_id": state["engagement_id"],
                "deleted_at": now(),
                "final_report_id": final["id"],
                "final_manifest_sha256": digest(final["manifest"]),
                "retention_overridden": datetime.now(timezone.utc) < due,
            }
            self.vault._atomic("deleted.json", canonical(receipt))
            os.unlink(self.vault.NAME, dir_fd=self.vault.fd)
            os.fsync(self.vault.fd)
            self.vault.key = None
            return receipt
