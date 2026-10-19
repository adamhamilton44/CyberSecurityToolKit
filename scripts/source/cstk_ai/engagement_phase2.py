"""Adapter from CSTK AI to the existing phase-2 engagement policy engine.

AI output may create a review candidate, but only the policy engine's normal
revision, validation, and transition workflow can change authorization.
"""
from __future__ import annotations
import importlib.util
import json
import os
from datetime import datetime, timezone
import math
import re
from pathlib import Path
from typing import Any

DEFAULT_ENGINE = Path(__file__).with_name("cstk_engagement.py")
ALLOWED_CANDIDATE_PATHS = {
    "name", "client", "authorization.reference", "authorization.system_owner",
    "authorization.authorized_by", "authorization.valid_from",
    "authorization.valid_until", "authorization.timezone", "contacts",
    "scope.include", "scope.exclude", "actions.allow",
    "actions.confirm_each_run", "actions.deny", "constraints.testing_windows",
    "constraints.allowed_source_ips", "constraints.ports",
    "constraints.max_requests_per_second", "constraints.max_bandwidth_mbps",
    "constraints.max_concurrency", "constraints.stop_conditions",
    "technical_policy.scan_intensity", "technical_policy.automatic_exploitation",
    "technical_policy.denial_of_service", "data_handling", "reporting", "notes",
}

class BridgeError(RuntimeError): pass

class Phase2Bridge:
    def __init__(self, root: Path | None = None, engine_path: Path | None = None):
        self.root = root or Path.home()/".local/share/cstk/Engagements"
        self.engine_path = engine_path or Path(os.environ.get("CSTK_ENGAGEMENT_ENGINE", DEFAULT_ENGINE))
        spec = importlib.util.spec_from_file_location("cstk_ai_phase2_engine", self.engine_path)
        if spec is None or spec.loader is None: raise BridgeError(f"unable to load engagement engine: {self.engine_path}")
        self.engine = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.engine)

    def list(self) -> list[dict[str, Any]]:
        return [self.engine.refresh_summary(path) for path in self.engine.engagement_candidates(self.root)]

    def detail(self, identifier: str) -> dict[str, Any]:
        directory = self.engine.resolve_engagement(self.root, identifier)
        config, revision, digest = self.engine.load_current_config(directory)
        return {"directory": directory, "config": config, "revision": revision, "sha256": digest, "state": self.engine.load_state(directory), "activation_errors": self.engine.validation_errors(config, activation=True)}

    def ai_context(self, identifier: str) -> dict[str, Any]:
        item = self.detail(identifier)
        if item["state"] != "active": raise BridgeError("engagement is not active; AI authorization context withheld")
        config = item["config"]
        return {
            "engagement_id": config["engagement_id"], "slug": config["slug"],
            "revision": item["revision"], "revision_sha256": item["sha256"],
            "authorization": config["authorization"], "scope": config["scope"],
            "actions": config["actions"], "constraints": config["constraints"],
            "technical_policy": config["technical_policy"],
            "incident_coordination": config["incident_coordination"],
            "data_handling": config["data_handling"],
        }

    def hud_snapshot(self, identifier: str, now: datetime | None = None) -> dict[str, Any]:
        """Return the small set of facts an operator must see continuously."""
        item = self.detail(identifier); config = item["config"]
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise BridgeError("HUD time must include a timezone")
        starts = self.engine.parse_datetime(config["authorization"]["valid_from"])
        ends = self.engine.parse_datetime(config["authorization"]["valid_until"])
        seconds = (ends - current).total_seconds()
        if current < starts: timing = "NOT STARTED"
        elif seconds <= 0: timing = "EXPIRED"
        elif seconds < 48*3600: timing = f"{max(1, math.ceil(seconds/3600))} HOURS LEFT"
        else: timing = f"{math.ceil(seconds/86400)} DAYS LEFT"
        contacts = {entry["role"]: entry for entry in config.get("contacts", [])}
        emergency = contacts.get("emergency") or contacts.get("primary") or {}
        actions = config["actions"]; constraints = config["constraints"]
        inside_window = self.engine._inside_testing_window(config, current)
        operational = item["state"] == "active" and starts <= current < ends and inside_window
        return {
            "state": item["state"].upper(), "operational": operational,
            "timing": timing, "client": config.get("client") or "NOT SET",
            "name": config["name"], "slug": config["slug"],
            "valid_from": config["authorization"]["valid_from"],
            "valid_until": config["authorization"]["valid_until"],
            "timezone": config["authorization"]["timezone"],
            "inside_testing_window": inside_window,
            "included_targets": len(config["scope"]["include"]),
            "excluded_targets": len(config["scope"]["exclude"]),
            "allowed_actions": len(actions["allow"]),
            "confirm_actions": len(actions["confirm_each_run"]),
            "denied_actions": len(actions["deny"]),
            "source_ip_rules": len(constraints["allowed_source_ips"]),
            "max_rps": constraints["max_requests_per_second"],
            "max_concurrency": constraints["max_concurrency"],
            "emergency_contact": emergency.get("name", "NOT SET"),
            "emergency_method": emergency.get("method", "NOT SET"),
            "revision": item["revision"], "revision_sha256": item["sha256"],
        }

    def capture_ai_candidate(self, identifier: str, payload: dict[str, Any]) -> Path:
        item = self.detail(identifier); accepted = {key:value for key,value in payload.items() if key in ALLOWED_CANDIDATE_PATHS}
        if not accepted: raise BridgeError("AI candidate contains no recognized engagement fields")
        record = {
            "kind": "cstk-ai-engagement-candidate-v1", "status": "review_required",
            "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "base_revision": item["revision"], "base_revision_sha256": item["sha256"],
            "fields": accepted,
        }
        destination = item["directory"]/"Temp"/"ai-engagement-candidate.json"
        self.engine.atomic_write(destination, self.engine.canonical_json_bytes(record))
        self.engine.append_audit(item["directory"], "ai_engagement_candidate_captured", {"fields": sorted(accepted), "candidate": str(destination.relative_to(item["directory"]))})
        return destination

    def questionnaire_questions(self) -> list[dict[str, str]]:
        """Return the policy engine's mandatory questions in document order."""
        text = self.engine.safe_read(self.engine.QUESTIONNAIRE_PATH).decode("utf-8")
        found = re.findall(r"^\* \*\*([A-Z0-9_]+)\*\*:\s*(.+)$", text, re.MULTILINE)
        questions = [
            {"tag": tag, "question": question.strip(), "config_path": self.engine.QUESTION_TO_CONFIG[tag]}
            for tag, question in found if tag in self.engine.QUESTION_TO_CONFIG
        ]
        if {entry["tag"] for entry in questions} != set(self.engine.QUESTION_TO_CONFIG):
            raise BridgeError("questionnaire tags do not match the policy engine")
        return questions

    def questionnaire_candidate(self, identifier: str) -> dict[str, Any]:
        item = self.detail(identifier)
        destination = item["directory"] / "Temp" / "ai-questionnaire-candidate.json"
        if not destination.exists():
            return {
                "kind": "cstk-ai-questionnaire-candidate-v1",
                "status": "review_required",
                "base_revision": item["revision"],
                "base_revision_sha256": item["sha256"],
                "answers": {},
            }
        record = self.engine.read_json(destination)
        if record.get("kind") != "cstk-ai-questionnaire-candidate-v1" or not isinstance(record.get("answers"), dict):
            raise BridgeError("invalid questionnaire candidate record")
        return record

    def capture_questionnaire_answer(self, identifier: str, tag: str, answer: str, source: str = "operator") -> Path:
        tag = tag.strip().upper()
        answer = answer.strip()
        if tag not in self.engine.QUESTION_TO_CONFIG:
            raise BridgeError(f"unknown questionnaire tag: {tag}")
        if not answer:
            raise BridgeError("questionnaire answer cannot be empty")
        if source not in {"operator", "ai"}:
            raise BridgeError("questionnaire answer source must be operator or ai")
        item = self.detail(identifier)
        record = self.questionnaire_candidate(identifier)
        # A changed authorization revision must be reviewed as a new candidate.
        if (record["base_revision"], record["base_revision_sha256"]) != (item["revision"], item["sha256"]):
            raise BridgeError("engagement revision changed; start a new questionnaire review candidate")
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        record.setdefault("created_at", now)
        record["updated_at"] = now
        record["answers"][tag] = {
            "answer": answer,
            "source": source,
            "config_path": self.engine.QUESTION_TO_CONFIG[tag],
        }
        destination = item["directory"] / "Temp" / "ai-questionnaire-candidate.json"
        self.engine.atomic_write(destination, self.engine.canonical_json_bytes(record))
        self.engine.append_audit(item["directory"], "ai_questionnaire_answer_captured", {
            "tag": tag, "source": source,
            "candidate": str(destination.relative_to(item["directory"])),
        })
        return destination

    def questionnaire_progress(self, identifier: str) -> dict[str, Any]:
        record = self.questionnaire_candidate(identifier)
        questions = self.questionnaire_questions()
        answered = set(record["answers"])
        remaining = [entry for entry in questions if entry["tag"] not in answered]
        return {
            "answered": len(answered), "total": len(questions),
            "remaining": remaining, "complete": not remaining,
            "status": record["status"],
            "base_revision": record["base_revision"],
            "base_revision_sha256": record["base_revision_sha256"],
        }
