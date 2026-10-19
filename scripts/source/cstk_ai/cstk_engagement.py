#!/usr/bin/env python3
"""Manage isolated CSTK engagement workspaces without network activity.

Phase 1 deliberately handles storage, revisioning, state, selection, and audit
only. Target/action enforcement is a later phase and must not be inferred from
the presence of an active engagement.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCHEMA_VERSION = 1
DIR_MODE = 0o700
FILE_MODE = 0o600
STATES = ("draft", "ready", "active", "paused", "closed", "archived")
DATA_DIRS = ("Loot", "Malware", "Logs", "Evidence", "Reports", "Audit", "Runs", "Temp")
TARGET_TYPES = (
    "ip",
    "cidr",
    "dns",
    "wildcard_dns",
    "url",
    "api",
    "cloud",
    "mobile_app",
    "wireless",
    "identity",
    "repository",
    "physical_location",
)
ACTIONS = (
    "recon.passive",
    "network.discovery",
    "vulnerability.scan",
    "web.passive",
    "web.active",
    "credential.offline",
    "credential.online",
    "exploit.validation",
    "payload.generate",
    "payload.deliver",
    "post_exploitation",
    "persistence",
    "credential.access",
    "command_and_control",
    "data.access",
    "data.exfiltration",
    "social_engineering",
    "wireless",
    "physical",
    "availability.disruption",
    "data.modification",
    "log.tampering",
    "destructive",
)
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DNS_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
TIME_RE = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
WEEKDAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
QUESTIONNAIRE_NAME = "engagement_scoping_cheat_sheet.md"
QUESTIONNAIRE_PATH = Path(__file__).with_name(QUESTIONNAIRE_NAME)
QUESTION_TO_CONFIG = {
    "TARGET_LIST": "scope.include",
    "OUT_OF_SCOPE": "scope.exclude",
    "THIRD_PARTY_INFRASTRUCTURE": "environment.third_party_infrastructure",
    "ENVIRONMENT_TYPE": "environment.types",
    "HOSTING_LOCATION": "environment.access_method and environment.access_notes",
    "MAX_THROUGHPUT": "constraints.max_requests_per_second, constraints.max_bandwidth_mbps, constraints.max_concurrency",
    "SCAN_INTENSITY": "technical_policy.scan_intensity",
    "CREDENTIALED_TESTING": "technical_policy.credentialed_testing and technical_policy.credential_references",
    "EXPLOITATION_ALLOWED": "technical_policy.automatic_exploitation and actions.exploit.validation",
    "DENIAL_OF_SERVICE": "technical_policy.denial_of_service and actions.availability.disruption",
    "START_TIME": "authorization.valid_from",
    "END_TIME": "authorization.valid_until",
    "TESTING_WINDOWS": "constraints.testing_windows",
    "TIME_ZONE": "authorization.timezone and constraints.testing_windows.timezone",
    "SOURCE_IPS": "constraints.allowed_source_ips or traffic_identification.source_ip_not_applicable_reason",
    "CUSTOM_HEADERS": "traffic_identification.custom_header",
    "IDS_IPS_BYPASS": "traffic_identification.defense_coordination",
    "PRIMARY_POC": "contacts.primary",
    "EMERGENCY_POC": "contacts.emergency",
    "INCIDENT_RESPONSE_NOTIFICATION": "incident_coordination.soc_notification",
    "BREACH_ESCALATION": "contacts.breach_escalation and incident_coordination.breach_escalation_procedure",
    "SENSITIVE_DATA_POLICY": "data_handling.sensitive_data_policy",
    "OUTPUT_ENCRYPTION": "data_handling.encryption_required and data_handling.encryption_standard",
}


class EngagementError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_datetime(value: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("date-time must include an explicit UTC offset or Z")
    return parsed


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63].strip("-")
    if not slug:
        raise EngagementError("engagement name must contain a letter or number")
    if not SLUG_RE.fullmatch(slug):
        raise EngagementError("unable to produce a safe engagement slug")
    return slug


def has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def terminal_safe(value: Any) -> str:
    return "".join(character if 32 <= ord(character) != 127 else "?" for character in str(value))


def ensure_plain_directory(path: Path, *, create: bool = False) -> Path:
    if not path.is_absolute():
        raise EngagementError(f"path must be absolute: {path}")
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise EngagementError(f"refusing unsafe directory: {path}")
    elif create:
        path.mkdir(mode=DIR_MODE, parents=True, exist_ok=False)
    else:
        raise EngagementError(f"directory does not exist: {path}")
    if path.stat().st_uid != os.geteuid():
        raise EngagementError(f"directory is not owned by the current account: {path}")
    if create:
        os.chmod(path, DIR_MODE)
    return path


def ensure_child_directories(base: Path, names: Iterable[str]) -> None:
    for name in names:
        child = base / name
        if child.exists() or child.is_symlink():
            if child.is_symlink() or not child.is_dir():
                raise EngagementError(f"refusing unsafe engagement path: {child}")
        else:
            child.mkdir(mode=DIR_MODE)
        os.chmod(child, DIR_MODE)


def atomic_write(path: Path, data: bytes, mode: int = FILE_MODE) -> None:
    parent = ensure_plain_directory(path.parent)
    if path.is_symlink():
        raise EngagementError(f"refusing symbolic-link file: {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp.exists():
            tmp.unlink()


def safe_read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EngagementError(f"refusing unsafe or missing file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb", closefd=True) as stream:
            return stream.read()
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def questionnaire_tags() -> set[str]:
    text = safe_read(QUESTIONNAIRE_PATH).decode("utf-8")
    return set(re.findall(r"\*\*([A-Z0-9_]+)\*\*", text))


def questionnaire_fingerprint() -> dict[str, str]:
    return {
        "name": QUESTIONNAIRE_NAME,
        "sha256": sha256_bytes(safe_read(QUESTIONNAIRE_PATH)),
        "answered_at": utc_now(),
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(safe_read(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngagementError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EngagementError(f"expected a JSON object in {path}")
    return value


def read_text(path: Path) -> str:
    return safe_read(path).decode("utf-8").strip()


def current_revision_number(engagement_dir: Path) -> int:
    raw = read_text(engagement_dir / "scope" / "current_revision")
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise EngagementError("invalid current revision pointer")
    return int(raw)


def revision_path(engagement_dir: Path, number: int) -> Path:
    return engagement_dir / "scope" / "revisions" / f"{number:06d}.json"


def load_current_config(engagement_dir: Path) -> tuple[dict[str, Any], int, str]:
    number = current_revision_number(engagement_dir)
    path = revision_path(engagement_dir, number)
    raw = safe_read(path)
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngagementError(f"invalid engagement revision: {exc}") from exc
    if not isinstance(config, dict):
        raise EngagementError("engagement revision is not a JSON object")
    return config, number, sha256_bytes(raw)


def load_state(engagement_dir: Path) -> str:
    state = read_text(engagement_dir / "state")
    if state not in STATES:
        raise EngagementError(f"invalid engagement state: {state}")
    return state


def target_error(target: Any, label: str) -> str | None:
    if not isinstance(target, dict):
        return f"{label} must be an object"
    target_type = target.get("type")
    value = target.get("value")
    if target_type not in TARGET_TYPES:
        return f"{label}.type is not supported"
    if not isinstance(value, str) or not value.strip():
        return f"{label}.value is required"
    value = value.strip()
    try:
        if target_type == "ip":
            ipaddress.ip_address(value)
        elif target_type == "cidr":
            ipaddress.ip_network(value, strict=True)
        elif target_type == "dns":
            candidate = value.encode("idna").decode("ascii")
            if not DNS_RE.fullmatch(candidate):
                raise ValueError("invalid DNS name")
        elif target_type == "wildcard_dns":
            if not value.startswith("*."):
                raise ValueError("wildcard DNS entry must start with *.")
            candidate = value[2:].encode("idna").decode("ascii")
            if not DNS_RE.fullmatch(candidate):
                raise ValueError("invalid wildcard DNS name")
        elif target_type in ("url", "api"):
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("URL/API entry must use http or https and include a host")
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError("URL/API entry must not include userinfo or a fragment")
            _ = parsed.port
    except (ValueError, UnicodeError) as exc:
        return f"{label} is invalid: {exc}"
    return None


def validation_errors(config: dict[str, Any], *, activation: bool = False) -> list[str]:
    errors: list[str] = []
    required_strings = ("engagement_id", "slug", "name", "engagement_type")
    for key in required_strings:
        if not isinstance(config.get(key), str) or not config[key].strip():
            errors.append(f"{key} is required")
        elif has_control_characters(config[key]):
            errors.append(f"{key} contains control characters")
    if config.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    try:
        uuid.UUID(str(config.get("engagement_id", "")))
    except ValueError:
        errors.append("engagement_id must be a UUID")
    if isinstance(config.get("slug"), str) and not SLUG_RE.fullmatch(config["slug"]):
        errors.append("slug is unsafe")
    if config.get("engagement_type") not in (
        "penetration_test", "red_team", "purple_team", "vulnerability_assessment", "retest", "lab"
    ):
        errors.append("engagement_type is not supported")

    questionnaire = config.get("questionnaire")
    if not isinstance(questionnaire, dict):
        errors.append("questionnaire must be an object")
    else:
        if questionnaire.get("name") != QUESTIONNAIRE_NAME:
            errors.append(f"questionnaire.name must be {QUESTIONNAIRE_NAME}")
        if not isinstance(questionnaire.get("sha256"), str) or not SHA256_RE.fullmatch(questionnaire["sha256"]):
            errors.append("questionnaire.sha256 must be a lowercase SHA-256")
        try:
            parse_datetime(questionnaire.get("answered_at", ""))
        except (TypeError, ValueError) as exc:
            errors.append(f"questionnaire.answered_at: {exc}")
        if activation:
            try:
                actual_tags = questionnaire_tags()
                expected_tags = set(QUESTION_TO_CONFIG)
                missing_mappings = actual_tags - expected_tags
                removed_questions = expected_tags - actual_tags
                if missing_mappings:
                    errors.append("questionnaire has unmapped questions: " + ", ".join(sorted(missing_mappings)))
                if removed_questions:
                    errors.append("questionnaire mapping refers to missing questions: " + ", ".join(sorted(removed_questions)))
                actual_hash = sha256_bytes(safe_read(QUESTIONNAIRE_PATH))
                if questionnaire.get("sha256") != actual_hash:
                    errors.append("questionnaire changed after this revision; review every question and create a new revision")
            except (EngagementError, UnicodeDecodeError) as exc:
                errors.append(f"questionnaire baseline is unavailable: {exc}")

    environment = config.get("environment")
    if not isinstance(environment, dict):
        errors.append("environment must be an object")
    else:
        types = environment.get("types")
        valid_types = {"production", "staging", "development", "uat", "lab", "other"}
        if not isinstance(types, list) or not types or set(types) - valid_types or len(types) != len(set(types)):
            errors.append("environment.types must contain one or more supported unique values")
        if environment.get("access_method") not in (
            "public_internet", "vpn", "internal_network", "local_network_drop", "internal_agent", "mixed"
        ):
            errors.append("environment.access_method is invalid")
        if environment.get("access_notes") is not None and not isinstance(environment.get("access_notes"), str):
            errors.append("environment.access_notes must be text or null")
        third_parties = environment.get("third_party_infrastructure")
        if not isinstance(third_parties, list):
            errors.append("environment.third_party_infrastructure must be an array")
        else:
            for index, item in enumerate(third_parties):
                if not isinstance(item, dict) or any(
                    not isinstance(item.get(key), str) or not item[key].strip()
                    for key in ("provider", "service", "written_authorization_reference")
                ):
                    errors.append(
                        f"environment.third_party_infrastructure[{index}] requires provider, service, and written authorization reference"
                    )

    authorization = config.get("authorization")
    if not isinstance(authorization, dict):
        errors.append("authorization must be an object")
    else:
        for key in ("reference", "system_owner", "authorized_by", "valid_from", "valid_until", "timezone"):
            if not isinstance(authorization.get(key), str) or not authorization[key].strip():
                errors.append(f"authorization.{key} is required")
            elif has_control_characters(authorization[key]):
                errors.append(f"authorization.{key} contains control characters")
        if authorization.get("third_party_consent") not in ("not_applicable", "required_pending", "confirmed"):
            errors.append("authorization.third_party_consent is invalid")
        start = end = None
        for key in ("valid_from", "valid_until"):
            if isinstance(authorization.get(key), str):
                try:
                    parsed = parse_datetime(authorization[key])
                    if key == "valid_from":
                        start = parsed
                    else:
                        end = parsed
                except ValueError as exc:
                    errors.append(f"authorization.{key}: {exc}")
        if start and end and start >= end:
            errors.append("authorization.valid_until must be after valid_from")
        evidence = authorization.get("evidence")
        if not isinstance(evidence, dict):
            errors.append("authorization.evidence must be an object")
        else:
            digest = evidence.get("sha256")
            if digest not in (None, "") and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
                errors.append("authorization.evidence.sha256 must be a lowercase SHA-256")
            if activation and (not evidence.get("location") or not digest):
                errors.append("activation requires authorization evidence location and SHA-256")
        if activation and authorization.get("third_party_consent") == "required_pending":
            errors.append("third-party consent is still pending")
        if (
            activation
            and isinstance(environment, dict)
            and environment.get("third_party_infrastructure")
            and authorization.get("third_party_consent") != "confirmed"
        ):
            errors.append("third-party infrastructure requires confirmed written provider consent")

    testers = config.get("testers")
    if not isinstance(testers, list) or not testers:
        errors.append("at least one tester is required")
    else:
        for index, tester in enumerate(testers):
            if not isinstance(tester, dict) or not tester.get("name") or not tester.get("role"):
                errors.append(f"testers[{index}] requires name and role")
    contacts = config.get("contacts")
    if not isinstance(contacts, list) or not contacts:
        errors.append("at least one contact is required")
    else:
        valid_contact_roles = {
            "primary", "technical", "emergency", "breach_escalation", "legal", "report_recipient"
        }
        for index, contact in enumerate(contacts):
            if not isinstance(contact, dict) or not contact.get("name") or not contact.get("method"):
                errors.append(f"contacts[{index}] requires name and method")
            elif contact.get("role") not in valid_contact_roles:
                errors.append(f"contacts[{index}].role is invalid")
        if activation:
            for required_role in ("primary", "emergency", "breach_escalation"):
                if not any(isinstance(item, dict) and item.get("role") == required_role for item in contacts):
                    errors.append(f"activation requires a {required_role.replace('_', ' ')} contact")

    scope = config.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        include = scope.get("include")
        exclude = scope.get("exclude")
        if not isinstance(include, list):
            errors.append("scope.include must be an array")
            include = []
        if not isinstance(exclude, list):
            errors.append("scope.exclude must be an array")
            exclude = []
        if activation and not include:
            errors.append("activation requires at least one in-scope target")
        for collection_name, collection in (("include", include), ("exclude", exclude)):
            for index, target in enumerate(collection):
                error = target_error(target, f"scope.{collection_name}[{index}]")
                if error:
                    errors.append(error)

    actions = config.get("actions")
    if not isinstance(actions, dict):
        errors.append("actions must be an object")
    else:
        sets: dict[str, set[str]] = {}
        for key in ("allow", "confirm_each_run", "deny"):
            values = actions.get(key)
            if not isinstance(values, list):
                errors.append(f"actions.{key} must be an array")
                values = []
            invalid = sorted(set(values) - set(ACTIONS))
            if invalid:
                errors.append(f"actions.{key} contains unsupported values: {', '.join(invalid)}")
            sets[key] = set(values)
            if isinstance(values, list) and len(values) != len(set(values)):
                errors.append(f"actions.{key} contains duplicate values")
        if (sets["allow"] & sets["confirm_each_run"]) or (sets["allow"] & sets["deny"]) or (
            sets["confirm_each_run"] & sets["deny"]
        ):
            errors.append("an action cannot appear in more than one policy list")
        if activation and set(ACTIONS) != sets["allow"] | sets["confirm_each_run"] | sets["deny"]:
            errors.append("activation requires every known action to be explicitly classified")

    technical_policy = config.get("technical_policy")
    if not isinstance(technical_policy, dict):
        errors.append("technical_policy must be an object")
    else:
        if technical_policy.get("scan_intensity") not in (
            "passive_low_impact_only", "standard_non_destructive", "intrusive_explicit", "custom"
        ):
            errors.append("technical_policy.scan_intensity is invalid")
        credentialed = technical_policy.get("credentialed_testing")
        references = technical_policy.get("credential_references")
        if not isinstance(credentialed, bool):
            errors.append("technical_policy.credentialed_testing must be true or false")
        if not isinstance(references, list):
            errors.append("technical_policy.credential_references must be an array")
        else:
            if credentialed is False and references:
                errors.append("credential references must be empty when credentialed testing is disabled")
            if activation and credentialed is True and not references:
                errors.append("credentialed testing requires at least one non-secret account reference")
            for index, reference in enumerate(references):
                if not isinstance(reference, dict) or any(
                    not isinstance(reference.get(key), str) or not reference[key].strip()
                    for key in ("account_identifier", "role", "secret_source")
                ):
                    errors.append(
                        f"technical_policy.credential_references[{index}] requires account identifier, role, and secret source reference"
                    )
        exploitation = technical_policy.get("automatic_exploitation")
        if exploitation not in ("denied_stop_on_flag", "manual_approval_each", "explicitly_allowed"):
            errors.append("technical_policy.automatic_exploitation is invalid")
        denial_of_service = technical_policy.get("denial_of_service")
        if denial_of_service not in ("strictly_forbidden", "lab_only_explicit", "explicitly_allowed"):
            errors.append("technical_policy.denial_of_service is invalid")
        if isinstance(actions, dict):
            if exploitation == "denied_stop_on_flag" and "exploit.validation" not in sets.get("deny", set()):
                errors.append("denied exploitation requires actions.exploit.validation to be denied")
            if exploitation == "manual_approval_each" and "exploit.validation" not in sets.get("confirm_each_run", set()):
                errors.append("manual exploitation approval requires actions.exploit.validation to require confirmation")
            if exploitation == "explicitly_allowed" and "exploit.validation" in sets.get("deny", set()):
                errors.append("allowed exploitation cannot classify actions.exploit.validation as denied")
            if denial_of_service == "strictly_forbidden" and "availability.disruption" not in sets.get("deny", set()):
                errors.append("forbidden denial-of-service testing requires actions.availability.disruption to be denied")
            if denial_of_service == "lab_only_explicit":
                if config.get("engagement_type") != "lab":
                    errors.append("lab-only denial-of-service testing requires a lab engagement")
                if "availability.disruption" not in sets.get("confirm_each_run", set()):
                    errors.append("lab-only denial-of-service testing requires confirmation for every run")
            if denial_of_service == "explicitly_allowed" and "availability.disruption" in sets.get("deny", set()):
                errors.append("allowed denial-of-service testing cannot classify actions.availability.disruption as denied")

    constraints = config.get("constraints")
    if not isinstance(constraints, dict):
        errors.append("constraints must be an object")
    else:
        windows = constraints.get("testing_windows")
        if not isinstance(windows, list):
            errors.append("constraints.testing_windows must be an array")
            windows = []
        if activation and not windows:
            errors.append("activation requires at least one testing window")
        for index, window in enumerate(windows):
            if not isinstance(window, dict):
                errors.append(f"constraints.testing_windows[{index}] must be an object")
                continue
            days = window.get("days")
            if not isinstance(days, list) or not days or set(days) - WEEKDAYS or len(days) != len(set(days)):
                errors.append(f"constraints.testing_windows[{index}].days is invalid")
            if not isinstance(window.get("start"), str) or not TIME_RE.fullmatch(window["start"]):
                errors.append(f"constraints.testing_windows[{index}].start is invalid")
            if not isinstance(window.get("end"), str) or not TIME_RE.fullmatch(window["end"]):
                errors.append(f"constraints.testing_windows[{index}].end is invalid")
            if not isinstance(window.get("timezone"), str) or not window["timezone"].strip():
                errors.append(f"constraints.testing_windows[{index}].timezone is required")
        source_ips = constraints.get("allowed_source_ips")
        if not isinstance(source_ips, list):
            errors.append("constraints.allowed_source_ips must be an array")
        else:
            for index, value in enumerate(source_ips):
                try:
                    ipaddress.ip_network(value, strict=False)
                except (TypeError, ValueError):
                    errors.append(f"constraints.allowed_source_ips[{index}] is invalid")
        ports = constraints.get("ports")
        if not isinstance(ports, list):
            errors.append("constraints.ports must be an array")
        else:
            for rule_index, rule in enumerate(ports):
                if not isinstance(rule, dict) or rule.get("protocol") not in ("tcp", "udp"):
                    errors.append(f"constraints.ports[{rule_index}] has an invalid protocol")
                    continue
                values = rule.get("ports")
                if not isinstance(values, list) or not values:
                    errors.append(f"constraints.ports[{rule_index}].ports must be a non-empty array")
                    continue
                for value_index, value in enumerate(values):
                    try:
                        start_text, separator, end_text = str(value).partition("-")
                        start_port = int(start_text)
                        end_port = int(end_text) if separator else start_port
                        if not 1 <= start_port <= end_port <= 65535:
                            raise ValueError
                    except ValueError:
                        errors.append(f"constraints.ports[{rule_index}].ports[{value_index}] is invalid")
        rate = constraints.get("max_requests_per_second")
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate <= 0:
            errors.append("constraints.max_requests_per_second must be greater than zero")
        bandwidth = constraints.get("max_bandwidth_mbps")
        if bandwidth is not None and (
            not isinstance(bandwidth, (int, float)) or isinstance(bandwidth, bool) or bandwidth <= 0
        ):
            errors.append("constraints.max_bandwidth_mbps must be greater than zero or null")
        concurrency = constraints.get("max_concurrency")
        if not isinstance(concurrency, int) or isinstance(concurrency, bool) or concurrency < 1:
            errors.append("constraints.max_concurrency must be a positive integer")
        if constraints.get("redirect_policy") not in ("deny", "same_host_only", "validate_every_hop"):
            errors.append("constraints.redirect_policy is invalid")
        if constraints.get("dns_policy") not in (
            "hostname_authorized", "ip_authorized", "both_required", "manual_review_on_change"
        ):
            errors.append("constraints.dns_policy is invalid")
        stop_conditions = constraints.get("stop_conditions")
        if not isinstance(stop_conditions, list) or (activation and not stop_conditions):
            errors.append("activation requires at least one stop condition")
        elif any(not isinstance(item, str) or not item.strip() for item in stop_conditions):
            errors.append("constraints.stop_conditions contains an empty or invalid value")

    traffic = config.get("traffic_identification")
    if not isinstance(traffic, dict):
        errors.append("traffic_identification must be an object")
    else:
        reason = traffic.get("source_ip_not_applicable_reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            errors.append("traffic_identification.source_ip_not_applicable_reason must be meaningful text or null")
        if activation and isinstance(constraints, dict) and not constraints.get("allowed_source_ips") and not reason:
            errors.append("activation requires approved source IPs or a documented not-applicable reason")
        header = traffic.get("custom_header")
        if not isinstance(header, dict) or not isinstance(header.get("enabled"), bool):
            errors.append("traffic_identification.custom_header must include an enabled flag")
        else:
            name = header.get("name")
            template = header.get("value_template")
            if header["enabled"] and (
                not isinstance(name, str) or not name.strip() or not isinstance(template, str) or not template.strip()
            ):
                errors.append("enabled custom traffic headers require a name and value template")
            if not header["enabled"] and (name is not None or template is not None):
                errors.append("disabled custom traffic headers must use null name and value template")
        if traffic.get("defense_coordination") not in (
            "client_whitelist", "monitor_only", "unchanged", "covert_authorized_no_evasion_automation"
        ):
            errors.append("traffic_identification.defense_coordination is invalid")

    incident = config.get("incident_coordination")
    if not isinstance(incident, dict):
        errors.append("incident_coordination must be an object")
    else:
        if incident.get("soc_notification") not in (
            "notified", "limited_notice", "not_notified_with_authorization", "not_applicable"
        ):
            errors.append("incident_coordination.soc_notification is invalid")
        procedure = incident.get("breach_escalation_procedure")
        if not isinstance(procedure, str) or not procedure.strip():
            errors.append("incident_coordination.breach_escalation_procedure is required")

    data_handling = config.get("data_handling")
    if not isinstance(data_handling, dict):
        errors.append("data_handling must be an object")
    else:
        if data_handling.get("classification") not in ("public", "internal", "confidential", "restricted"):
            errors.append("data_handling.classification is invalid")
        retention = data_handling.get("retention_days")
        if not isinstance(retention, int) or isinstance(retention, bool) or retention < 0:
            errors.append("data_handling.retention_days must be a non-negative integer")
        if data_handling.get("out_of_scope_storage") not in ("none", "minimal_fingerprint", "approved_quarantine"):
            errors.append("data_handling.out_of_scope_storage is invalid")
        if data_handling.get("secret_storage") not in ("redact", "encrypted_only", "prohibited"):
            errors.append("data_handling.secret_storage is invalid")
        sensitive_policy = data_handling.get("sensitive_data_policy")
        valid_sensitive_actions = {"mask_and_continue", "stop_and_notify", "encrypted_capture_authorized", "prohibited"}
        if not isinstance(sensitive_policy, dict):
            errors.append("data_handling.sensitive_data_policy must be an object")
        else:
            for category in ("pii", "pci", "phi"):
                if sensitive_policy.get(category) not in valid_sensitive_actions:
                    errors.append(f"data_handling.sensitive_data_policy.{category} is invalid")
        for key in ("encryption_required", "cleanup_required"):
            if not isinstance(data_handling.get(key), bool):
                errors.append(f"data_handling.{key} must be true or false")
        encryption_standard = data_handling.get("encryption_standard")
        if not isinstance(encryption_standard, str) or not encryption_standard.strip():
            errors.append("data_handling.encryption_standard is required")
    reporting = config.get("reporting")
    if not isinstance(reporting, dict):
        errors.append("reporting must be an object")
    else:
        if not isinstance(reporting.get("format"), str) or not reporting["format"].strip():
            errors.append("reporting.format is required")
        if not isinstance(reporting.get("delivery_method"), str) or not reporting["delivery_method"].strip():
            errors.append("reporting.delivery_method is required")
        deadline = reporting.get("critical_finding_deadline_minutes")
        if not isinstance(deadline, int) or isinstance(deadline, bool) or deadline < 0:
            errors.append("reporting.critical_finding_deadline_minutes must be a non-negative integer")
    return errors


def assert_private_engagement_tree(engagement_dir: Path) -> None:
    paths = [engagement_dir]
    paths.extend(engagement_dir / name for name in DATA_DIRS)
    paths.extend((engagement_dir / "scope", engagement_dir / "scope" / "revisions"))
    for path in paths:
        if path.is_symlink() or not path.is_dir():
            raise EngagementError(f"unsafe or missing engagement directory: {path}")
        metadata = path.stat()
        if metadata.st_uid != os.geteuid() or stat_mode(metadata.st_mode) & 0o077:
            raise EngagementError(f"engagement directory ownership or mode is unsafe: {path}")
    revision = current_revision_number(engagement_dir)
    critical_files = (
        engagement_dir / "engagement.json",
        engagement_dir / "state",
        engagement_dir / "scope" / "current_revision",
        revision_path(engagement_dir, revision),
        engagement_dir / "Audit" / "events.jsonl",
    )
    for path in critical_files:
        if path.is_symlink() or not path.is_file():
            raise EngagementError(f"unsafe or missing engagement file: {path}")
        metadata = path.stat()
        if metadata.st_uid != os.geteuid() or stat_mode(metadata.st_mode) & 0o077:
            raise EngagementError(f"engagement file ownership or mode is unsafe: {path}")


def stat_mode(value: int) -> int:
    return value & 0o7777


def engagement_candidates(root: Path) -> list[Path]:
    root = ensure_plain_directory(root, create=True)
    candidates: list[Path] = []
    for child in sorted(root.iterdir(), key=lambda value: value.name):
        if child.name.startswith(".") or child.is_symlink() or not child.is_dir():
            continue
        if (child / "engagement.json").is_file() and not (child / "engagement.json").is_symlink():
            candidates.append(child)
    return candidates


def resolve_engagement(root: Path, identifier: str) -> Path:
    if not identifier or any(char in identifier for char in ("/", "\\", "\0")) or identifier in (".", ".."):
        raise EngagementError("unsafe engagement identifier")
    matches: list[Path] = []
    for candidate in engagement_candidates(root):
        summary = read_json(candidate / "engagement.json")
        if identifier in (candidate.name, summary.get("engagement_id"), summary.get("slug")):
            matches.append(candidate)
    if not matches:
        raise EngagementError(f"engagement not found: {identifier}")
    if len(matches) > 1:
        raise EngagementError(f"engagement identifier is ambiguous: {identifier}")
    return ensure_plain_directory(matches[0])


def append_audit(engagement_dir: Path, event: str, details: dict[str, Any] | None = None) -> None:
    audit_dir = engagement_dir / "Audit"
    ensure_plain_directory(audit_dir)
    path = audit_dir / "events.jsonl"
    if path.is_symlink():
        raise EngagementError("refusing symbolic-link audit log")
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, FILE_MODE)
    try:
        os.fchmod(fd, FILE_MODE)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(fd, "r+", encoding="utf-8", closefd=False) as stream:
            stream.seek(0)
            previous_hash = None
            for line in stream:
                if line.strip():
                    try:
                        previous_hash = json.loads(line).get("event_sha256")
                    except json.JSONDecodeError as exc:
                        raise EngagementError("audit log contains invalid JSON") from exc
            config, revision, scope_hash = load_current_config(engagement_dir)
            record = {
                "timestamp": utc_now(),
                "event": event,
                "engagement_id": config["engagement_id"],
                "revision": revision,
                "scope_sha256": scope_hash,
                "previous_event_sha256": previous_hash,
                "details": details or {},
            }
            record["event_sha256"] = sha256_bytes(canonical_json_bytes(record))
            stream.seek(0, os.SEEK_END)
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def refresh_summary(engagement_dir: Path) -> dict[str, Any]:
    config, revision, scope_hash = load_current_config(engagement_dir)
    state = load_state(engagement_dir)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": config["engagement_id"],
        "slug": config["slug"],
        "name": config["name"],
        "client": config.get("client"),
        "engagement_type": config.get("engagement_type"),
        "state": state,
        "revision": revision,
        "scope_sha256": scope_hash,
        "valid_from": config.get("authorization", {}).get("valid_from"),
        "valid_until": config.get("authorization", {}).get("valid_until"),
        "updated_at": utc_now(),
    }
    atomic_write(engagement_dir / "engagement.json", canonical_json_bytes(summary))
    return summary


def prepare_new_config(source: dict[str, Any]) -> dict[str, Any]:
    config = copy.deepcopy(source)
    engagement_id = str(uuid.uuid4())
    slug = normalize_slug(str(config.get("slug") or config.get("name") or ""))
    config["schema_version"] = SCHEMA_VERSION
    config["engagement_id"] = engagement_id
    config["slug"] = slug
    config["status"] = "draft"
    config["questionnaire"] = questionnaire_fingerprint()
    config["revision"] = {
        "number": 1,
        "created_at": utc_now(),
        "created_by": str(config.get("revision", {}).get("created_by") or os.environ.get("USER") or "unknown"),
        "change_reason": "Initial draft",
        "previous_sha256": None,
    }
    return config


def create_engagement(root: Path, source: dict[str, Any]) -> Path:
    root = ensure_plain_directory(root, create=True)
    config = prepare_new_config(source)
    errors = validation_errors(config, activation=False)
    if errors:
        raise EngagementError("invalid engagement draft:\n- " + "\n- ".join(errors))
    short_id = config["engagement_id"].split("-")[0]
    final_dir = root / f"{config['slug']}--{short_id}"
    temp_dir = root / f".creating-{config['engagement_id']}"
    if final_dir.exists() or temp_dir.exists() or final_dir.is_symlink() or temp_dir.is_symlink():
        raise EngagementError("engagement destination already exists")
    temp_dir.mkdir(mode=DIR_MODE)
    try:
        ensure_child_directories(temp_dir, DATA_DIRS + ("scope",))
        ensure_child_directories(temp_dir / "scope", ("revisions",))
        revision_data = canonical_json_bytes(config)
        atomic_write(revision_path(temp_dir, 1), revision_data)
        atomic_write(temp_dir / "scope" / "current_revision", b"1\n")
        atomic_write(temp_dir / "state", b"draft\n")
        refresh_summary(temp_dir)
        append_audit(temp_dir, "engagement_created", {"state": "draft"})
        os.replace(temp_dir, final_dir)
        dir_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        if temp_dir.exists():
            for current_root, directories, files in os.walk(temp_dir, topdown=False):
                for filename in files:
                    Path(current_root, filename).unlink()
                for dirname in directories:
                    Path(current_root, dirname).rmdir()
            temp_dir.rmdir()
        raise
    return final_dir


def revise_engagement(root: Path, identifier: str, source: dict[str, Any]) -> Path:
    engagement_dir = resolve_engagement(root, identifier)
    state = load_state(engagement_dir)
    if state not in ("draft", "ready", "paused"):
        raise EngagementError("pause or reopen the engagement before creating a new revision")
    current, number, previous_hash = load_current_config(engagement_dir)
    config = copy.deepcopy(source)
    config["schema_version"] = SCHEMA_VERSION
    config["engagement_id"] = current["engagement_id"]
    config["slug"] = current["slug"]
    config["status"] = "draft"
    config["questionnaire"] = questionnaire_fingerprint()
    config["revision"] = {
        "number": number + 1,
        "created_at": utc_now(),
        "created_by": str(config.get("revision", {}).get("created_by") or os.environ.get("USER") or "unknown"),
        "change_reason": str(config.get("revision", {}).get("change_reason") or "Revised engagement"),
        "previous_sha256": previous_hash,
    }
    errors = validation_errors(config, activation=False)
    if errors:
        raise EngagementError("invalid engagement revision:\n- " + "\n- ".join(errors))
    path = revision_path(engagement_dir, number + 1)
    if path.exists() or path.is_symlink():
        raise EngagementError("next revision file already exists")
    atomic_write(path, canonical_json_bytes(config))
    atomic_write(engagement_dir / "scope" / "current_revision", f"{number + 1}\n".encode())
    atomic_write(engagement_dir / "state", b"draft\n")
    refresh_summary(engagement_dir)
    append_audit(engagement_dir, "engagement_revised", {"previous_revision": number, "state": "draft"})
    return path


def authorization_current(config: dict[str, Any]) -> bool:
    authorization = config["authorization"]
    now = dt.datetime.now(dt.timezone.utc)
    return parse_datetime(authorization["valid_from"]).astimezone(dt.timezone.utc) <= now <= parse_datetime(
        authorization["valid_until"]
    ).astimezone(dt.timezone.utc)


TRANSITIONS = {
    "draft": {"ready", "closed"},
    "ready": {"active", "closed"},
    "active": {"paused", "closed"},
    "paused": {"active", "closed"},
    "closed": {"archived"},
    "archived": set(),
}


def transition(root: Path, identifier: str, target_state: str) -> dict[str, Any]:
    engagement_dir = resolve_engagement(root, identifier)
    current_state = load_state(engagement_dir)
    if target_state not in TRANSITIONS[current_state]:
        raise EngagementError(f"invalid transition: {current_state} -> {target_state}")
    config, _, _ = load_current_config(engagement_dir)
    if target_state in ("ready", "active"):
        errors = validation_errors(config, activation=True)
        if errors:
            raise EngagementError("engagement is not activation-ready:\n- " + "\n- ".join(errors))
    if target_state == "active" and not authorization_current(config):
        raise EngagementError("authorization is not currently valid")
    atomic_write(engagement_dir / "state", f"{target_state}\n".encode())
    summary = refresh_summary(engagement_dir)
    append_audit(engagement_dir, "state_changed", {"from": current_state, "to": target_state})
    return summary


def selection_values(root: Path, identifier: str) -> dict[str, str]:
    engagement_dir = resolve_engagement(root, identifier)
    assert_private_engagement_tree(engagement_dir)
    state = load_state(engagement_dir)
    if state != "active":
        raise EngagementError(f"engagement must be active, not {state}")
    config, revision, scope_hash = load_current_config(engagement_dir)
    errors = validation_errors(config, activation=True)
    if errors:
        raise EngagementError("active engagement is invalid:\n- " + "\n- ".join(errors))
    if not authorization_current(config):
        raise EngagementError("authorization is not currently valid")
    ensure_child_directories(engagement_dir, DATA_DIRS)
    session_id = str(uuid.uuid4())
    values = {
        "CSTK_ENGAGEMENT_ID": config["engagement_id"],
        "CSTK_ENGAGEMENT_SLUG": config["slug"],
        "CSTK_ENGAGEMENT_DIR": str(engagement_dir),
        "CSTK_ENGAGEMENT_STATE": state,
        "CSTK_SCOPE_REVISION": str(revision),
        "CSTK_SCOPE_SHA256": scope_hash,
        "CSTK_SESSION_ID": session_id,
        "CSTK_LOOT_DIR": str(engagement_dir / "Loot"),
        "CSTK_MALWARE_DIR": str(engagement_dir / "Malware"),
        "CSTK_LOG_DIR": str(engagement_dir / "Logs"),
        "CSTK_EVIDENCE_DIR": str(engagement_dir / "Evidence"),
        "CSTK_REPORT_DIR": str(engagement_dir / "Reports"),
        "CSTK_AUDIT_DIR": str(engagement_dir / "Audit"),
        "CSTK_RUNS_DIR": str(engagement_dir / "Runs"),
        "CSTK_TEMP_DIR": str(engagement_dir / "Temp"),
    }
    append_audit(engagement_dir, "session_selected", {"session_id": session_id})
    return values


def _dns_matches(host: str, scope_type: str, scope_value: str) -> bool:
    host = host.rstrip(".").lower()
    scope_value = scope_value.rstrip(".").lower()
    if scope_type == "dns":
        return host == scope_value
    if scope_type == "wildcard_dns":
        suffix = scope_value[1:].lower()
        return host.endswith(suffix) and host != suffix[1:]
    return False


def _url_matches(candidate: urllib.parse.SplitResult, scope_value: str) -> bool:
    allowed = urllib.parse.urlsplit(scope_value)
    candidate_port = candidate.port or (443 if candidate.scheme == "https" else 80)
    allowed_port = allowed.port or (443 if allowed.scheme == "https" else 80)
    if candidate.scheme.lower() != allowed.scheme.lower() or candidate.hostname != allowed.hostname:
        return False
    if candidate_port != allowed_port:
        return False
    allowed_path = allowed.path or "/"
    candidate_path = candidate.path or "/"
    if not allowed_path.endswith("/"):
        return candidate_path == allowed_path
    return candidate_path.startswith(allowed_path)


def _target_matches_entry(target: str, entry: dict[str, Any]) -> bool:
    entry_type = entry.get("type")
    entry_value = str(entry.get("value", "")).strip()
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        if entry_type in ("url", "api"):
            return _url_matches(parsed, entry_value)
        if entry_type in ("dns", "wildcard_dns"):
            return _dns_matches(parsed.hostname, entry_type, entry_value)
        try:
            candidate_ip = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            return False
        if entry_type == "ip":
            return candidate_ip == ipaddress.ip_address(entry_value)
        if entry_type == "cidr":
            return candidate_ip in ipaddress.ip_network(entry_value)
        return False
    try:
        candidate_ip = ipaddress.ip_address(target)
    except ValueError:
        if entry_type in ("dns", "wildcard_dns"):
            return _dns_matches(target, entry_type, entry_value)
        return False
    if entry_type == "ip":
        return candidate_ip == ipaddress.ip_address(entry_value)
    if entry_type == "cidr":
        return candidate_ip in ipaddress.ip_network(entry_value)
    return False


def _target_allowed(config: dict[str, Any], target: str) -> tuple[bool, str]:
    scope = config["scope"]
    if any(_target_matches_entry(target, entry) for entry in scope["exclude"]):
        return False, "target matches an explicit scope exclusion"
    if not any(_target_matches_entry(target, entry) for entry in scope["include"]):
        return False, "target does not match an in-scope entry"
    return True, "target is included and not excluded"


def _ip_in_scope(config: dict[str, Any], value: str) -> bool:
    try:
        candidate = ipaddress.ip_address(value)
    except ValueError:
        return False
    scope = config["scope"]
    for entry in scope["exclude"]:
        if entry.get("type") in ("ip", "cidr") and _target_matches_entry(str(candidate), entry):
            return False
    return any(
        entry.get("type") in ("ip", "cidr") and _target_matches_entry(str(candidate), entry)
        for entry in scope["include"]
    )


def _port_allowed(config: dict[str, Any], protocol: str, port: int) -> bool:
    for rule in config["constraints"]["ports"]:
        if rule.get("protocol") != protocol:
            continue
        for value in rule.get("ports", []):
            text = str(value)
            if "-" in text:
                first, last = (int(part) for part in text.split("-", 1))
                if first <= port <= last:
                    return True
            elif int(text) == port:
                return True
    return False


def _source_allowed(config: dict[str, Any], source_ip: str | None) -> bool:
    allowed = config["constraints"].get("allowed_source_ips", [])
    if not allowed:
        return True
    if not source_ip:
        return False
    try:
        candidate = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    for value in allowed:
        try:
            if candidate == ipaddress.ip_address(value):
                return True
        except ValueError:
            if candidate in ipaddress.ip_network(value, strict=False):
                return True
    return False


def _inside_testing_window(config: dict[str, Any], now: dt.datetime) -> bool:
    windows = config["constraints"].get("testing_windows", [])
    if not windows:
        return True
    weekday = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    for window in windows:
        try:
            local = now.astimezone(ZoneInfo(window["timezone"]))
        except (KeyError, ZoneInfoNotFoundError):
            continue
        if weekday[local.weekday()] not in window["days"]:
            continue
        start = dt.time.fromisoformat(window["start"])
        end = dt.time.fromisoformat(window["end"])
        current = local.time().replace(tzinfo=None)
        if start <= end and start <= current <= end:
            return True
        if start > end and (current >= start or current <= end):
            return True
    return False


def authorize_action(
    root: Path,
    identifier: str,
    *,
    action: str,
    target: str,
    resolved_ips: Iterable[str] = (),
    protocol: str | None = None,
    port: int | None = None,
    source_ip: str | None = None,
    confirmed_by: str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    engagement_dir = resolve_engagement(root, identifier)
    config, revision, digest = load_current_config(engagement_dir)
    reasons: list[str] = []
    state = load_state(engagement_dir)
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise EngagementError("authorization time must include a timezone")
    if state != "active":
        reasons.append("engagement is not active")
    if not authorization_current(config):
        reasons.append("authorization dates are not currently valid")
    if not _inside_testing_window(config, current):
        reasons.append("current time is outside every approved testing window")
    if action not in ACTIONS:
        reasons.append("action is not a recognized CSTK action")
    elif action in config["actions"]["deny"]:
        reasons.append("action is explicitly denied")
    elif action in config["actions"]["confirm_each_run"] and not confirmed_by:
        reasons.append("action requires fresh per-run confirmation")
    elif action not in config["actions"]["allow"] and action not in config["actions"]["confirm_each_run"]:
        reasons.append("action is not authorized")
    target_ok, target_reason = _target_allowed(config, target)
    if not target_ok:
        reasons.append(target_reason)
    parsed = urllib.parse.urlsplit(target)
    hostname_target = bool(parsed.hostname and not re.fullmatch(r"[0-9a-fA-F:.]+", parsed.hostname)) or (
        not parsed.scheme and not re.fullmatch(r"[0-9a-fA-F:.]+", target)
    )
    resolved = list(dict.fromkeys(resolved_ips))
    if hostname_target and config["constraints"].get("dns_policy") == "both_required":
        if not resolved:
            reasons.append("DNS policy requires at least one resolved IP")
        elif any(not _ip_in_scope(config, value) for value in resolved):
            reasons.append("one or more resolved IPs are not explicitly in scope or are excluded")
    if (protocol is None) != (port is None):
        reasons.append("protocol and port must be supplied together")
    elif protocol is not None and port is not None:
        if protocol not in ("tcp", "udp") or not 1 <= port <= 65535:
            reasons.append("protocol or port is invalid")
        elif not _port_allowed(config, protocol, port):
            reasons.append("protocol and port are outside the approved constraints")
    if not _source_allowed(config, source_ip):
        reasons.append("source IP is missing or not approved")
    allowed = not reasons
    decision = {
        "allowed": allowed,
        "action": action,
        "target": target,
        "resolved_ips": resolved,
        "protocol": protocol,
        "port": port,
        "source_ip": source_ip,
        "confirmed_by": confirmed_by,
        "engagement_id": config["engagement_id"],
        "engagement_slug": config["slug"],
        "scope_revision": revision,
        "scope_sha256": digest,
        "decided_at": current.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "reasons": reasons or [target_reason, "action and operational constraints are authorized"],
    }
    append_audit(engagement_dir, "action_authorized" if allowed else "action_denied", decision)
    return decision


def prompt(label: str, *, required: bool = True, default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("A value is required.")


def choice(label: str, values: tuple[str, ...], default: str | None = None) -> str:
    rendered = "/".join(values)
    while True:
        value = prompt(f"{label} ({rendered})", default=default).lower()
        if value in values:
            return value
        print("Choose one of the displayed values.")


def yes_no(label: str, default: bool = True) -> bool:
    rendered = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{rendered}]: ").strip().lower()
        if not value:
            return default
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False


def comma_values(label: str) -> list[str]:
    value = prompt(label, required=False)
    return [item.strip() for item in value.split(",") if item.strip()]


def collect_targets(label: str, *, require_one: bool) -> list[dict[str, Any]]:
    print(f"\n{label}")
    print("Types: " + ", ".join(TARGET_TYPES))
    targets: list[dict[str, Any]] = []
    while True:
        target_type = prompt("Target type (blank to finish)", required=False).lower()
        if not target_type:
            if targets or not require_one:
                return targets
            print("At least one in-scope target is required for an activation-ready draft.")
            if not yes_no("Add one now", True):
                return targets
            continue
        if target_type not in TARGET_TYPES:
            print("Unsupported target type.")
            continue
        value = prompt("Target value")
        note = prompt("Note", required=False)
        target = {"type": target_type, "value": value, "note": note or None}
        error = target_error(target, "target")
        if error:
            print(error)
            continue
        targets.append(target)


def collect_actions() -> dict[str, list[str]]:
    print("\nAction policy")
    for index, action in enumerate(ACTIONS, start=1):
        print(f"{index:2d} - {action}")

    def select_numbers(label: str) -> set[str]:
        while True:
            raw = prompt(label, required=False)
            if not raw:
                return set()
            try:
                indexes = {int(value.strip()) for value in raw.split(",") if value.strip()}
            except ValueError:
                print("Use comma-separated numbers.")
                continue
            if any(index < 1 or index > len(ACTIONS) for index in indexes):
                print("One or more action numbers are outside the displayed range.")
                continue
            return {ACTIONS[index - 1] for index in indexes}

    allowed = select_numbers("Allowed action numbers")
    confirmed = select_numbers("Confirm-each-run action numbers")
    overlap = allowed & confirmed
    if overlap:
        raise EngagementError("actions selected in both allow and confirm: " + ", ".join(sorted(overlap)))
    denied = set(ACTIONS) - allowed - confirmed
    return {
        "allow": sorted(allowed),
        "confirm_each_run": sorted(confirmed),
        "deny": sorted(denied),
    }


def interactive_config() -> dict[str, Any]:
    print("CSTK engagement creation wizard")
    print(f"Every mandatory question in {QUESTIONNAIRE_NAME} is asked below.")
    print("The engagement is saved as a draft. Activation is a separate reviewed step.\n")
    name = prompt("Engagement name")
    client = prompt("Client/system owner name", required=False)
    engagement_type = choice(
        "Engagement type",
        ("penetration_test", "red_team", "purple_team", "vulnerability_assessment", "retest", "lab"),
        "penetration_test",
    )
    tester_name = prompt("Lead tester name")
    tester_role = prompt("Lead tester role", default="lead tester")
    authorization_reference = prompt("Authorization/SOW/ROE reference")
    system_owner = prompt("System owner")
    authorized_by = prompt("Authorizing person and role")
    valid_from = prompt("Authorization starts (ISO 8601 with offset)")
    valid_until = prompt("Authorization ends (ISO 8601 with offset)")
    timezone = prompt("Engagement time zone", default="UTC")
    third_party = choice(
        "Third-party consent",
        ("not_applicable", "required_pending", "confirmed"),
        "not_applicable",
    )
    environment_types: list[str] = []
    valid_environment_types = ("production", "staging", "development", "uat", "lab", "other")
    while not environment_types:
        environment_types = comma_values("Environment types (production,staging,development,uat,lab,other)")
        if not environment_types or set(environment_types) - set(valid_environment_types):
            print("Enter one or more displayed environment types.")
            environment_types = []
    access_method = choice(
        "Tester access/hosting location",
        ("public_internet", "vpn", "internal_network", "local_network_drop", "internal_agent", "mixed"),
        "public_internet",
    )
    access_notes = prompt("Access/hosting location details", required=False)
    third_party_infrastructure: list[dict[str, str]] = []
    if yes_no("Does scope include third-party hosted infrastructure", False):
        print("Record only providers covered by written authorization. Never paste credentials or secrets.")
        while True:
            third_party_infrastructure.append(
                {
                    "provider": prompt("Third-party provider"),
                    "service": prompt("Third-party service/account/tenant"),
                    "written_authorization_reference": prompt("Written provider authorization reference"),
                }
            )
            if not yes_no("Add another third-party provider", False):
                break
    evidence_location = prompt("Authorization evidence location/reference", required=False)
    evidence_sha256 = prompt("Authorization evidence SHA-256", required=False).lower() or None
    primary_name = prompt("Primary point-of-contact name and title")
    primary_method = prompt("Primary point-of-contact method")
    technical_name = prompt("Technical contact name")
    technical_method = prompt("Technical contact method")
    emergency_name = prompt("Emergency/stop contact name")
    emergency_method = prompt("Emergency/stop contact method")
    breach_name = prompt("Breach-escalation contact name and title")
    breach_method = prompt("Breach-escalation contact method")
    soc_notification = choice(
        "SOC/incident-response notification",
        ("notified", "limited_notice", "not_notified_with_authorization", "not_applicable"),
        "notified",
    )
    breach_procedure = prompt("Breach discovery escalation procedure")
    include = collect_targets("In-scope targets", require_one=True)
    exclude = collect_targets("Explicit exclusions", require_one=False)
    scan_intensity = choice(
        "Scan intensity",
        ("passive_low_impact_only", "standard_non_destructive", "intrusive_explicit", "custom"),
        "standard_non_destructive",
    )
    credentialed_testing = yes_no("Is credentialed testing authorized", False)
    credential_references: list[dict[str, str]] = []
    if credentialed_testing:
        print("Enter account identifiers and an approved secret source reference only. Never enter a password, token, or key.")
        while True:
            credential_references.append(
                {
                    "account_identifier": prompt("Test account identifier"),
                    "role": prompt("Test account role"),
                    "secret_source": prompt("Approved secret source/reference (not the secret)"),
                }
            )
            if not yes_no("Add another credentialed test account", False):
                break
    automatic_exploitation = choice(
        "Automated exploitation policy",
        ("denied_stop_on_flag", "manual_approval_each", "explicitly_allowed"),
        "denied_stop_on_flag",
    )
    denial_of_service = choice(
        "Denial-of-service policy",
        ("strictly_forbidden", "lab_only_explicit", "explicitly_allowed"),
        "strictly_forbidden",
    )
    actions = collect_actions()
    for policy in actions.values():
        while automatic_exploitation == "denied_stop_on_flag" and "exploit.validation" in policy:
            policy.remove("exploit.validation")
        while denial_of_service == "strictly_forbidden" and "availability.disruption" in policy:
            policy.remove("availability.disruption")
    if automatic_exploitation == "denied_stop_on_flag":
        actions["deny"].append("exploit.validation")
    elif automatic_exploitation == "manual_approval_each":
        actions["confirm_each_run"].append("exploit.validation")
    if denial_of_service == "strictly_forbidden":
        actions["deny"].append("availability.disruption")
    for policy in actions.values():
        policy.sort()
    days = comma_values("Testing days (mon,tue,wed,thu,fri,sat,sun)") or ["mon", "tue", "wed", "thu", "fri"]
    window_start = prompt("Daily start time (HH:MM)", default="08:00")
    window_end = prompt("Daily end time (HH:MM)", default="18:00")
    source_ips = comma_values("Approved source IPs/CIDRs (comma separated; blank if none specified)")
    source_ip_reason = None if source_ips else prompt("Why source IP identification is not applicable")
    use_custom_header = yes_no("Use a custom HTTP header to identify testing traffic", False)
    custom_header = {
        "enabled": use_custom_header,
        "name": prompt("Custom header name") if use_custom_header else None,
        "value_template": prompt("Custom header value template") if use_custom_header else None,
    }
    print("Defense coordination records the approved client arrangement; CSTK does not automate bypass or evasion.")
    defense_coordination = choice(
        "Firewall/WAF/IDS/IPS coordination",
        ("client_whitelist", "monitor_only", "unchanged", "covert_authorized_no_evasion_automation"),
        "monitor_only",
    )
    port_values = comma_values("TCP ports/ranges (comma separated; blank if all contract-approved ports)")
    max_rate = float(prompt("Maximum requests per second", default="5"))
    bandwidth_text = prompt("Maximum bandwidth in Mbps (blank if not specified)", required=False)
    max_bandwidth = float(bandwidth_text) if bandwidth_text else None
    max_concurrency = int(prompt("Maximum concurrency", default="4"))
    redirect_policy = choice("Redirect policy", ("deny", "same_host_only", "validate_every_hop"), "deny")
    dns_policy = choice(
        "DNS policy",
        ("hostname_authorized", "ip_authorized", "both_required", "manual_review_on_change"),
        "both_required",
    )
    stop_conditions = comma_values("Stop conditions (comma separated)")
    if not stop_conditions:
        stop_conditions = [
            "Unexpected service instability or availability impact",
            "A target cannot be positively matched to approved scope",
            "The system owner or emergency contact requests a stop",
        ]
    classification = choice("Data classification", ("public", "internal", "confidential", "restricted"), "confidential")
    retention_days = int(prompt("Retention days", default="30"))
    out_of_scope_storage = choice(
        "Out-of-scope storage",
        ("none", "minimal_fingerprint", "approved_quarantine"),
        "minimal_fingerprint",
    )
    secret_storage = choice("Secret storage", ("redact", "encrypted_only", "prohibited"), "redact")
    sensitive_actions = ("mask_and_continue", "stop_and_notify", "encrypted_capture_authorized", "prohibited")
    sensitive_data_policy = {
        "pii": choice("PII handling", sensitive_actions, "stop_and_notify"),
        "pci": choice("PCI/card-data handling", sensitive_actions, "stop_and_notify"),
        "phi": choice("PHI/health-data handling", sensitive_actions, "stop_and_notify"),
    }
    encryption_required = yes_no("Require encryption for stored/exported engagement data", True)
    encryption_standard = prompt("Approved output encryption standard/method")
    report_format = prompt("Report format", default="PDF plus encrypted evidence archive")
    delivery_method = prompt("Approved report delivery method")
    critical_deadline = int(prompt("Critical-finding notification deadline in minutes", default="60"))
    red_team: dict[str, Any] | None = None
    if engagement_type in ("red_team", "purple_team"):
        red_team = {
            "objectives": comma_values("Red-team objectives (comma separated)"),
            "assumed_breach": yes_no("Assumed-breach start", False),
            "deconfliction_contact": prompt("White-cell/deconfliction contact"),
            "notification_mode": choice(
                "Notification mode", ("announced", "limited_notice", "unannounced_with_white_cell"), "limited_notice"
            ),
            "cleanup_validation_required": yes_no("Require cleanup validation", True),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "slug": normalize_slug(name),
        "name": name,
        "client": client or None,
        "engagement_type": engagement_type,
        "status": "draft",
        "revision": {"created_by": tester_name},
        "authorization": {
            "reference": authorization_reference,
            "system_owner": system_owner,
            "authorized_by": authorized_by,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "timezone": timezone,
            "third_party_consent": third_party,
            "evidence": {"location": evidence_location or None, "sha256": evidence_sha256},
        },
        "environment": {
            "types": environment_types,
            "access_method": access_method,
            "access_notes": access_notes or None,
            "third_party_infrastructure": third_party_infrastructure,
        },
        "testers": [{"name": tester_name, "role": tester_role}],
        "contacts": [
            {"name": primary_name, "role": "primary", "method": primary_method},
            {"name": technical_name, "role": "technical", "method": technical_method},
            {"name": emergency_name, "role": "emergency", "method": emergency_method},
            {"name": breach_name, "role": "breach_escalation", "method": breach_method},
        ],
        "scope": {"include": include, "exclude": exclude},
        "actions": actions,
        "technical_policy": {
            "scan_intensity": scan_intensity,
            "credentialed_testing": credentialed_testing,
            "credential_references": credential_references,
            "automatic_exploitation": automatic_exploitation,
            "denial_of_service": denial_of_service,
        },
        "constraints": {
            "testing_windows": [{"days": days, "start": window_start, "end": window_end, "timezone": timezone}],
            "allowed_source_ips": source_ips,
            "ports": [{"protocol": "tcp", "ports": port_values}] if port_values else [],
            "max_requests_per_second": max_rate,
            "max_bandwidth_mbps": max_bandwidth,
            "max_concurrency": max_concurrency,
            "redirect_policy": redirect_policy,
            "dns_policy": dns_policy,
            "stop_conditions": stop_conditions,
        },
        "traffic_identification": {
            "source_ip_not_applicable_reason": source_ip_reason,
            "custom_header": custom_header,
            "defense_coordination": defense_coordination,
        },
        "incident_coordination": {
            "soc_notification": soc_notification,
            "breach_escalation_procedure": breach_procedure,
        },
        "data_handling": {
            "classification": classification,
            "retention_days": retention_days,
            "out_of_scope_storage": out_of_scope_storage,
            "secret_storage": secret_storage,
            "sensitive_data_policy": sensitive_data_policy,
            "encryption_required": encryption_required,
            "encryption_standard": encryption_standard,
            "cleanup_required": yes_no("Require cleanup confirmation", True),
        },
        "reporting": {
            "format": report_format,
            "delivery_method": delivery_method,
            "critical_finding_deadline_minutes": critical_deadline,
        },
        "red_team": red_team,
        "notes": prompt("Notes", required=False) or None,
    }


def print_summary_table(root: Path) -> None:
    rows: list[dict[str, Any]] = []
    for candidate in engagement_candidates(root):
        try:
            rows.append(refresh_summary(candidate))
        except EngagementError as exc:
            rows.append({"slug": candidate.name, "state": "INVALID", "name": str(exc), "revision": "-", "scope_sha256": "-"})
    if not rows:
        print("No engagements found.")
        return
    print(f"{'SLUG':30} {'STATE':9} {'REV':>4} {'SCOPE':12} NAME")
    for row in rows:
        print(
            f"{terminal_safe(row.get('slug', ''))[:30]:30} {terminal_safe(row.get('state', ''))[:9]:9} "
            f"{terminal_safe(row.get('revision', '-')):>4} {terminal_safe(row.get('scope_sha256', '-'))[:12]:12} "
            f"{terminal_safe(row.get('name', ''))}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="absolute engagements directory")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create a draft engagement")
    create.add_argument("--config", type=Path, help="JSON draft; omit for the interactive wizard")
    revise = subparsers.add_parser("revise", help="create the next immutable revision")
    revise.add_argument("identifier")
    revise.add_argument("--config", required=True, type=Path)
    subparsers.add_parser("list", help="list engagements").add_argument("--format", choices=("table", "json"), default="table")
    show = subparsers.add_parser("show", help="show current engagement configuration")
    show.add_argument("identifier")
    validate = subparsers.add_parser("validate", help="validate activation requirements")
    validate.add_argument("identifier")
    transition_parser = subparsers.add_parser("transition", help="change engagement state")
    transition_parser.add_argument("identifier")
    transition_parser.add_argument("state", choices=STATES)
    select = subparsers.add_parser("select", help="select an active engagement for one CSTK process")
    select.add_argument("identifier")
    select.add_argument("--format", choices=("tsv", "json"), default="tsv")
    authorize = subparsers.add_parser("authorize", help="evaluate one target/action before tool dispatch")
    authorize.add_argument("identifier")
    authorize.add_argument("--action", required=True, choices=ACTIONS)
    authorize.add_argument("--target", required=True)
    authorize.add_argument("--resolved-ip", action="append", default=[])
    authorize.add_argument("--protocol", choices=("tcp", "udp"))
    authorize.add_argument("--port", type=int)
    authorize.add_argument("--source-ip")
    authorize.add_argument("--confirmed-by")
    authorize.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root
    try:
        if args.command == "create":
            config = read_json(args.config) if args.config else interactive_config()
            created = create_engagement(root, config)
            print(created.name)
        elif args.command == "revise":
            revised = revise_engagement(root, args.identifier, read_json(args.config))
            print(revised)
        elif args.command == "list":
            if args.format == "table":
                print_summary_table(root)
            else:
                summaries = [refresh_summary(path) for path in engagement_candidates(root)]
                print(json.dumps(summaries, indent=2, sort_keys=True))
        elif args.command == "show":
            engagement_dir = resolve_engagement(root, args.identifier)
            config, revision, scope_hash = load_current_config(engagement_dir)
            output = {
                "state": load_state(engagement_dir),
                "revision": revision,
                "scope_sha256": scope_hash,
                "configuration": config,
            }
            print(json.dumps(output, indent=2, sort_keys=True))
        elif args.command == "validate":
            engagement_dir = resolve_engagement(root, args.identifier)
            config, _, _ = load_current_config(engagement_dir)
            errors = validation_errors(config, activation=True)
            if errors:
                print("Engagement is not activation-ready:", file=sys.stderr)
                for error in errors:
                    print(f"- {error}", file=sys.stderr)
                return 2
            print("Engagement is activation-ready.")
        elif args.command == "transition":
            summary = transition(root, args.identifier, args.state)
            print(f"{summary['slug']}: {summary['state']}")
        elif args.command == "select":
            values = selection_values(root, args.identifier)
            if args.format == "json":
                print(json.dumps(values, indent=2, sort_keys=True))
            else:
                for key, value in values.items():
                    if "\t" in value or "\n" in value:
                        raise EngagementError(f"unsafe selection value for {key}")
                    print(f"{key}\t{value}")
        elif args.command == "authorize":
            decision = authorize_action(
                root,
                args.identifier,
                action=args.action,
                target=args.target,
                resolved_ips=args.resolved_ip,
                protocol=args.protocol,
                port=args.port,
                source_ip=args.source_ip,
                confirmed_by=args.confirmed_by,
            )
            if args.format == "json":
                print(json.dumps(decision, indent=2, sort_keys=True))
            else:
                status = "ALLOW" if decision["allowed"] else "DENY"
                print(f"{status}: {terminal_safe(args.action)} -> {terminal_safe(args.target)}")
                for reason in decision["reasons"]:
                    print(f"- {terminal_safe(reason)}")
            return 0 if decision["allowed"] else 3
        else:
            raise EngagementError("unsupported command")
    except (EngagementError, OSError, ValueError) as exc:
        print(f"cstk-engagement: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
