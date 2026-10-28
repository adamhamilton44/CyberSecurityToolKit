#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "source" / "cstk_ai" / "cstk_engagement.py"
SPEC = importlib.util.spec_from_file_location("cstk_engagement", MODULE_PATH)
assert SPEC and SPEC.loader
engagement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engagement)


def iso(value: dt.datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def valid_config(name: str = "Example Assessment") -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    allowed = {
        "recon.passive",
        "network.discovery",
        "vulnerability.scan",
        "web.passive",
        "web.active",
    }
    confirm = {"credential.online", "exploit.validation"}
    denied = set(engagement.ACTIONS) - allowed - confirm
    return {
        "schema_version": 1,
        "slug": engagement.normalize_slug(name),
        "name": name,
        "client": "Fixture Organization",
        "engagement_type": "penetration_test",
        "status": "draft",
        "revision": {"created_by": "fixture-tester"},
        "authorization": {
            "reference": "FIXTURE-ROE-1",
            "system_owner": "Fixture Organization",
            "authorized_by": "Fixture Authorizer",
            "valid_from": iso(now - dt.timedelta(days=1)),
            "valid_until": iso(now + dt.timedelta(days=1)),
            "timezone": "UTC",
            "third_party_consent": "not_applicable",
            "evidence": {"location": "fixture://roe", "sha256": "a" * 64},
        },
        "environment": {
            "types": ["staging"],
            "access_method": "vpn",
            "access_notes": "fixture",
            "third_party_infrastructure": [],
        },
        "testers": [{"name": "fixture-tester", "role": "lead tester"}],
        "contacts": [
            {"name": "Primary Contact", "role": "primary", "method": "fixture"},
            {"name": "Technical Contact", "role": "technical", "method": "fixture"},
            {"name": "Emergency Contact", "role": "emergency", "method": "fixture"},
            {"name": "Breach Contact", "role": "breach_escalation", "method": "fixture"},
        ],
        "scope": {
            "include": [
                {"type": "cidr", "value": "192.0.2.0/28", "note": "RFC 5737 fixture"},
                {"type": "dns", "value": "app.example.test", "note": "fixture"},
            ],
            "exclude": [{"type": "ip", "value": "192.0.2.5", "note": "fixture exclusion"}],
        },
        "actions": {
            "allow": sorted(allowed),
            "confirm_each_run": sorted(confirm),
            "deny": sorted(denied),
        },
        "technical_policy": {
            "scan_intensity": "standard_non_destructive",
            "credentialed_testing": False,
            "credential_references": [],
            "automatic_exploitation": "manual_approval_each",
            "denial_of_service": "strictly_forbidden",
        },
        "constraints": {
            "testing_windows": [
                {
                    "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                    "start": "00:00",
                    "end": "23:59",
                    "timezone": "UTC",
                }
            ],
            "allowed_source_ips": ["198.51.100.10"],
            "ports": [{"protocol": "tcp", "ports": ["80", "443"]}],
            "max_requests_per_second": 5,
            "max_bandwidth_mbps": 10,
            "max_concurrency": 4,
            "redirect_policy": "validate_every_hop",
            "dns_policy": "both_required",
            "stop_conditions": ["Unexpected availability impact", "The system owner requests a stop"],
        },
        "traffic_identification": {
            "source_ip_not_applicable_reason": None,
            "custom_header": {"enabled": False, "name": None, "value_template": None},
            "defense_coordination": "monitor_only",
        },
        "incident_coordination": {
            "soc_notification": "notified",
            "breach_escalation_procedure": "Pause testing and contact the breach escalation contact.",
        },
        "data_handling": {
            "classification": "confidential",
            "retention_days": 30,
            "out_of_scope_storage": "minimal_fingerprint",
            "secret_storage": "redact",
            "sensitive_data_policy": {
                "pii": "mask_and_continue",
                "pci": "stop_and_notify",
                "phi": "stop_and_notify",
            },
            "encryption_required": True,
            "encryption_standard": "fixture encrypted storage and transfer",
            "cleanup_required": True,
        },
        "reporting": {
            "format": "fixture",
            "delivery_method": "fixture",
            "critical_finding_deadline_minutes": 60,
        },
        "red_team": None,
        "notes": "fixture only",
    }


class EngagementManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cstk-engagement-test-")
        self.root = Path(self.temp.name) / "engagements"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_active(self, name: str = "Example Assessment") -> Path:
        created = engagement.create_engagement(self.root, valid_config(name))
        slug = engagement.read_json(created / "engagement.json")["slug"]
        engagement.transition(self.root, slug, "ready")
        engagement.transition(self.root, slug, "active")
        return created

    def test_two_sessions_never_share_output_roots(self) -> None:
        first = self.create_active("Client Alpha")
        second = self.create_active("Client Beta")
        first_values = engagement.selection_values(self.root, "client-alpha")
        second_values = engagement.selection_values(self.root, "client-beta")
        self.assertNotEqual(first_values["CSTK_SESSION_ID"], second_values["CSTK_SESSION_ID"])
        self.assertNotEqual(first_values["CSTK_LOOT_DIR"], second_values["CSTK_LOOT_DIR"])
        Path(first_values["CSTK_LOOT_DIR"], "fixture.txt").write_text("alpha", encoding="utf-8")
        Path(second_values["CSTK_LOOT_DIR"], "fixture.txt").write_text("beta", encoding="utf-8")
        self.assertEqual((first / "Loot" / "fixture.txt").read_text(), "alpha")
        self.assertEqual((second / "Loot" / "fixture.txt").read_text(), "beta")

    def test_selection_does_not_create_global_active_pointer(self) -> None:
        self.create_active()
        engagement.selection_values(self.root, "example-assessment")
        names = {path.name for path in self.root.rglob("*")}
        self.assertNotIn("active_engagement", names)
        self.assertNotIn(".active_engagement", names)

    def test_directory_and_file_modes_are_private(self) -> None:
        created = engagement.create_engagement(self.root, valid_config())
        self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o700)
        for directory in engagement.DATA_DIRS:
            self.assertEqual(stat.S_IMODE((created / directory).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((created / "state").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((created / "scope" / "revisions" / "000001.json").stat().st_mode), 0o600)

    def test_revision_one_is_immutable_when_revision_two_is_created(self) -> None:
        created = engagement.create_engagement(self.root, valid_config())
        revision_one = created / "scope" / "revisions" / "000001.json"
        before = revision_one.read_bytes()
        before_hash = hashlib.sha256(before).hexdigest()
        changed = valid_config("Updated Name")
        changed["revision"] = {"created_by": "fixture-tester", "change_reason": "approved fixture change"}
        revision_two = engagement.revise_engagement(self.root, "example-assessment", changed)
        self.assertEqual(revision_one.read_bytes(), before)
        self.assertEqual(hashlib.sha256(revision_one.read_bytes()).hexdigest(), before_hash)
        revised = json.loads(revision_two.read_text())
        self.assertEqual(revised["revision"]["number"], 2)
        self.assertEqual(revised["revision"]["previous_sha256"], before_hash)
        self.assertEqual(engagement.current_revision_number(created), 2)

    def test_invalid_transition_is_denied(self) -> None:
        engagement.create_engagement(self.root, valid_config())
        with self.assertRaises(engagement.EngagementError):
            engagement.transition(self.root, "example-assessment", "active")

    def test_expired_authorization_cannot_be_activated(self) -> None:
        config = valid_config("Expired Assessment")
        now = dt.datetime.now(dt.timezone.utc)
        config["authorization"]["valid_from"] = iso(now - dt.timedelta(days=3))
        config["authorization"]["valid_until"] = iso(now - dt.timedelta(days=2))
        engagement.create_engagement(self.root, config)
        engagement.transition(self.root, "expired-assessment", "ready")
        with self.assertRaises(engagement.EngagementError):
            engagement.transition(self.root, "expired-assessment", "active")

    def test_path_traversal_identifier_is_denied(self) -> None:
        engagement.create_engagement(self.root, valid_config())
        for identifier in ("../example-assessment", "/tmp/example", "..", "a\\b"):
            with self.subTest(identifier=identifier):
                with self.assertRaises(engagement.EngagementError):
                    engagement.resolve_engagement(self.root, identifier)

    def test_symlinked_output_directory_is_denied(self) -> None:
        created = self.create_active()
        loot = created / "Loot"
        loot.rmdir()
        loot.symlink_to(Path(self.temp.name))
        with self.assertRaises(engagement.EngagementError):
            engagement.selection_values(self.root, "example-assessment")

    def test_permissive_engagement_mode_is_denied(self) -> None:
        created = self.create_active()
        os.chmod(created / "Logs", 0o755)
        with self.assertRaises(engagement.EngagementError):
            engagement.selection_values(self.root, "example-assessment")

    def test_action_overlap_is_rejected(self) -> None:
        config = valid_config()
        config["actions"]["confirm_each_run"].append(config["actions"]["allow"][0])
        with self.assertRaises(engagement.EngagementError):
            engagement.create_engagement(self.root, config)

    def test_malformed_operational_constraints_are_rejected(self) -> None:
        config = valid_config()
        config["constraints"]["ports"][0]["ports"] = ["443", "65536", "9000-8000"]
        config["constraints"]["max_concurrency"] = 0
        config["constraints"]["testing_windows"][0]["start"] = "25:00"
        with self.assertRaises(engagement.EngagementError):
            engagement.create_engagement(self.root, config)

    def test_cheat_sheet_questions_have_explicit_config_mappings(self) -> None:
        self.assertEqual(engagement.questionnaire_tags(), set(engagement.QUESTION_TO_CONFIG))
        self.assertEqual(len(engagement.QUESTION_TO_CONFIG), 23)

    def test_cheat_sheet_fingerprint_is_pinned_to_revision(self) -> None:
        config = engagement.prepare_new_config(valid_config())
        self.assertEqual(config["questionnaire"]["name"], engagement.QUESTIONNAIRE_NAME)
        self.assertEqual(
            config["questionnaire"]["sha256"],
            engagement.sha256_bytes(engagement.safe_read(engagement.QUESTIONNAIRE_PATH)),
        )
        config["questionnaire"]["sha256"] = "0" * 64
        errors = engagement.validation_errors(config, activation=True)
        self.assertTrue(any("questionnaire changed" in error for error in errors))

    def test_new_minimum_question_groups_are_required(self) -> None:
        for key in ("environment", "technical_policy", "traffic_identification", "incident_coordination"):
            with self.subTest(key=key):
                config = engagement.prepare_new_config(valid_config())
                config.pop(key)
                self.assertTrue(engagement.validation_errors(config, activation=False))

    def test_activation_requires_source_identity_or_reason(self) -> None:
        config = engagement.prepare_new_config(valid_config())
        config["constraints"]["allowed_source_ips"] = []
        config["traffic_identification"]["source_ip_not_applicable_reason"] = None
        errors = engagement.validation_errors(config, activation=True)
        self.assertTrue(any("approved source IPs" in error for error in errors))
        config["traffic_identification"]["source_ip_not_applicable_reason"] = "Testing runs from an internal agent."
        errors = engagement.validation_errors(config, activation=True)
        self.assertFalse(any("approved source IPs" in error for error in errors))

    def test_technical_policy_must_match_action_policy(self) -> None:
        config = valid_config()
        config["technical_policy"]["automatic_exploitation"] = "denied_stop_on_flag"
        with self.assertRaises(engagement.EngagementError):
            engagement.create_engagement(self.root, config)

    def test_third_party_infrastructure_requires_confirmed_provider_consent(self) -> None:
        config = engagement.prepare_new_config(valid_config())
        config["environment"]["third_party_infrastructure"] = [
            {
                "provider": "Fixture Cloud",
                "service": "fixture tenant",
                "written_authorization_reference": "fixture://provider-approval",
            }
        ]
        errors = engagement.validation_errors(config, activation=True)
        self.assertTrue(any("provider consent" in error for error in errors))
        config["authorization"]["third_party_consent"] = "confirmed"
        errors = engagement.validation_errors(config, activation=True)
        self.assertFalse(any("provider consent" in error for error in errors))

    def test_credential_records_contain_references_not_secret_fields(self) -> None:
        config = valid_config()
        config["technical_policy"]["credentialed_testing"] = True
        config["technical_policy"]["credential_references"] = [
            {"account_identifier": "test-user", "role": "standard user", "secret_source": "vault://fixture/test-user"}
        ]
        created = engagement.create_engagement(self.root, config)
        saved, _, _ = engagement.load_current_config(created)
        reference = saved["technical_policy"]["credential_references"][0]
        self.assertEqual(set(reference), {"account_identifier", "role", "secret_source"})
        self.assertNotIn("password", reference)
        self.assertNotIn("token", reference)

    def test_audit_chain_is_complete(self) -> None:
        created = self.create_active()
        engagement.selection_values(self.root, "example-assessment")
        events = [json.loads(line) for line in (created / "Audit" / "events.jsonl").read_text().splitlines()]
        self.assertGreaterEqual(len(events), 4)
        previous = None
        for event in events:
            self.assertEqual(event["previous_event_sha256"], previous)
            recorded = event.pop("event_sha256")
            self.assertEqual(recorded, engagement.sha256_bytes(engagement.canonical_json_bytes(event)))
            previous = recorded

    def test_cli_create_validate_activate_and_select(self) -> None:
        config_path = Path(self.temp.name) / "cli-config.json"
        config_path.write_text(json.dumps(valid_config("CLI Assessment")), encoding="utf-8")
        base = [sys.executable, str(MODULE_PATH), "--root", str(self.root)]

        created = subprocess.run(
            base + ["create", "--config", str(config_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("cli-assessment--", created.stdout)
        subprocess.run(base + ["validate", "cli-assessment"], check=True, capture_output=True, text=True)
        subprocess.run(base + ["transition", "cli-assessment", "ready"], check=True, capture_output=True, text=True)
        subprocess.run(base + ["transition", "cli-assessment", "active"], check=True, capture_output=True, text=True)
        selected = subprocess.run(
            base + ["select", "cli-assessment", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        values = json.loads(selected.stdout)
        self.assertEqual(values["CSTK_ENGAGEMENT_SLUG"], "cli-assessment")
        self.assertEqual(values["CSTK_ENGAGEMENT_STATE"], "active")
        self.assertEqual(values["CSTK_SCOPE_REVISION"], "1")

    def test_phase2_allows_in_scope_action_with_constraints(self) -> None:
        self.create_active()
        decision = engagement.authorize_action(
            self.root,
            "example-assessment",
            action="network.discovery",
            target="192.0.2.4",
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        self.assertTrue(decision["allowed"])

    def test_phase2_explicit_exclusion_overrides_cidr(self) -> None:
        self.create_active()
        decision = engagement.authorize_action(
            self.root,
            "example-assessment",
            action="network.discovery",
            target="192.0.2.5",
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        self.assertFalse(decision["allowed"])
        self.assertTrue(any("exclusion" in reason for reason in decision["reasons"]))

    def test_phase2_dns_policy_requires_scoped_resolution(self) -> None:
        self.create_active()
        missing = engagement.authorize_action(
            self.root,
            "example-assessment",
            action="web.active",
            target="https://app.example.test/",
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        self.assertFalse(missing["allowed"])
        allowed = engagement.authorize_action(
            self.root,
            "example-assessment",
            action="web.active",
            target="https://app.example.test/",
            resolved_ips=["192.0.2.4"],
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        self.assertTrue(allowed["allowed"])
        excluded = engagement.authorize_action(
            self.root,
            "example-assessment",
            action="web.active",
            target="https://app.example.test/",
            resolved_ips=["192.0.2.5"],
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        self.assertFalse(excluded["allowed"])

    def test_phase2_confirmation_source_and_port_fail_closed(self) -> None:
        self.create_active()
        base = {
            "root": self.root,
            "identifier": "example-assessment",
            "action": "exploit.validation",
            "target": "192.0.2.4",
            "protocol": "tcp",
            "port": 443,
            "source_ip": "198.51.100.10",
        }
        self.assertFalse(engagement.authorize_action(**base)["allowed"])
        self.assertTrue(engagement.authorize_action(**base, confirmed_by="fixture-tester")["allowed"])
        wrong_source = dict(base, confirmed_by="fixture-tester", source_ip="198.51.100.11")
        self.assertFalse(engagement.authorize_action(**wrong_source)["allowed"])
        wrong_port = dict(base, confirmed_by="fixture-tester", port=22)
        self.assertFalse(engagement.authorize_action(**wrong_port)["allowed"])

    def test_phase2_decisions_are_audited(self) -> None:
        created = self.create_active()
        engagement.authorize_action(
            self.root,
            "example-assessment",
            action="network.discovery",
            target="192.0.2.4",
            protocol="tcp",
            port=80,
            source_ip="198.51.100.10",
        )
        engagement.authorize_action(
            self.root,
            "example-assessment",
            action="destructive",
            target="192.0.2.4",
            source_ip="198.51.100.10",
        )
        events = [json.loads(line)["event"] for line in (created / "Audit" / "events.jsonl").read_text().splitlines()]
        self.assertIn("action_authorized", events)
        self.assertIn("action_denied", events)


class DispatchBoundaryTests(unittest.TestCase):
    def test_guided_target_functions_check_engagement_before_dispatch(self):
        source = (Path(__file__).resolve().parents[2] / "cstk.sh").read_text()
        for name in ("nmap_tool", "enum_tool", "sweep_ip", "waf_detect", "ssh_enum", "pass_attack", "web_tls_assessment"):
            body = source.split(name + "() {", 1)[1].split("\n}", 1)[0]
            first = next(line.strip() for line in body.splitlines() if line.strip())
            self.assertIn("engagement_dispatch_guard " + name, first)


if __name__ == "__main__":
    unittest.main(verbosity=2)
