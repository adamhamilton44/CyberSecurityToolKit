import datetime as dt
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import test_engagement_manager as baseline

valid_config = baseline.valid_config
policy = baseline.engagement

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "scripts/source/cstk_ai"))
sys.path.insert(0, str(BASE / "scripts/source/reporting"))
import engagement_runtime as runtime


class ScopeRegressions(unittest.TestCase):
    setUp = baseline.EngagementManagerTests.setUp
    tearDown = baseline.EngagementManagerTests.tearDown
    create_active = baseline.EngagementManagerTests.create_active

    def test_overnight_window_uses_start_day(self):
        c = valid_config()
        c["constraints"]["testing_windows"] = [
            {"days": ["mon"], "start": "22:00", "end": "02:00", "timezone": "UTC"}
        ]
        self.assertTrue(
            policy._inside_testing_window(
                c, dt.datetime(2026, 10, 27, 1, tzinfo=dt.timezone.utc)
            )
        )
        self.assertFalse(
            policy._inside_testing_window(
                c, dt.datetime(2026, 10, 26, 1, tzinfo=dt.timezone.utc)
            )
        )
        self.assertFalse(
            policy._inside_testing_window(
                c, dt.datetime(2026, 10, 27, 2, tzinfo=dt.timezone.utc)
            )
        )

    def test_url_traversal_and_ambiguous_encodings_fail(self):
        for target in [
            "https://app.example.test/allowed/../outside",
            "https://app.example.test/allowed/%2e%2e/outside",
            "https://app.example.test/allowed/%252e%252e/outside",
            "https://app.example.test/allowed/%2foutside",
            "https://user@app.example.test/allowed/",
            "https://app.example.test/allowed/\\outside",
            "0177.0.0.1",
            "127.1",
            "2130706433",
        ]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                policy.validate_network_target(target)

    def test_url_path_boundaries_and_wildcard_apex(self):
        c = valid_config()
        c["scope"]["include"] = [
            {"type": "url", "value": "https://app.example.test/api/"}
        ]
        self.assertTrue(
            policy._target_allowed(c, "https://app.example.test/api/item")[0]
        )
        for value in [
            "https://app.example.test/apix/item",
            "http://app.example.test/api/item",
            "https://app.example.test:8443/api/item",
        ]:
            self.assertFalse(policy._target_allowed(c, value)[0])
        self.assertFalse(
            policy._dns_matches("example.test", "wildcard_dns", "*.example.test")
        )
        self.assertTrue(
            policy._dns_matches("x.example.test", "wildcard_dns", "*.example.test")
        )

    def test_explicit_resolved_exclusion_applies_to_dns_only_policy(self):
        self.create_active()
        d = policy.resolve_engagement(self.root, "example-assessment")
        c, _, _ = policy.load_current_config(d)
        c["constraints"]["dns_policy"] = "hostname_authorized"
        # Policy decisions are tested on a valid in-memory record; revisions remain immutable.
        with patch.object(policy, "load_current_config", return_value=(c, 1, "a" * 64)):
            decision = policy.authorize_action(
                self.root,
                "example-assessment",
                action="web.active",
                target="https://app.example.test/",
                resolved_ips=["192.0.2.5"],
                protocol="tcp",
                port=443,
                source_ip="198.51.100.10",
            )
        self.assertFalse(decision["allowed"])
        self.assertIn(
            "a resolved address matches an explicit IP exclusion", decision["reasons"]
        )

    def test_policy_uses_supplied_time_for_dates(self):
        self.create_active()
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)
        result = policy.authorize_action(
            self.root,
            "example-assessment",
            action="network.discovery",
            target="192.0.2.4",
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
            now=future,
        )
        self.assertFalse(result["allowed"])
        self.assertIn("authorization dates are not currently valid", result["reasons"])

    def test_paused_or_changed_scope_stops_adapter(self):
        self.create_active()
        item = runtime.snapshot(self.root, "example-assessment")
        with self.assertRaises(runtime.Stopped):
            runtime.Guard(self.root, "example-assessment", "0" * 64).check()
        policy.transition(self.root, "example-assessment", "paused")
        with self.assertRaises(runtime.Stopped):
            runtime.Guard(self.root, "example-assessment", item["digest"]).check()

    def make_guard(self):
        self.create_active()
        item = runtime.snapshot(self.root, "example-assessment")
        return runtime.Guard(self.root, "example-assessment", item["digest"])

    def test_excluded_tcp_address_never_connects(self):
        guard = self.make_guard()
        with (
            patch.object(runtime, "pinned_socket") as stream,
            patch.object(runtime, "route_source") as route,
        ):
            with self.assertRaises(runtime.Stopped):
                runtime.tcp_probe(guard, ["192.0.2.5"], [443])
        stream.assert_not_called()
        route.assert_not_called()

    def test_excluded_web_target_never_resolves(self):
        guard = self.make_guard()
        with patch.object(runtime.socket, "getaddrinfo") as resolver:
            with self.assertRaises(runtime.Stopped):
                runtime.resolve_checked(guard, "https://outside.example.test/")
        resolver.assert_not_called()

    def test_dns_rebinding_cannot_change_connected_ip(self):
        guard = self.make_guard()
        with (
            patch.object(
                runtime.socket,
                "getaddrinfo",
                return_value=[(2, 1, 6, "", ("192.0.2.4", 443))],
            ),
            patch.object(runtime, "route_source", return_value="198.51.100.10"),
        ):
            _, addresses, port = runtime.resolve_checked(
                guard, "https://app.example.test/"
            )
        self.assertEqual(addresses, ["192.0.2.4"])
        self.assertEqual(port, 443)
        # The actual connection path only accepts numeric IP and binds the verified source.
        with patch.object(runtime.socket, "socket") as factory:
            runtime.pinned_socket(addresses[0], port, "198.51.100.10")
        factory.return_value.connect.assert_called_once_with(("192.0.2.4", 443))
        factory.return_value.bind.assert_called_once_with(("198.51.100.10", 0))

    def test_redirect_is_checked_before_second_connection(self):
        guard = self.make_guard()
        response = MagicMock()
        response.status = 302
        response.getheader.return_value = "https://outside.example.test/"
        connection = MagicMock()
        connection.getresponse.return_value = response
        with (
            patch.object(
                runtime.socket,
                "getaddrinfo",
                return_value=[(2, 1, 6, "", ("192.0.2.4", 80))],
            ) as resolver,
            patch.object(runtime, "route_source", return_value="198.51.100.10"),
            patch.object(runtime, "pinned_socket") as pinned,
            patch.object(
                runtime.http.client, "HTTPConnection", return_value=connection
            ),
        ):
            with self.assertRaises(runtime.Stopped):
                runtime.web_request(guard, "http://app.example.test/")
        self.assertEqual(pinned.call_count, 1)
        self.assertEqual(resolver.call_count, 1)

    def test_mixed_dns_answers_fail_before_connect(self):
        guard = self.make_guard()
        answers = [(2, 1, 6, "", ("192.0.2.4", 443)), (2, 1, 6, "", ("192.0.2.5", 443))]
        with (
            patch.object(runtime.socket, "getaddrinfo", return_value=answers),
            patch.object(runtime, "route_source", return_value="198.51.100.10"),
            patch.object(runtime, "pinned_socket") as pinned,
        ):
            with self.assertRaises(runtime.Stopped):
                runtime.resolve_checked(guard, "https://app.example.test/")
        pinned.assert_not_called()


class LauncherContracts(unittest.TestCase):
    def test_all_tool_entrypoints_are_guarded(self):
        import re

        source = (BASE / "cstk.sh").read_text()
        section = source[
            source.index("# ##### OSINT FUNCTIONS #####") : source.index(
                "######################### MAIN SCRIPT"
            )
        ]
        # Menus only dispatch; the project audit is local/read-only and the
        # control alias only lists engagements. Every legacy target tool must gate.
        local_or_dispatch = {
            "run_control_client",
            "web_check_menu",
            "project_security_assessment",
            "defense_menu",
        }
        functions = re.findall(
            r"^([a-z_][a-z_0-9]*)\(\) \{\n(.*?)(?=^\})", section, re.M | re.S
        )
        self.assertGreater(len(functions), 40)
        for name, body in functions:
            if name not in local_or_dispatch:
                self.assertIn("engagement_dispatch_guard " + name, body, name)
            if name == "web_check_menu":
                self.assertIn("engagement_dispatch_guard web_check", body)

    def test_wrapper_denies_without_selection_or_explicit_lab(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            env = dict(
                os.environ,
                home_dir=directory,
                user="fixture",
                user_home=directory,
                CSTK_USER_DATA_DIR=directory,
                CSTK_LOOT_DIR=directory,
                CSTK_MALWARE_DIR=directory,
                CSTK_LOG_DIR=directory,
                CSTK_KEYS_DIR=directory,
                CSTK_LOGGING_ENABLED="off",
                CSTK_MAIN_RUNNER="1",
            )
            for key in ["CSTK_ENGAGEMENT_ID", "CSTK_STANDALONE_LAB"]:
                env.pop(key, None)
            wrapper = BASE / "scripts/lib/cstk_wrapper"
            result = subprocess.run(
                ["bash", str(wrapper), "/usr/bin/true"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            env["CSTK_STANDALONE_LAB"] = "1"
            result = subprocess.run(
                ["bash", str(wrapper), "/usr/bin/true"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


class AdditionalPolicyRegressions(unittest.TestCase):
    setUp = baseline.EngagementManagerTests.setUp
    tearDown = baseline.EngagementManagerTests.tearDown
    create_active = baseline.EngagementManagerTests.create_active

    def test_url_port_cannot_be_misrepresented(self):
        self.create_active()
        d = policy.authorize_action(
            self.root,
            "example-assessment",
            action="web.active",
            target="https://app.example.test/",
            resolved_ips=["192.0.2.4"],
            protocol="tcp",
            port=80,
            source_ip="198.51.100.10",
        )
        self.assertFalse(d["allowed"])
        self.assertIn("supplied protocol/port does not match the URL", d["reasons"])

    def test_tampered_audit_cannot_authorize_traffic(self):
        directory = self.create_active()
        p = directory / "Audit/events.jsonl"
        p.write_text(p.read_text().replace("fixture-tester", "tampered-tester"))
        # Modify a guaranteed stored property if fixture-tester was not present.
        lines = p.read_text().splitlines()
        import json

        item = json.loads(lines[0])
        item["event"] = "tampered"
        lines[0] = json.dumps(item)
        p.write_text("\n".join(lines) + "\n")
        with self.assertRaises(policy.EngagementError):
            policy.authorize_action(
                self.root,
                "example-assessment",
                action="network.discovery",
                target="192.0.2.4",
                protocol="tcp",
                port=443,
                source_ip="198.51.100.10",
            )

    def test_denied_target_is_fingerprinted_in_audit(self):
        directory = self.create_active()
        policy.authorize_action(
            self.root,
            "example-assessment",
            action="web.active",
            target="https://outside.example.test/?secret=example",
            protocol="tcp",
            port=443,
            source_ip="198.51.100.10",
        )
        import json

        details = json.loads(
            (directory / "Audit/events.jsonl").read_text().splitlines()[-1]
        )["details"]
        self.assertNotIn("target", details)
        self.assertIn("target_sha256", details)
        self.assertNotIn("secret=example", str(details))


class URLNormalizationTests(unittest.TestCase):
    def test_encoded_letters_cannot_bypass_excluded_url(self):
        c = valid_config()
        c["scope"]["include"] = [
            {"type": "url", "value": "https://app.example.test/api/"}
        ]
        c["scope"]["exclude"] = [
            {"type": "url", "value": "https://app.example.test/api/secret"}
        ]
        for target in [
            "https://app.example.test/api/%73ecret",
            "https://app.example.test/api/%2573ecret",
            "https://app.example.test/api/secret/child",
        ]:
            self.assertFalse(policy._target_allowed(c, target)[0], target)

    def test_server_dependent_path_normalization_is_rejected(self):
        for target in [
            "https://app.example.test/api//secret",
            "https://app.example.test/api/secret;ignored",
            "https://app.example.test/api/secret%3bignored",
        ]:
            with self.assertRaises(ValueError):
                policy.validate_network_target(target)

    def test_query_specific_scope_is_not_misrepresented_as_path_scope(self):
        self.assertIsNotNone(
            policy.target_error(
                {"type": "url", "value": "https://app.example.test/api/?role=public"},
                "scope",
            )
        )
