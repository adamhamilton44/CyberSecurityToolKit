#!/usr/bin/env python3
"""CSTK engagement manager and bounded, policy-gated network adapters."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import uuid
from collections import deque
from pathlib import Path

import cstk_engagement as policy
from cstk_reporting.integration import Capture, reporting_session, unlock_notebook
from cstk_reporting.storage import NotebookError


class Stopped(RuntimeError):
    pass


def snapshot(root, identifier, expected=None):
    directory = policy.resolve_engagement(root, identifier)
    policy.assert_private_engagement_tree(directory)
    config, revision, digest = policy.load_current_config(directory)
    errors = policy.validation_errors(config, activation=True)
    current = dt.datetime.now(dt.timezone.utc)
    state = policy.load_state(directory)
    if state != "active":
        errors.append("engagement is " + state)
    if not policy.authorization_current(config, current):
        errors.append("authorization date is not current")
    if not policy._inside_testing_window(config, current):
        errors.append("testing window is closed")
    if expected and digest != expected:
        errors.append("scope revision changed; select the engagement again")
    contacts = [c for c in config["contacts"] if c["role"] == "emergency"]
    contact = contacts[0] if contacts else {}
    return {
        "directory": directory,
        "config": config,
        "revision": revision,
        "digest": digest,
        "state": state,
        "errors": errors,
        "emergency": contact,
    }


def status_lines(item):
    c = item["config"]
    limits = c["constraints"]
    contact = item["emergency"]
    status = (
        "STOP / REVIEW: " + "; ".join(item["errors"])
        if item["errors"]
        else "ACTIVE / GUARDED OPERATIONS ONLY"
    )
    include = ", ".join(e["value"] for e in c["scope"]["include"])
    exclude = ", ".join(e["value"] for e in c["scope"]["exclude"]) or "(none recorded)"
    return [
        f"ENGAGEMENT {c['slug']} | {status}",
        f"Client: {str(c.get('client', ''))[:16]} | Rev {item['revision']} {item['digest'][:8]} | {limits['max_requests_per_second']} req/s sequential",
        f"Authorization: {c['authorization']['valid_from']} to {c['authorization']['valid_until']} ({c['authorization']['timezone']})",
        f"IN ({len(c['scope']['include'])}): {include}",
        f"OUT ({len(c['scope']['exclude'])}): {exclude}",
        f"EMERGENCY: {contact.get('name', '')} | {contact.get('method', '')}",
    ]


class Guard:
    def __init__(self, root, identifier, expected=None, confirmed=False):
        self.root = root
        self.identifier = identifier
        self.expected = expected
        self.confirmed = confirmed
        self.cancel = threading.Event()
        self.deadline = time.monotonic() + 300
        self.messages = deque(maxlen=30)
        self.lock = threading.RLock()
        self.last_start = 0.0
        self.item = snapshot(root, identifier, expected)
        self.run_id = str(uuid.uuid4())
        self.results = []
        self.sockets = set()
        self.capture = None

    def register_socket(self, stream):
        with self.lock:
            if self.cancel.is_set():
                stream.close()
                raise Stopped("run has been cancelled")
            self.sockets.add(stream)

    def stop(self):
        self.cancel.set()
        with self.lock:
            for stream in self.sockets:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    stream.close()
                except OSError:
                    pass
            self.sockets.clear()

    def check(self):
        if self.cancel.is_set():
            raise Stopped("cancelled or engagement no longer operational")
        if time.monotonic() >= self.deadline:
            raise Stopped("five-minute adapter run limit reached")
        self.item = snapshot(self.root, self.identifier, self.expected)
        if self.item["errors"]:
            raise Stopped("; ".join(self.item["errors"]))
        return self.item

    def log(self, message):
        with self.lock:
            self.messages.append(policy.terminal_safe(message))

    def pace(self, byte_count=0):
        item = self.check()
        constraints = item["config"]["constraints"]
        bandwidth = constraints["max_bandwidth_mbps"]
        delay = max(
            1 / constraints["max_requests_per_second"],
            byte_count * 8 / (bandwidth * 1_000_000) if bandwidth else 0,
        )
        until = self.last_start + delay
        while time.monotonic() < until:
            self.check()
            self.cancel.wait(min(0.1, until - time.monotonic()))
        self.last_start = time.monotonic()

    def decision(self, target, addresses, port, source, action):
        self.check()
        decision = policy.authorize_action(
            self.root,
            self.identifier,
            action=action,
            target=target,
            resolved_ips=addresses,
            protocol="tcp",
            port=port,
            source_ip=source,
            confirmed_by=os.environ.get("USER", "operator") if self.confirmed else None,
        )
        if decision["scope_sha256"] != self.item["digest"]:
            raise Stopped("scope changed during authorization")
        if not decision["allowed"]:
            raise Stopped("; ".join(decision["reasons"]))
        if self.capture is not None:
            self.capture.authorized(decision)
        return decision

    def record(self, value):
        self.check()
        if "url" in value:
            parsed = urllib.parse.urlsplit(value["url"])
            value = dict(
                value,
                url=urllib.parse.urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, "", "")
                ),
            )
        if self.capture is not None:
            self.capture.record(value)
        self.results.append(value)
        self.log(json.dumps(value, sort_keys=True))


def route_source(address, port):
    """UDP connect selects a local route; no application datagram is sent."""
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.connect((str(ip), port))
        return probe.getsockname()[0]


def pinned_socket(address, port, source, guard=None):
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    stream = socket.socket(family, socket.SOCK_STREAM)
    try:
        if guard is not None:
            guard.register_socket(stream)
        stream.settimeout(2)
        stream.bind((source, 0))
        stream.connect((str(ip), port))
        return stream
    except BaseException:
        stream.close()
        raise


def tcp_probe(guard, addresses, ports):
    for address in addresses:
        target = str(ipaddress.ip_address(address))
        for port in ports:
            guard.pace()
            # Reject scope/action/port before route selection or any target connection.
            preliminary = guard.check()
            if not policy._target_allowed(preliminary["config"], target)[0]:
                guard.decision(target, [target], port, None, "network.discovery")
            source = route_source(target, port)
            guard.decision(target, [target], port, source, "network.discovery")
            try:
                with pinned_socket(target, port, source, guard):
                    result = "open"
            except OSError:
                result = "closed-or-unreachable"
            guard.check()
            guard.record({"target": target, "port": port, "result": result})


def resolve_checked(guard, target):
    policy.validate_network_target(target)
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in ("http", "https"):
        raise Stopped("HTTP(S) URL required")
    item = guard.check()
    config = item["config"]
    # DNS queries are not made for an excluded/unlisted URL.
    if not policy._target_allowed(config, target)[0]:
        policy.append_audit(
            item["directory"],
            "guarded_target_denied",
            {
                "action": "web.active",
                "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
            },
        )
        raise Stopped(
            "URL is excluded or not included; DNS resolution was not attempted"
        )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not policy._port_allowed(config, "tcp", port):
        raise Stopped("URL port is not authorized")
    actions = config["actions"]
    if "web.active" in actions["deny"] or (
        "web.active" not in actions["allow"]
        and "web.active" not in actions["confirm_each_run"]
    ):
        raise Stopped("web.active is not authorized; DNS resolution was not attempted")
    if "web.active" in actions["confirm_each_run"] and not guard.confirmed:
        raise Stopped("fresh per-run confirmation is required before DNS resolution")
    try:
        addresses = [str(ipaddress.ip_address(parsed.hostname))]
    except ValueError:
        if config["constraints"]["dns_policy"] != "both_required":
            raise Stopped("guarded hostname requests require both_required DNS policy")
        addresses = sorted(
            {
                r[4][0]
                for r in socket.getaddrinfo(
                    parsed.hostname, port, type=socket.SOCK_STREAM
                )
            }
        )
    if not addresses:
        raise Stopped("no resolved address")
    # Every answer is authorized, then the selected numeric IP is pinned for this request.
    for address in addresses:
        source = route_source(address, port)
        guard.decision(target, addresses, port, source, "web.active")
    return parsed, addresses, port


def web_request(guard, target):
    seen = set()
    for hop in range(6):
        if target in seen:
            raise Stopped("redirect loop")
        seen.add(target)
        guard.pace()
        parsed, addresses, port = resolve_checked(guard, target)
        address = addresses[0]
        source = route_source(address, port)
        guard.decision(target, addresses, port, source, "web.active")
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=2)
        try:
            conn.sock = pinned_socket(address, port, source, guard)
            if parsed.scheme == "https":
                conn.sock = ssl.create_default_context().wrap_socket(
                    conn.sock,
                    server_hostname=parsed.hostname,
                    do_handshake_on_connect=False,
                )
                guard.register_socket(conn.sock)
                guard.check()
                conn.sock.do_handshake()
                guard.check()
            guard.decision(target, addresses, port, source, "web.active")
            headers = {
                "User-Agent": "CSTK-Engagement/1",
                "Connection": "close",
                "Accept-Encoding": "identity",
            }
            custom = guard.item["config"]["traffic_identification"]["custom_header"]
            if custom["enabled"]:
                name = custom["name"]
                value = custom["value_template"].replace(
                    "{engagement_id}", guard.item["config"]["engagement_id"]
                )
                if not re.fullmatch(
                    r"[A-Za-z0-9-]+", name
                ) or policy.has_control_characters(value):
                    raise Stopped("unsafe identification header")
                if name.lower() in (
                    "host",
                    "connection",
                    "content-length",
                    "transfer-encoding",
                ):
                    raise Stopped("reserved identification header")
                headers[name] = value
            path = urllib.parse.urlunsplit(
                ("", "", parsed.path or "/", parsed.query, "")
            )
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            guard.check()
            location = response.getheader("Location")
            guard.record(
                {
                    "url": target,
                    "connected_ip": address,
                    "status": response.status,
                    "hop": hop,
                }
            )
            if response.status in (301, 302, 303, 307, 308) and location:
                redirect_policy = guard.item["config"]["constraints"]["redirect_policy"]
                next_target = urllib.parse.urljoin(target, location)
                next_url = urllib.parse.urlsplit(next_target)
                if redirect_policy == "deny":
                    raise Stopped("redirect following is denied")
                if (
                    redirect_policy == "same_host_only"
                    and next_url.hostname != parsed.hostname
                ):
                    raise Stopped("redirect changes host under same_host_only policy")
                if parsed.scheme == "https" and next_url.scheme != "https":
                    raise Stopped("HTTPS downgrade denied")
                if hop == 5:
                    raise Stopped("redirect limit reached")
                target = next_target
                continue  # Next iteration validates destination before DNS or connection.
            # Do not retain page bodies or fetch linked resources. Bound response bytes.
            total = 0
            digest = hashlib.sha256()
            while True:
                guard.check()
                chunk = response.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1_048_576:
                    raise Stopped("response exceeds 1 MiB limit")
                digest.update(chunk)
                limits = guard.item["config"]["constraints"]
                if limits["max_bandwidth_mbps"] and guard.cancel.wait(
                    len(chunk) * 8 / (limits["max_bandwidth_mbps"] * 1_000_000)
                ):
                    guard.check()
            guard.record(
                {"url": target, "body_bytes": total, "body_sha256": digest.hexdigest()}
            )
            return
        finally:
            conn.close()


def parse_ports(value):
    ports = sorted({int(p) for p in value.split(",")})
    if not ports or len(ports) > 64 or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("provide 1–64 comma-separated ports in 1–65535")
    return ports


def render(guard):
    lines = status_lines(guard.item)
    with guard.lock:
        lines += ["", "Ctrl+C stops this run."] + list(guard.messages)[-12:]
    if sys.stdout.isatty():
        import shutil

        cols, rows = shutil.get_terminal_size((80, 24))
        print(
            "\033[H\033[2J"
            + "\n".join(
                policy.terminal_safe(x)[: max(1, cols - 1)] for x in lines[: rows - 1]
            ),
            flush=True,
        )


def run_adapter(args, notebook=None):
    if notebook is None:
        with unlock_notebook(args.root, args.identifier) as opened:
            return run_adapter(args, opened)
    expected = getattr(args, "expected_scope", None) or os.environ.get(
        "CSTK_SCOPE_SHA256"
    )
    if not expected:
        raise Stopped("select an engagement through cstk first")
    if sys.stdout.isatty():
        import shutil

        cols, rows = shutil.get_terminal_size((80, 24))
        if cols < 60 or rows < 16:
            raise Stopped(
                "resize the terminal to at least 60 columns and 16 rows so engagement status stays visible"
            )
    guard = Guard(args.root, args.identifier, expected, args.confirm)
    item = guard.check()
    guard.expected = item["digest"]
    expected = item["digest"]
    # One guarded run per engagement across processes; never exceed concurrency limits.
    lock_path = item["directory"] / "Runs" / ".adapter.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_fd)
        raise Stopped("another guarded run is already active in this engagement")
    try:
        if args.adapter == "tcp":
            network = ipaddress.ip_network(args.target, strict=False)
            if network.num_addresses > 256:
                raise Stopped("TCP adapter accepts at most 256 explicit IP addresses")
            addresses = [
                str(a) for a in network
            ]  # CIDR entries are expanded and checked individually.
            ports = parse_ports(args.ports)
            operation = lambda: tcp_probe(guard, addresses, ports)
        else:
            operation = lambda: web_request(guard, args.target)
        guard.capture = Capture(notebook, item, args.adapter, args.target, guard.run_id)
        failure = []

        def work():
            try:
                operation()
            except Exception as exc:
                failure.append(str(exc))
                guard.log("STOP: " + str(exc))

        previous = signal.signal(signal.SIGINT, lambda *_: guard.stop())
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        cancelled_at = None
        try:
            while thread.is_alive():
                try:
                    guard.check()
                except Exception as exc:
                    guard.stop()
                    guard.log("STOP: " + str(exc))
                if guard.cancel.is_set():
                    cancelled_at = cancelled_at or time.monotonic()
                    if time.monotonic() - cancelled_at > 3:
                        failure.append(
                            "operation stopped; pending resolver/read abandoned"
                        )
                        break
                render(guard)
                thread.join(0.2)
            render(guard)
        finally:
            signal.signal(signal.SIGINT, previous)
        directory = policy.resolve_engagement(args.root, args.identifier)
        policy.assert_private_engagement_tree(directory)
        was_cancelled = guard.cancel.is_set()
        # Close every registered transport before finalizing the private run record.
        guard.stop()
        record = {
            "run_id": guard.run_id,
            "adapter": args.adapter,
            "scope_sha256": expected,
            "results": guard.results,
            "errors": failure,
            "cancelled": was_cancelled,
        }
        destination = directory / "Runs" / (guard.run_id + ".json")
        policy.atomic_write(destination, json.dumps(record, indent=2).encode())
        policy.append_audit(
            directory,
            "guarded_run_finished",
            {
                "run_id": guard.run_id,
                "adapter": args.adapter,
                "errors": failure,
                "cancelled": was_cancelled,
            },
        )
        print("Run record:", destination)
        guard.capture.finish(failure, was_cancelled, len(guard.results))
        if failure or was_cancelled:
            return 3
        return 0
    finally:
        guard.stop()
        os.close(lock_fd)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--help"], ["-h"]) or (len(argv) == 3 and argv[2] in ("--help", "-h")):
        policy.build_parser().print_help()
        print("Additional runtime commands: status ID | hud ID | report ID")
        print("run ID --adapter tcp|web --target TARGET [--ports PORTS] --confirm")
        print(
            "Guarded runs require encrypted reporting capture; report opens notebook review."
        )
        return 0
    # Existing manager commands preserve their stable CLI and storage format.
    if len(argv) < 3 or argv[2] not in ("status", "hud", "run", "report"):
        return policy.main(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    status = sub.add_parser("status")
    status.add_argument("identifier")
    hud = sub.add_parser("hud")
    hud.add_argument("identifier")
    report = sub.add_parser("report")
    report.add_argument("identifier")
    run = sub.add_parser("run")
    run.add_argument("identifier")
    run.add_argument("--adapter", choices=("tcp", "web"), required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--ports", default="443")
    run.add_argument("--confirm", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            return reporting_session(args.root, args.identifier, run_adapter)
        if args.command == "hud":
            if not sys.stdout.isatty():
                return 0
            import shutil

            try:
                while True:
                    cols, rows = shutil.get_terminal_size((80, 24))
                    try:
                        item = snapshot(
                            args.root,
                            args.identifier,
                            os.environ.get("CSTK_SCOPE_SHA256"),
                        )
                        lines = status_lines(item)
                    except Exception as exc:
                        lines = ["ENGAGEMENT STOP / REVIEW: " + str(exc)]
                    if rows >= 16:
                        frame = (
                            "\0337"
                            + "".join(
                                f"\033[{i + 1};1H\033[2K"
                                + policy.terminal_safe(line)[: max(1, cols - 1)]
                                for i, line in enumerate((lines + [""] * 6)[:6])
                            )
                            + "\0338"
                        )
                        sys.stdout.write(frame)
                        sys.stdout.flush()
                    time.sleep(1)
            except (KeyboardInterrupt, BrokenPipeError):
                return 0
        if args.command == "status":
            item = snapshot(
                args.root, args.identifier, os.environ.get("CSTK_SCOPE_SHA256")
            )
            for line in status_lines(item):
                print(policy.terminal_safe(line))
            return 3 if item["errors"] else 0
        return run_adapter(args)
    except (EOFError, KeyboardInterrupt):
        print("Session closed; encrypted notes retained.", file=sys.stderr)
        return 130
    except (
        policy.EngagementError,
        NotebookError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        Stopped,
    ) as exc:
        print("STOP / REVIEW: " + policy.terminal_safe(str(exc)), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
