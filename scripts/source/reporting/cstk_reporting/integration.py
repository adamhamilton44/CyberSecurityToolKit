"""In-process guarded capture. No daemon, stored passphrase, or execution permit."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import shutil
from contextlib import contextmanager

from .model import redact, require_open
from .service import Notebook
from .storage import NotebookError


def current(root, identifier):
    import cstk_engagement as policy

    directory = policy.resolve_engagement(root, identifier)
    policy.assert_private_engagement_tree(directory)
    config, revision, sha = policy.load_current_config(directory)
    return directory, config, revision, sha


def bind(notebook, config, revision, sha):
    state = notebook.snapshot()
    require_open(state)
    scope = state["scope_history"][-1]
    if state["engagement_id"] != config["engagement_id"]:
        raise NotebookError("Notebook belongs to another engagement.")
    if scope["revision"] != revision or scope["scope_sha256"] != sha:
        raise NotebookError(
            "Scope changed: review and import the current scope snapshot in reporting first."
        )


@contextmanager
def unlock_notebook(root, identifier, *, setup=False):
    from .cli import passphrase, say

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory, config, revision, sha = current(root, identifier)
    path = directory / "reporting-notebook"
    if path.is_symlink():
        raise NotebookError("Unsafe notebook path.")
    if not path.exists() or (
        setup
        and not (path / "notebook.enc").exists()
        and not (path / "deleted.json").exists()
    ):
        if not setup:
            raise NotebookError(
                "Set up the encrypted notebook using B in the engagement manager first."
            )
        say(
            "Create encrypted reporting notebook. Losing this passphrase loses the notes.",
            style="yellow",
        )
        notebook = Notebook.create(path, passphrase(new=True), config, revision, sha)
    else:
        notebook = Notebook.open(path, passphrase())
    try:
        # Review/export stays available after engagement closure or scope revision.
        if not setup:
            bind(notebook, config, revision, sha)
        yield notebook
    finally:
        notebook.close()


class Capture:
    def __init__(self, notebook, item, adapter, target, run_id):
        self.notebook = notebook
        self.item = item
        self.authorized_count = 0
        self.run_id = run_id
        self.adapter = adapter
        bind(notebook, item["config"], item["revision"], item["digest"])
        # A pending attempt is recorded before DNS/routing/traffic. This is not
        # authorization; Guard.decision still checks every actual destination.
        self.activity = notebook.start_activity(
            "Guarded " + adapter + " check",
            "Pending destination SHA256=" + hashlib.sha256(target.encode()).hexdigest(),
            scope_revision=item["revision"],
            scope_sha256=item["digest"],
        )

    def authorized(self, decision):
        if (
            decision.get("allowed") is not True
            or decision.get("engagement_id") != self.item["config"]["engagement_id"]
            or decision.get("scope_revision") != self.item["revision"]
            or decision.get("scope_sha256") != self.item["digest"]
        ):
            raise NotebookError("Guard decision and notebook binding differ.")

        # Write before each newly authorized request/connection. Any storage
        # failure prevents the following transport action.
        def save(state):
            scope = state["scope_history"][-1]
            if (
                state["engagement_id"] != decision["engagement_id"]
                or scope["revision"] != decision["scope_revision"]
                or scope["scope_sha256"] != decision["scope_sha256"]
            ):
                raise NotebookError("Notebook scope changed during capture.")
            activity = next(a for a in state["activities"] if a["id"] == self.activity)
            if activity["outcome"] != "running":
                raise NotebookError("Activity was closed during capture.")
            activity["target"] = redact(decision["target"])
            return self.activity

        self.notebook._edit("guarded_destination_authorized", save)
        self.authorized_count += 1

    def record(self, value):
        if not self.authorized_count:
            raise NotebookError("Result has no authorized destination.")
        allowed = (
            "target",
            "port",
            "result",
            "url",
            "connected_ip",
            "status",
            "hop",
            "body_bytes",
            "body_sha256",
        )
        summary = {key: value[key] for key in allowed if key in value}
        asset = summary.get("url", summary.get("target", ""))
        self.notebook.add_note(
            "Guarded " + self.adapter + " observation",
            "Run " + self.run_id + "\n" + json.dumps(summary, sort_keys=True),
            asset=str(asset),
            kind="evidence",
        )

    def finish(self, errors, cancelled, count):
        failed = bool(errors or cancelled)
        outcome = ("partial" if count else "error") if failed else "completed"
        summary = f"Run {self.run_id}: {count} structured observations; {self.authorized_count} authorization decisions. "
        summary += (
            "Bounded check completed; no vulnerability conclusion is implied."
            if not failed
            else "Check incomplete: " + redact("; ".join(errors) or "cancelled")
        )
        self.notebook.finish_activity(
            self.activity, outcome, summary, exit_code=3 if failed else 0
        )


def reporting_session(root, identifier, run_adapter):
    from rich.prompt import Confirm, Prompt

    from .cli import ask_profile, say, shell

    with unlock_notebook(root, identifier, setup=True) as notebook:
        directory, config, revision, sha = current(root, identifier)
        state = notebook.snapshot()
        if state["engagement_id"] != config["engagement_id"]:
            raise NotebookError("Notebook belongs to another engagement.")
        scope = state["scope_history"][-1]
        if state["lifecycle"] == "open" and scope["scope_sha256"] != sha:
            say(
                f"Current engagement scope revision {revision}; notebook revision {scope['revision']}.",
                style="yellow",
            )
            say(
                "Review the current immutable engagement scope before importing it. Testing authorization is unchanged."
            )
            if Confirm.ask("Import the current scope snapshot?", default=False):
                notebook.revise_scope_snapshot(config, revision, sha)
        if not state["profile"].get("author") and state["lifecycle"] == "open":
            if Confirm.ask("Complete reporting questions now?", default=True):
                ask_profile(notebook)

        def guarded(action, unlocked):
            from .cli import say

            adapter = "tcp" if action == "T" else "web"
            target = Prompt.ask(
                "Explicit IP/CIDR (max 256)" if adapter == "tcp" else "Full HTTP(S) URL"
            )
            ports = (
                Prompt.ask("Comma separated TCP ports", default="443")
                if adapter == "tcp"
                else "443"
            )
            if (
                Prompt.ask("Authorize this bounded operation: type RUN", default="")
                != "RUN"
            ):
                return
            args = argparse.Namespace(
                root=root,
                identifier=identifier,
                adapter=adapter,
                target=target,
                ports=ports,
                confirm=True,
                expected_scope=unlocked.snapshot()["scope_history"][-1]["scope_sha256"],
            )
            try:
                rc = run_adapter(args, unlocked)
                say(
                    "Guarded check finished, status " + str(rc),
                    style="green" if rc == 0 else "yellow",
                )
            except (OSError, ValueError, RuntimeError) as exc:
                say("STOP / REVIEW: " + redact(str(exc)), style="red")

        shell(notebook, shutil.which("soffice") or "soffice", guarded_operation=guarded)
    return 0
