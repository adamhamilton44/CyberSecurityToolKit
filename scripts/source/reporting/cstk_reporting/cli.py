"""Local CLI. Passphrases are prompted, never accepted in argv or environment."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import resource
import warnings
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__
from .adapters import import_web_tls_report
from .model import DISPOSITIONS, QUESTIONS, SEVERITIES
from .service import Notebook
from .storage import NotebookError, now

console = Console(highlight=False)


def say(value, style=None):
    console.print(str(value), style=style, markup=False)


def multiline(label):
    say(label + " (finish with a line containing only a period)", style="cyan")
    lines = []
    while True:
        line = input()
        if line == ".":
            break
        lines.append(line)
        if sum(map(len, lines)) > 24000:
            raise NotebookError("Note is too long.")
    return "\n".join(lines)


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise NotebookError("Select a regular JSON source file smaller than two MiB.")
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def passphrase(new=False):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass(
                "New notebook passphrase: " if new else "Notebook passphrase: "
            )
            if new and value != getpass.getpass("Confirm passphrase: "):
                raise NotebookError("Passphrases do not match.")
            return value
    except getpass.GetPassWarning as exc:
        raise NotebookError(
            "A private terminal is required for passphrase input."
        ) from exc


def ask_profile(notebook):
    profile = notebook.snapshot()["profile"]
    answers = {}
    say("Reporting questions do not change testing authorization.", style="yellow")
    for key, label, requirement in QUESTIONS:
        value = Prompt.ask(
            label + " [" + requirement + "]", default=str(profile.get(key, ""))
        )
        answers[key] = value
    notebook.set_profile(answers)
    say("Reporting answers saved encrypted.", style="green")


def status(notebook):
    state = notebook.snapshot()
    say("CSTK REPORTING NOTEBOOK", style="bold cyan")
    say(
        f"Engagement {state['engagement_id']} | {state['lifecycle']} | encrypted notebook available",
        style="green",
    )
    say(
        f"{len(state['notes'])} notes | {len(state['activities'])} activities | {len(state['findings'])} findings"
    )
    say("Optional diagnostic logging does not control this notebook.")
    errors = notebook.readiness()
    if errors:
        say("Finalization readiness:", style="yellow")
        for error in errors:
            say("- " + error)
    else:
        say(
            "Required reporting fields and finding dispositions are complete.",
            style="green",
        )


def review(notebook):
    state = notebook.snapshot()
    table = Table(title="Finding review")
    for field in ("Reference", "Status", "Severity", "Title"):
        table.add_column(field)
    for finding in state["findings"]:
        table.add_row(
            *[Text(str(finding[key])) for key in ("id", "status", "severity", "title")]
        )
    console.print(table)
    if not state["findings"]:
        return
    finding_id = Prompt.ask("Finding reference (blank returns)", default="")
    if not finding_id:
        return
    finding = next((f for f in state["findings"] if f["id"] == finding_id), None)
    if not finding:
        raise NotebookError("Finding not found.")
    say(finding["observation"])
    say("Evidence references: " + ", ".join(finding["evidence_ids"]))
    for note in state["notes"]:
        if note["id"] in finding["evidence_ids"]:
            say(note["title"] + "\n" + note["body"])
    disposition = Prompt.ask(
        "Disposition", choices=list(DISPOSITIONS), default=finding["status"]
    )
    reviewer = Prompt.ask("Your name")
    fields = {}
    if disposition == "confirmed":
        for field in (
            "title",
            "asset",
            "observation",
            "impact",
            "remediation",
            "validation",
            "severity_reason",
            "owner",
            "target_date",
            "references",
        ):
            fields[field] = Prompt.ask(
                field.replace("_", " ").capitalize(), default=finding.get(field, "")
            )
        fields["severity"] = Prompt.ask(
            "Reviewed severity", choices=list(SEVERITIES), default=finding["severity"]
        )
    else:
        fields["disposition_reason"] = Prompt.ask(
            "Disposition reason", default=finding.get("disposition_reason", "")
        )
        if disposition == "duplicate":
            fields["duplicate_of"] = Prompt.ask("Confirmed finding reference")
    notebook.review_finding(finding_id, disposition, reviewer, **fields)
    say("Review saved encrypted.", style="green")


def export_parent():
    path = Path(
        Prompt.ask("Private report output parent directory (mode 0700)")
    ).expanduser()
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    return path


def shell(notebook, soffice, guarded_operation=None):
    while True:
        say("\nCSTK REPORTING  |  encrypted notebook unlocked", style="bold cyan")
        say(
            "1 Reporting questions   2 Add note/evidence   3 Review findings   4 Add manual finding\n5 Import Web/TLS report  6 Readiness/status     7 Draft report      8 Finalize reviewed draft\n9 Revise/withdraw note   A Record manual activity   S Import newer scope snapshot\nN Browse encrypted notes   C Close interrupted activity   R Reopen finalized notebook   K Change passphrase   D Delete retained notes   X Exit"
        )
        if guarded_operation is not None:
            say(
                "T Guarded TCP check   W Guarded HTTP(S) check  | capture required",
                style="cyan",
            )
        action = Prompt.ask("Select").upper()
        try:
            if action in ("T", "W") and guarded_operation is not None:
                guarded_operation(action, notebook)
            elif action == "X":
                return
            elif action == "1":
                ask_profile(notebook)
            elif action == "2":
                title = Prompt.ask("Note title")
                asset = Prompt.ask("Asset", default="")
                kind = Prompt.ask(
                    "Note kind",
                    choices=["operator", "evidence", "limitation", "positive_control"],
                    default="operator",
                )
                include = (
                    Confirm.ask("Include this context in the report", default=False)
                    if kind != "evidence"
                    else False
                )
                say(
                    notebook.add_note(
                        title,
                        multiline("Note body"),
                        asset=asset,
                        kind=kind,
                        report_include=include,
                    ),
                    style="green",
                )
            elif action == "3":
                review(notebook)
            elif action == "4":
                title = Prompt.ask("Finding title")
                asset = Prompt.ask("Affected asset")
                observation = multiline("Observation")
                evidence = Prompt.ask("Evidence note references separated by commas")
                say(
                    notebook.add_finding(
                        title,
                        asset,
                        observation,
                        evidence_ids=[
                            x.strip() for x in evidence.split(",") if x.strip()
                        ],
                    ),
                    style="green",
                )
            elif action == "5":
                path = Path(
                    Prompt.ask("Selected Web/TLS report text file")
                ).expanduser()
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.stat().st_size > 1024 * 1024
                ):
                    raise NotebookError("Select a regular report smaller than one MiB.")
                target = Prompt.ask("Assessed target (reporting context only)")
                ids = import_web_tls_report(notebook, path.read_text(), target)
                say(
                    f"{len(ids)} candidates imported. Original selected file remains on disk; this command does not encrypt or delete that source file.",
                    style="yellow",
                )
            elif action == "6":
                status(notebook)
            elif action == "7":
                say(
                    "Exports contain decrypted client information. Use the approved delivery channel.",
                    style="yellow",
                )
                if not Confirm.ask(
                    "Create an unencrypted editable Word/PDF report bundle",
                    default=False,
                ):
                    continue
                parent = export_parent()
                record = notebook.export_draft(
                    parent / ("draft-" + now().replace(":", "-")), soffice=soffice
                )
                say("Review bundle: " + record["directory"])
                say("Candidate reference: " + record["id"], style="green")
            elif action == "8":
                errors = notebook.readiness()
                if errors:
                    for error in errors:
                        say(error, style="yellow")
                    continue
                candidate = Prompt.ask("Reviewed draft reference")
                reviewer = Prompt.ask("Final reviewer name")
                say(
                    "Read the Word and PDF before finalizing. Changes to source notes or exported files invalidate review.",
                    style="yellow",
                )
                if (
                    Prompt.ask("Type FINALIZE after reviewing the selected draft")
                    != "FINALIZE"
                ):
                    continue
                parent = export_parent()
                record = notebook.finalize(
                    candidate,
                    reviewer,
                    parent / ("final-" + now().replace(":", "-")),
                    soffice=soffice,
                )
                say("Final report: " + record["directory"], style="green")
                say(
                    "Encrypted notes retained; no testing authorization state was changed."
                )
            elif action == "9":
                for note in notebook.snapshot()["notes"]:
                    say(
                        note["id"]
                        + " "
                        + note["title"]
                        + (" [withdrawn]" if note["withdrawn"] else "")
                    )
                note_id = Prompt.ask("Note reference")
                operation = Prompt.ask(
                    "Operation", choices=["body", "include", "withdraw", "restore"]
                )
                kwargs = (
                    {"body": multiline("Revised body")}
                    if operation == "body"
                    else {"report_include": Confirm.ask("Include in report")}
                    if operation == "include"
                    else {"withdrawn": operation == "withdraw"}
                )
                notebook.update_note(note_id, **kwargs)
                say("Note updated encrypted.", style="green")
            elif action == "A":
                tool = Prompt.ask("Tool or manual test name")
                target = Prompt.ask("Assessed asset")
                outcome = Prompt.ask(
                    "Outcome", choices=["completed", "partial", "error", "skipped"]
                )
                summary = multiline("Concise activity summary and coverage limitations")
                record_id = notebook.start_activity(tool, target, origin="operator")
                notebook.finish_activity(record_id, outcome, summary)
                say(
                    "Manual activity saved. Times identify notebook capture, not independently verified execution.",
                    style="green",
                )
            elif action == "S":
                config, sha = read_json(
                    Path(
                        Prompt.ask("Selected newer scope revision JSON file")
                    ).expanduser()
                )
                revision = int(Prompt.ask("Revision number"))
                notebook.revise_scope_snapshot(config, revision, sha)
                say(
                    "New reporting snapshot saved; testing authorization was not changed.",
                    style="green",
                )
            elif action == "N":
                notes = notebook.snapshot()["notes"]
                for note in notes:
                    say(
                        note["id"]
                        + " "
                        + note["title"]
                        + (" [withdrawn]" if note["withdrawn"] else "")
                    )
                selected = Prompt.ask("Note reference (blank returns)", default="")
                if selected:
                    note = next((n for n in notes if n["id"] == selected), None)
                    if note is None:
                        raise NotebookError("Note not found.")
                    say(note["title"], style="cyan")
                    say(note["body"])
            elif action == "C":
                running = [
                    run
                    for run in notebook.snapshot()["activities"]
                    if run["outcome"] == "running"
                ]
                if not running:
                    say("No interrupted activities need a terminal outcome.")
                    continue
                for run in running:
                    say(run["id"] + " " + run["tool"] + " " + run["target"])
                record_id = Prompt.ask("Interrupted activity reference")
                outcome = Prompt.ask(
                    "Recorded outcome",
                    choices=["error", "partial", "skipped"],
                    default="error",
                )
                summary = multiline(
                    "Explain the interruption and any reviewed partial evidence"
                )
                notebook.finish_activity(record_id, outcome, summary)
                say(
                    "Interrupted capture closed with an explicit outcome.",
                    style="green",
                )
            elif action == "R":
                notebook.reopen(Prompt.ask("Reason for reopening"))
            elif action == "K":
                notebook.vault.rotate(passphrase(new=True))
                say("Passphrase and data key changed.", style="green")
            elif action == "D":
                say(
                    "Deletion cannot erase copies in backups, swap, or retained reports. Legal hold and report integrity are checked.",
                    style="yellow",
                )
                state = notebook.snapshot()
                say("Required confirmation: DELETE NOTES " + state["engagement_id"])
                confirmation = Prompt.ask("Confirmation")
                reason = Prompt.ask(
                    "Early-deletion override reason (blank honors retention)",
                    default="",
                )
                notebook.purge(confirmation, override_reason=reason)
                say(
                    "Notebook deleted. Non-sensitive deletion receipt retained.",
                    style="green",
                )
                return
            else:
                say("Choose a listed option.", style="yellow")
        except (NotebookError, OSError, ValueError) as error:
            say(str(error), style="red")


def main(argv=None):
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    parser = argparse.ArgumentParser(
        description="Encrypted engagement notebook and reports. No AI."
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--vault",
        type=Path,
        help="Private notebook directory (owned by you, mode 0700)",
    )
    parser.add_argument(
        "--soffice", help="Absolute LibreOffice executable used for PDF generation"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("questions", help="Show the reporting-only questionnaire")
    init = sub.add_parser(
        "init", help="Create an encrypted notebook from a selected scope revision"
    )
    init.add_argument(
        "--scope",
        type=Path,
        required=True,
        help="Selected CSTK scope revision JSON file",
    )
    init.add_argument("--revision", type=int, required=True)
    sub.add_parser(
        "shell", help="Unlock the notebook for note capture, review and reports"
    )
    sub.add_parser("status", help="Unlock and show readiness without changing content")
    args = parser.parse_args(argv)
    if args.command == "questions":
        for key, label, requirement in QUESTIONS:
            say(f"{key}: {label} [{requirement}]")
        return 0
    if not args.vault:
        parser.error("--vault is required")
    try:
        if args.command == "init":
            scope, sha = read_json(args.scope)
            with Notebook.create(
                args.vault, passphrase(new=True), scope, args.revision, sha
            ) as notebook:
                say(
                    "Encrypted notebook created. Record the passphrase separately; there is no recovery backdoor.",
                    style="green",
                )
                ask_profile(notebook)
        else:
            with Notebook.open(args.vault, passphrase()) as notebook:
                if args.command == "shell":
                    shell(notebook, args.soffice)
                else:
                    status(notebook)
        return 0
    except NotebookError as error:
        say(str(error), style="red")
        return 2
    except (OSError, ValueError, EOFError, KeyboardInterrupt):
        # Do not echo potentially sensitive source JSON, URLs, or exception payloads.
        say(
            "Operation did not complete. Check your input, passphrase, directory permissions, and selected source files.",
            style="red",
        )
        return 2
