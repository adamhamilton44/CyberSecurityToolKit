# Engagement usability validation

Validated on Kali Linux x86-64 on 29 October 2026, in an isolated feature
checkout. The installed main checkout and real engagement records were not changed.

- 15 questionnaire/usability regressions cover numbered readable choices,
  multiple selections, invalid numbers/dates/time zones, per-answer checkpoints,
  pause/resume, failed writes, invalid completed forms, visible saved identities,
  crash recovery without duplicate creation, safe offline defaults, non-overwrite,
  malformed/duplicate/symlink JSON, numbered selection, explicit activation,
  changed scope during review and a complete guided questionnaire.
- The full repository suite passed 178 tests, including the 15 usability tests,
  policy/source-IP/DNS/redirect/expiry regressions, install/update/uninstall
  recovery and public interfaces. Notebook/storage passed 30 tests, report
  generation 10, reporting CLI 9, and AI 36: 263 automated tests in total.
- Reporting storage adds a traverse-only ancestor regression. Ancestors use
  O_PATH with O_NOFOLLOW; the notebook leaf still requires owner-only 0700 and
  regular files require 0600. This supports private temporary hierarchies without
  weakening symlink or notebook ownership checks.
- Both maintained engagement/reporting programs and the AI binary are rebuilt
  from source. The offline JSON template is included in the manager and AI
  packages. Build caches are isolated to avoid concurrent-build interference.
- The packaged questionnaire is exercised through every question in a terminal,
  followed by saved-ID verification, numbered selection, explicit activation,
  pause/resume, offline template export and JSON import. No target is contacted.
- A Bash menu harness exercises actual menu definitions and the packaged helper,
  without root launcher/integrity startup. It verifies OSINT → Payloads → Post
  Exploit → ETC → Defense order, numbered review/selection/reporting, and offline
  export without typing an ID or running a target tool.
- Existing packaged reporting tests verify encrypted capture with logging off,
  denied fixture targets, Word/PDF draft/final generation, artifact hashes and
  withheld internal notes. The rebuilt AI TUI launches/exits without contacting
  a provider. UPX, shell syntax, ShellCheck and source checks are run.

Questionnaires/offline forms contain private plaintext permission metadata.
They are distinct from encrypted evidence notebooks; neither grants authority
without normal policy validation and explicit activation. Existing immutable
scope revisions and the mandatory questionnaire fingerprint are unchanged.

Help, man page, README, completion, guides, build inputs, source/binaries,
CI's relocated test paths and the reviewed release manifest are synchronized.
Installer/update/uninstall behavior is unchanged: no new dependency, service or
network action is added, and the entire Engagements tree (including .drafts) is
retained in private backups and across uninstall. Root-owned installed interfaces
and runtime hashes must be synchronized when deploying the reviewed change.
