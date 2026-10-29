# Reporting integration validation

Validated on Kali Linux x86-64, 28 October 2026, on the separate
`feature/engagement-reporting` checkout. Installed main was not changed.

## Component checks

- 29 notebook/storage tests: authenticated encryption, fixed KDF costs,
  wrong passwords, altered headers/payloads, private permissions,
  symlink/hard-link rejection, atomic failures, concurrent writers, key rotation,
  redaction, evidence review, stale drafts, retention and deletion.
- 10 report tests, including real Word/PDF conversion, editable document
  structure, internal-note withholding, changed report hashes, render/timeout
  cleanup, failed export registration, and duplicate-finding review integrity.
- 9 CLI tests: setup/status/questions, private password prompting, refusal of
  echo fallback or password arguments, capture with logging off, interrupted
  activity handling, guard binding and guarded-menu dispatch.
- 10 integrated adapter tests use real scope policy and encrypted notebooks with
  substituted transports: missing/wrong notebook, changed scope, expiry/pause
  during a check, denied targets, failed writes before connection, result
  allowlisting, query/secret exclusion, and capture with diagnostic logging off.
- 19 scope regressions cover DNS, exclusions, pinned destinations, redirects,
  policy expiry, URL normalization and legacy-dispatch blocking.
- Public-interface tests cover help, man rendering, Bash/Zsh completion and
  existing class routes, including the added `--report` option.

The complete repository suite passed 163 tests, including install/update/
uninstall recovery. The unchanged AI component passed 36 tests. Together with
the 48 notebook/report/CLI tests, 247 automated tests passed. The 10 adapter
and 19 scope tests above are included in the repository total. These
use local fixtures; they do not install packages or contact assessment targets.

## Packaged workflow

Both `Etc_engagement` and `cstk-reporting` are rebuilt with PyInstaller one-file
packaging and `upx -9`. Build metadata is in BUILD_VERSIONS.json. The runtime
includes its unchanged scope questionnaire and python-docx template resources.
UPX integrity and Python/shell/import checks are required before release.

Interactive private-terminal smoke tests cover passphrase unlock, denied
fixture operations, encrypted note persistence with logging off, and actual
Word/PDF export. The integrated test also launches a guarded attempt inside the
reporting session without prior selection, verifies draft hashes, finalizes the
reviewed fixture draft, verifies final hashes, and checks that internal note
content and passphrases are withheld. Only fictional fixture data is used.

The report layout is unchanged from the approved six-page fictional sample;
its Word pages and exported PDF were visually checked during prototype QA.
No real client notes, keys or reports are included in the branch.

## Deployment boundaries

Automatic capture covers the two existing guarded TCP/HTTP adapters. Unsupported
legacy tools remain blocked in engagement mode. Existing private audit/run files
and imported source files retain their own storage policies; notebook encryption
does not encrypt them. Exports deliberately contain plaintext client information.

No root installer, runtime synchronization or installed `sudo cstk` session was
run from this feature checkout. Deployment must generate the local root-owned
runtime manifest through the existing installer/synchronization path. That check
and the user's end-to-end terminal acceptance remain separate from this isolated
validation. Notes are retained across update/uninstall and report finalization.

These checks are regression evidence, not independent security certification.

## 29 October engagement usability update

The engagement helper now has recoverable questionnaires and offline JSON forms.
Reporting storage also supports non-listable traversable ancestors while retaining
O_NOFOLLOW, owner-private leaf and file checks. The added regression brings the
notebook/storage suite to 30 tests. See the shared engagement component
`../cstk_ai/ENGAGEMENT_VALIDATION.md` for the current integration checks.
