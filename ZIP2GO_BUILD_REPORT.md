# Zip2Go portable assessment edition

The archive at `scripts/lib/CSTK_Zip2Go.zip` now contains the agreed portable
assessment edition. It extracts into one `CSTK_2Go/` directory. The original
password-protected archive was backed up outside this Git checkout at
`../zip2go-backup/CSTK_Zip2Go.original.zip`; its original listing is stored beside
it. No old archive executables were run. Current and synced launcher references
did not yield a working literal ZIP password. A readable previous README was
located in `/home/adam/Documents/Github/CSTK_bin_files/CSTK_Zip2Go/README.md`.
The supplied identification of opaque enumeration assets was recorded: LinPEAS,
LES, and Unix exploit-suggester inputs. Those legacy assets were not imported
into this replacement assessment edition.

## Delivered contents

- Eighteen executable shell entry points: visible baseline runner, system metadata,
  local network metadata, fixed-path permission review, selected security policy
  review, explicitly scoped directory metadata, selected-file HTTP service,
  optional Web/TLS check, checksum verification, illustrative user-agent output, and ZIP/TAR helpers. A
  separate files-of-interest entry point provides scoped configuration/script
  metadata without copying file contents.
- Eighteen optional Linux x86-64 launchers built using `shc -r -f`, statically linked
  with musl. Generated launcher C sources are included for review/rebuild.
- Shared report helpers and five Python utilities. The Web/TLS implementation is
  copied from the maintained CSTK checker at build time rather than maintained
  as a separate drifting source copy.
- README with per-tool purpose, permissions, dependencies, traffic/host activity,
  report sensitivity, examples, exit behavior, and portability limits.
- SHA256SUMS, BUILD.json, project MIT license, shc/GPL notices and full GPL text,
  and musl license notices. The manifest covers every packaged file except itself.

The ZIP currently contains 77 files and is approximately 959 KiB, compared with
the original approximately 86 MiB archive. It remains on the existing Git LFS
path. The export command and output location are unchanged; its label explains
the assessment edition. An undefined banner-function call in that export path
was fixed, and the unnecessary five-second export delay was removed.

## Runtime design

No install, CSTK wrapper, root gate, dependency download, background daemon,
persistence, or automatic upload is required. `run_me.sh` performs four local
metadata checks sequentially in the foreground. Network checks describe local
interfaces/routes/listeners without initiating scans or DNS lookups. Reports
record missing commands, permission limits, timeouts, and optional incomplete
sections. They do not assert that the host is secure.

Outputs default to the extracted kit's `reports/` directory; `--output` supports
read-only media and a user-selected writable destination. Unique report
directories are mode 700, files mode 600. Local captured commands have execution
and output limits. The selected-directory inventory is capped at 200 entries and
two levels and traverses directories using no-follow file descriptors.

The separate HTTP helper serves only explicitly selected regular files, rejects
symlinks, traversal and unselected paths, and permits neither directory listings
nor uploads. Defaults are loopback, five-minute lifetime, and 20 successful
GET/HEAD requests. Request I/O and total listener lifetime are bounded, including
an incomplete-header client. It runs visibly and closes its socket/descriptors
on completion. It offers plaintext HTTP; sensitive transfers need an approved
encrypted transport.

The Web/TLS adapter requires an explicit URL and directs output to the selected
portable location, overriding inherited CSTK output/logging configuration. It is
not part of the default runner.

## Validation

Twenty-eight archive-specific tests pass:

1. Every packaged checksum and exact maintained-checker source matches.
2. All shell entry points and all compiled launchers accept help from elsewhere.
3. The default runner and a compiled check work as an ordinary account inside an
   isolated filesystem/network namespace; report permissions are private.
4. Read-only toolkit operation with separate output works; output symlinks fail.
5. Directory inventory honors entry limits and does not read contents or follow
   a symlink outside its scope.
6. Manifest verification detects a modified packaged file.
7. The HTTP service rejects listing, unknown, traversal and query-bearing paths;
   one approved download succeeds and the request limit closes the service.
8. Explicit file symlinks are refused by the HTTP service.
9. The Web/TLS adapter works against a local HTTP fixture and does not write to
   inherited CSTK locations or create the user's normal CSTK data tree.
10. PATH and symlink invocation work.
11. A minimal command environment produces explicit skips rather than failures.
12. Server lifetime terminates an incomplete HTTP request.
13. Local example user-agent output honors count bounds.
14. ZIP inspection/extraction preserves contents and refuses overwrites.
15. TAR extraction supports conventional root-directory members.
16. Archive traversal, links, and excess member counts are rejected before output.
17. Files-of-interest filtering reports only scoped configuration/script metadata,
    never file contents.
18. VM detection remains informational and does not alter other tools.
19. Local wordlist generation deduplicates results and refuses overwrites.
20. Plain Base64/hex roundtrips work without following output symlinks.
21. A mocked ping sweep probes only the explicit small scope and rejects large scopes.
22. A mocked ssh-keygen verifies that only a new keypair directory is created;
    existing authorized_keys remains untouched and no passphrase is passed in argv.
23. Helper inputs reject symlinks.
24. Maximum-size raw data can be encoded and decoded within the declared limits.

Bash syntax, ShellCheck at warning severity, ZIP CRCs, and whitespace checks pass.
The combined regression suite passed all 63 tests after the enumeration additions, including
installation/uninstallation, key provisioning, and the main Web/TLS tool.
The release builder uses an explicit file allowlist, so maintainer reports,
caches, and unrelated files under the source directory are excluded.

## Rebuild and limits

Maintainer sources live in `tools/zip2go/`; rebuild with
`python3 tools/build_zip2go.py`. This Linux x86-64 build uses shc, musl-gcc, strip,
and the installed musl/GPL license texts. It stages an allowlisted package in a
temporary directory, builds launchers, hashes final contents, and atomically
replaces the ZIP. No private key or archive password is bundled.

The compiled launchers still invoke `/bin/bash` and need the bundled helpers and
external commands. They target Linux x86-64; the shell sources are the fallback
for other architectures. A source-only ARM64 or BusyBox/minimal distribution
may need its documented dependencies; missing optional sections are reported.
This is not a claim of universal Linux compatibility. ARM64/BusyBox full-kit
execution and production file-transfer traffic were not tested on real devices.
Archive checksums are integrity aids, not authenticated publisher signatures.
Nothing has been committed or pushed.

## Additional utility scope

The new files-of-interest command is a metadata filter over an explicitly chosen
directory. It does not restore the older collection tool. The user-agent helper
prints illustrative strings without sending requests. ZIP/TAR operations are
capped at 30 seconds, 1000 members and 100 MiB. Extraction refuses existing
destinations, links, devices, duplicate/traversal paths and encrypted ZIP members;
files are non-executable and nothing is run. Automatic exploitation and credential/log-manipulation programs remain outside
this edition; reviewed enumeration profiles are now included below.

## Five additional adapted helpers

`sweeper.sh`, `modern_wordlist_creater.sh`, `HideInfo.sh`, `am_i_on_a_vm.sh`, and
`make_ssh_keys.sh` now have source and compiled entry points. They remain explicit
commands outside the default runner. The sweep accepts only an explicit IPv4
/24-or-smaller scope and sends one bounded ping per host. Wordlist transformations
are local and capped. HideInfo is plainly labeled Base64/hex conversion, without
disguised containers. VM observations do not change execution behavior.

The original SSH helper generated an access-installation payload that deleted
`.ssh` and applied immutable flags; that behavior was not ported. Its replacement
only invokes ssh-keygen in a fresh private directory, with interactive passphrase
entry, and never edits authorized_keys. The key-generation test uses a subprocess
double; no remote authentication or persistent access was attempted. Sweep tests
also use a command double; no external subnet was scanned.

## Reviewed enumeration profiles

Added `enumeration.sh` with pinned LES, a custom 11-module LinPEAS build, and
Unix Priv Check stable 1_x standard mode. The wrapper accepts a fixed tool choice,
output directory and time limit. It verifies source hashes and never forwards
arbitrary upstream flags. It records raw evidence and a JSON assessment with
exact scope/omissions and incomplete statuses; no exploitability or clean-host
verdict is inferred from a zero exit code.

LinPEAS uses the upstream builder at commit
`80cb747d062f63cffe225f57ef7fe15b79c05491`, with 11 module IDs in PROFILES.json and
network-scanning code omitted at build time. GTFOBins classification data is
pinned to `acd524623f9c406acedd2754ebd9c2431f3675ad`. Runtime `-n` disables the
upstream hostname lookup; `-N -L -z 1` and the selected check list are fixed.
Upstream FAST=1 remains in effect, so the unknown SUID/SGID execution branches
are not enabled. Secret-regex, account guessing and cloud modules are absent.

LES uses commit `bde09673eb5577f13030637d2c8a6a8ec98cddc8` without exploit-download
flags. Unix Priv Check uses `00e0d54c611a498ad6121ea03df2b88c8d7a80fb`, with the
UPC020/UPC021 database login probes omitted and explicitly marked NOT TESTED in
its output. The full diff and provenance hashes are packaged alongside licenses.
The archive README documents source rebuild and profile limitations.

Four additional tests cover source tamper/unknown-option refusal, LES candidate
output for synthetic kernel 4.4.0, honest timeout/incomplete metadata, and an
actual Unix Priv Check positive/negative fixture. That fixture creates an inert
world-writable crontab in an isolated read-only filesystem, detects its permission
warning, then changes the fixture to mode 644 and verifies the warning disappears.
Its contents are never scheduled/executed or modified by the scanner. Traps for
psql, curl, wget, su, strace and ldd remain uncalled during that test. These tests
verify behavior and evidence, not a successful exploit or an EDR alert.

## Follow-up evidence audit

The enumeration runner now removes exported Bash functions from its child
environment and avoids masking a report-open error with a subsequent chmod.
The shared report capture checks its output pipeline and marks a 64 KiB cap
as partial even when the producing command exits successfully. A regression
fixture exercises that successful-but-truncated case.

The packaged README now distinguishes observed conditions, heuristic candidates,
reachability and absent responses. Firewall/IDS/antivirus effectiveness remains
unvalidated without scoped stimuli and correlated defender telemetry; no clean
bill of health is inferred. No exploit or elevation was attempted in this pass.

Rebuilt archive: all 64 repository tests passed (45.489 seconds), including
manifest coverage, pinned sources, isolated fixtures and compiled entry points.
