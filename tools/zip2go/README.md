# CSTK Zip2Go — portable assessment kit

Extract the entire `CSTK_2Go` directory and keep its contents together. Nothing
is installed. No CSTK launcher, wrapper variables, root account, or package
manager is required. Checks use your current account; inaccessible sections are
marked partial or skipped instead of requesting elevation.

```bash
unzip CSTK_Zip2Go.zip
cd CSTK_2Go
bash verify.sh
bash run_me.sh --output "$HOME/cstk-reports"
```

`run_me.sh` runs four local metadata checks sequentially in the foreground and
prints each step. Reports have unique names, directories use mode 700, and files
use mode 600. Permission limits, absent commands, and timeouts are recorded in
individual reports. A completed report is not a declaration that the host is
secure. The runner does not start a server or run the optional Web/TLS check.
You can interrupt it with Ctrl+C; partial results remain available.

## Tools, privileges, and operational impact

| Entry point | Purpose and output | Useful permissions / dependencies | Network and observable activity |
| --- | --- | --- | --- |
| `run_me.sh` | Run system, network, permission, and configuration checks; retain individual reports and a summary | Ordinary account, Bash, base utilities; optional commands below | No tool-initiated probes/connections. Starts local processes and writes reports; normal host monitoring may record this |
| `system_info.sh` | OS/kernel, account/groups, uptime, memory, local filesystem capacity, process names, virtualization metadata | Ordinary account; uname, id, uptime, df, free, ps; systemd-detect-virt optional | Local reads only. Process arguments and environment variables are excluded. Filesystem reads may update access times |
| `network_info.sh` | Local addresses, routes, numeric listener list, resolver nameservers | Ordinary account; ip and ss (iproute2), awk | No scans or DNS lookups. Restricted network namespaces and socket visibility can limit results |
| `permissions_audit.sh` | Ownership and modes of named account/configuration files and temporary directories | Ordinary account; stat. Root may see more metadata, but is not requested | Fixed local metadata checks. Does not read shadow contents, private keys, or recursively scan home directories |
| `security_config.sh` | Selected read-only kernel settings, selected SSH directives, SELinux/AppArmor state, service names | Ordinary account; sysctl, awk; getenforce, aa-status, systemctl optional. Some sections need additional privilege to be complete | Local reads and possible IPC to the service manager; may be logged. SSH Include/Match/default evaluation is deliberately outside this static review |
| `file_inventory.sh --path DIR` | JSON-line metadata for one selected directory, at most 200 entries and two levels | Read/search access to selected directory; Python 3 | Local directory reads only. Does not follow symlink entries, read file contents, or search outside the selected directory. Ordering is filesystem-dependent; reports disclose limits |
| `serve_files.sh --file FILE` | Download only individually selected files over HTTP, with a lifetime and request limit | Read permission on each selected regular file; Python 3; permission to bind the chosen local address and unprivileged port | Explicit listener and inbound transfers; plaintext, without authentication. Request activity is visible in the foreground. Never started automatically |
| `web_tls_check.sh URL` | Maintained CSTK Web/TLS checker: headers, cookies, certificate and protocol observations, local findings report | Ordinary account; Bash, curl; OpenSSL and timeout enable additional TLS checks | Active GET with a small Range request, OPTIONS, and bounded TLS handshakes to the supplied target; visible to the target and network controls. Redirects are not followed |
| `files_of_interest.sh --path DIR` | Scoped configuration/script filename and permission metadata; no file contents | Ordinary account; Python 3; read/search access to selected directory | Local only; same two-level/200-entry examination limit as inventory. This is not the older credential-collection helper |
| `random_user_agent.sh` | Print 1..20 illustrative user-agent strings | Ordinary account; Python 3 | Local stdout only; no requests, proxy setup, or browser changes. Example browser versions are not a current-browser database |
| `archive_helper.sh` | List ZIP/TAR member metadata or extract into a new directory | Ordinary account; Python 3 and timeout; read input and write destination parent | Local reads/writes only. No password recovery or archive-content execution |
| `verify.sh` | Compare packaged files against `SHA256SUMS` | Read permission; sha256sum | Local file reads only. A checksum detects changes; it is not a publisher signature |

Local commands are limited to eight seconds plus a two-second termination grace,
and each captured command contributes at most 64 KiB to its report. Missing
`timeout` causes optional local command sections to be skipped rather than run
without a time bound. Optional command failures do not abort an entire report;
review `[SKIP]` and `[PARTIAL]` lines. Output I/O failures stop the script.
The runner returns 1 if a child fails, 0 if all report steps finish. A standalone
report can return 0 with partial sections; read its completeness markers.

## Run from another directory

```bash
cd /tmp
bash /path/to/CSTK_2Go/system_info.sh --output "$HOME/cstk-reports"
/path/to/CSTK_2Go/bin/linux-x86_64/system_info --output "$HOME/cstk-reports"
```

Keep `lib/` next to the root scripts and keep binaries inside `bin/linux-x86_64/`.
Absolute paths, PATH invocation, and symlinks are supported where `readlink -f`
is available. Default output is `reports/` inside the extracted kit; use
`--output` on read-only media or wherever that directory is not writable.
Paths containing spaces are supported. Executable bits may need `chmod +x`
after extraction on some filesystems. A `noexec` mount prevents binary execution;
use the shell source with `bash /path/to/script.sh` when permitted.

## Explicit file movement

Select only files you intend the receiver to download. The service defaults to
IPv4 loopback and port 8765. For another machine to reach it, explicitly choose
an address configured on your machine and an allowed port:

```bash
bash serve_files.sh --file ./approved-report.zip --bind 192.0.2.10 --port 8765 --duration 120
```

Replace the example address with your actual local address. This is an
unprivileged, foreground download service. It provides no directory listing,
uploads, shell access, or automatic discovery. Unknown paths, traversal paths,
query-bearing requests, and unselected files are rejected. Final file symlinks
and special devices are refused. Selected files must have unique basenames;
there can be at most 20 files, each up to 100 MiB. Files remain open read-only
while serving; avoid modifying them during the transfer.

Default limits are 300 seconds and 20 successful GET/HEAD requests. Options are
`--duration 1..3600` and `--max-downloads 1..100`. Incoming request I/O has a
five-second timeout. Bind only to the intended interface. Use an authenticated,
encrypted transport such as your organization's approved SSH/SFTP workflow for
sensitive reports; this helper is plain HTTP. Ctrl+C stops it and closes the
listener and file descriptors. No persistent service or automatic firewall rule
is created.

## Reports and handling

Reports include host details, account/group names, addresses, service names, and
selected paths. Treat them as assessment evidence. They are saved locally;
there is no telemetry, automatic upload, or background daemon. Shell history,
process/accounting logs, service-manager IPC, filesystem access times, and host
monitoring can still record ordinary execution. There is no claim of invisibility.

To package a selected report directory with your system's ZIP utility:

```bash
zip -r assessment-reports.zip /path/to/selected-report-directory
```

The ZIP output itself is not encrypted. Follow your team's evidence-handling
policy. Deleting the extracted kit and chosen report directory removes the files
this kit created; it does not erase OS logs or guarantee secure deletion.

## Linux portability and compiled launchers

The source entry points use Bash and normal Linux utilities. Alpine/minimal
containers may lack Bash, Python, timeout, iproute2, or procps; no dependency is
installed automatically. macOS, Windows, Android, and Bash-free systems are not
certified targets. Command availability and permissions are reported honestly.

The optional `bin/linux-x86_64/` launchers are built with `shc -r -f` and a static
musl C runtime. They still invoke `/bin/bash` and the bundled readable helpers,
and still need each tool's external commands. They are not standalone native
implementations and do not run on ARM64. Use the shell source on ARM64, or rebuild
launchers on that architecture. The release includes the generated launcher C
files in `build/generated/` and the relevant license text; sources remain the
portable, reviewable fallback. Compilation is for convenient entry points,
not a confidentiality guarantee.

The kit does not bundle the old password/browser collection, password attacks,
log cleanup, exploit, persistence, or arbitrary-execution programs. This release
is a replacement assessment edition, not a promise of feature parity with the
older post-exploitation archive. The ZIP is intentionally unencrypted so the
README, sources, and manifest can be reviewed before running anything.

## Maintainer rebuild

In the CSTK repository, run `python3 tools/build_zip2go.py`. It packages these
sources, takes the current `scripts/bin/web_tls_security_assessment` source,
builds optional launchers with shc/musl-gcc, writes checksums and build metadata,
and atomically replaces `scripts/lib/CSTK_Zip2Go.zip`. Rebuild again after changing
any source; do not edit generated archives manually. See the repository's
`ZIP2GO_BUILD_REPORT.md` for verification and known limits.

## Additional local utilities

```bash
bash random_user_agent.sh --count 3
bash archive_helper.sh list ./sample.zip
bash archive_helper.sh extract ./sample.tar.gz "$HOME/new-extraction-directory"
```

Archive operations have a 30-second execution bound, a 100 MiB input/output cap,
and at most 1000 members. Extraction requires a previously nonexistent destination
under an existing parent. Links, special files, path traversal, duplicate paths,
and encrypted ZIP members are refused. Extracted files are mode 600, directories
700; execute bits are not restored. Nothing from an archive is executed. ZIP and
Python-supported TAR compression formats are accepted; RAR and 7z are not.
Extraction failure removes staging output; forceful termination can require
manual removal of a `cstk-extract-*` temporary directory beside the destination.

The files-of-interest filter selects directories and `.conf`, `.cfg`, `.ini`,
`.service`, `.timer`, `.sh`, `.py`, `.yaml`, `.yml`, and `.json` entries. Its limit
applies to all examined entries, not just matches. It never reads their contents.

## Additional explicit helpers

| Entry point | Behavior | Permissions/dependencies | Activity |
| --- | --- | --- | --- |
| `sweeper.sh --network IPv4_CIDR` | Sequential ICMP reachability checks for one explicit /24-or-smaller network; at most 256 addresses | Python 3, Linux-compatible ping; ping needs its normal local ICMP permissions/capabilities | Active, observable network probes, one per host; never called by the default runner. A missing reply does not prove a host is down |
| `modern_wordlist_creater.sh --input FILE --output NEW_FILE` | Deduplicated case/character variants with optional repeated `--suffix TEXT` | Python 3; read input/write output | Local only. At most 1000 input lines, 128 characters per line, 50000 variants. No guessing against accounts or services |
| `HideInfo.sh {encode\|decode} --format {base64\|hex} --input FILE --output NEW_FILE` | Plainly labeled Base64 or hex conversion | Python 3; read input/write output | Local only, 1 MiB raw/decoded data cap (encoded input up to 2 MiB plus newline); encoding offers no secrecy. No disguised GPG headers or hidden storage |
| `am_i_on_a_vm.sh` | Informational DMI, CPU, and optional systemd virtualization observations | Python 3, optional systemd-detect-virt | Local reads; restricted data is reported. Never exits early or changes other tools based on virtualization signals |
| `make_ssh_keys.sh --directory NEW_DIRECTORY` | Ed25519 keypair generation, with interactive passphrase prompts from ssh-keygen | Python 3 and ssh-keygen; writable parent directory | Local key creation only; existing directories are refused. No authorized_keys edits, .ssh deletion, immutable flags, or access-installation payload |

These helpers also have compiled entry points with the same names (without
`.sh`) under `bin/linux-x86_64/`. They are explicit actions, not additions to the
default runner. Python 3 is needed by each. Output files are created exclusively
with mode 600; existing files/symlinks are refused. Optional sweep `--output`
requires a new filename; interruption retains partial results. SSH keys use a
new mode-700 directory; the private key is mode 600, public key mode 644. The
operator supplies the passphrase interactively; key generation is cancelled
after two minutes if not finished. Neither private keys nor passphrases are
printed in reports. Keep key material separate from shared assessment archives.

## Privilege-escalation exposure enumeration

Enumeration identifies conditions and candidates; it does not establish that an
exploit succeeds. The archive includes reviewed profiles of these upstream tools:

```bash
bash enumeration.sh --tool linpeas --output "$HOME/cstk-reports" --seconds 120
bash enumeration.sh --tool les --output "$HOME/cstk-reports" --seconds 120
bash enumeration.sh --tool upc --output "$HOME/cstk-reports" --seconds 120
```

| Profile | Actual coverage | Explicit omissions / interpretation |
| --- | --- | --- |
| LinPEAS | Custom upstream build with 11 modules: OS/glibc observations, sudo version, PATH, SUID, SGID, ACLs, capabilities, library configuration, profile/init paths and writable root executables | No cloud/credential regex modules, account guessing, network discovery or hostname upload. Fixed `-n -N -L -z 1 -o system_information,interesting_perms_files` arguments; default FAST=1 avoids unknown SUID/SGID execution via strace/ldd. This is a declared subset, not the complete upstream suite |
| LES | Pinned Linux Exploit Suggester, default local kernel/package/prerequisite heuristic matching | No fetch-source/fetch-binary options or exploit execution. A version match may be a false positive because distributions backport fixes; no match is not evidence that every relevant vulnerability was tested |
| Unix Priv Check | Pinned stable 1_x standard permission/configuration audit, including exposed configuration permissions and trust-file metadata | Two upstream PostgreSQL login probes, UPC020/UPC021, are explicitly marked NOT TESTED in the output. Detailed binary/ldd analysis is not run. Local SSH-agent fingerprint queries may occur when agents are visible; no keys are installed or removed |

These are separate explicit commands, not automatic default-runner steps. They
can take substantially longer than baseline checks and read many filesystem
paths. Root is not required; restricted accounts necessarily see less. Missing
utilities, access denials, time limits and stale vulnerability data can affect
coverage. Raw output may contain account names, paths, configuration lines or
process details; protect it as assessment evidence.

Each run creates a private directory with `upstream-output.txt` and
`assessment.json`. The JSON records exact arguments, source hash/commit, selected
checks, omissions, timestamps, exit code and completion status. Raw upstream
output is preserved rather than converted into a green PASS. Status
`completed_unverified` means only that the process returned zero.
`incomplete_timeout`, `incomplete_output_limit`, and tool/runner errors retain
partial evidence. The default is 120 seconds, maximum 600, and a 16 MiB output
cap. Treat raw output as data; do not execute commands copied from it blindly.

These profiles issue no intentional outbound network probes, fetches, or
uploads. Normal local account/name resolution can still contact organizational
identity services, depending on host configuration. Extensive local reads and
process execution may be observable to EDR/auditd. A network IDS is not guaranteed
to see local-only enumeration; validating alerts requires correlating a recorded
run with actual endpoint or network telemetry. No alert test is implied by a
vulnerability finding.

The wrapper accepts only the documented arguments. Invoking a vendored script
directly with other upstream flags is outside the reviewed profile. Pinned
source and license notices are under `vendor/`; `PROFILES.json` contains exact
provenance and module IDs, and `profile.patch` records the UPC changes. LES and
LinPEAS remain candidate finders; they are not automatic exploitation programs.

Upstream references:

- [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/80cb747d062f63cffe225f57ef7fe15b79c05491/linPEAS)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester/tree/bde09673eb5577f13030637d2c8a6a8ec98cddc8)
- [Unix Priv Check 1_x](https://github.com/pentestmonkey/unix-privesc-check/tree/00e0d54c611a498ad6121ea03df2b88c8d7a80fb)

### Rebuilding the LinPEAS profile

Check out PEASS-ng commit `80cb747d062f63cffe225f57ef7fe15b79c05491`, with
`linPEAS/` and `build_lists/` present. Its Python builder requires requests and
PyYAML. Pin the builder's GTFOBins archive URL to
`https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/acd524623f9c406acedd2754ebd9c2431f3675ad`.
From `linPEAS/`, invoke the upstream builder with `--no-network-scanning`,
`--include` containing the comma-separated module IDs in `vendor/PROFILES.json`,
and an explicit `--output` path. Build in a disposable workspace; this step
fetches GTFOBins classification data. Copy the generated shell source into
`vendor/linpeas-enumeration.sh`, review behavior, update its profile hash, rerun
tests and rebuild the ZIP. The ordinary ZIP builder uses the pinned local files
and performs no vendor update/download. Preserve upstream license notices; this
is an aggregate containing components with their own licenses.

### Concrete validation without exploitation

In a disposable VM, an inert `/etc/crontab` fixture with mode 666 should produce
a writable-configuration warning. Change only the fixture mode to 644 and repeat;
that specific warning should disappear. The automated tests use this exact
positive/negative comparison inside an isolated filesystem. They never schedule
a job or attempt privilege escalation. Such a fixture tests a permission check;
read-only mounts, ACLs and other controls still affect practical exploitability.

For detection validation, correlate the recorded start/end timestamps, hashes and
commands with actual EDR/auditd process/file events. Record the result as alert
observed, no alert observed, or telemetry unavailable. A scanner finding alone
does not establish that an IDS/EDR rule fired, and no alert alone does not prove a
system is safe. Network IDS coverage is a separate question for local-only reads.

## Evidence and detection validation

Use each result at its actual proof level:

| Evidence | Supported conclusion | Remaining validation |
| --- | --- | --- |
| Local configuration or permission observation | The named condition was visible to this account at this time | Applicability, effective configuration, compensating controls |
| LES or enumeration candidate | A heuristic matched; further review is warranted | Vendor backports, prerequisites, reachable attack path; no exploit was executed |
| No findings | These checks found nothing within their recorded scope | Missing privileges, skipped modules, new vulnerabilities, other attack paths |
| Reachability reply | The selected endpoint answered that probe | Firewall policy enforcement for other protocols, directions and identities |
| No reply | No reply was observed | Host availability, routing, rate limits and filtering cannot be distinguished |

This package does not validate IDS, antivirus or firewall effectiveness by itself.
For those controls, agree the test scope and time window with the assessment
coordinator, record expected events and correlate them with defender telemetry.
Use an isolated test host and approved harmless control samples or documented
vendor test events. Record target, account, UTC time, stimulus, expected policy,
observed response, sensor evidence, and cleanup. Separate **alert observed**,
**no alert observed**, and **telemetry unavailable**. Lack of an alert proves
neither successful evasion nor an uncompromised system. Do not mark a control
passed from command exit status alone.

Positive and negative local fixtures in the repository tests validate scanner
behavior without executing an exploit: an inert writable crontab is detected,
and its corrected permissions remove that warning. This is evidence of that
check's behavior, not evidence of root access or complete security coverage.
No finite collection of these tools can certify that a system cannot be exploited.
