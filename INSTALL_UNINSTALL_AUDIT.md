# CSTK install/uninstall audit

The installer and uninstaller now share a root-owned installation ledger and
isolated managed-tool directories. Existing uncommitted Web/TLS work was retained;
no synced `sources/` references were changed. The follow-up fixes, dependency review and live VM uninstall result are documented below.

## Problems corrected

| Finding | Correction |
| --- | --- |
| Uninstaller attempted to execute an empty package-lookup variable | Replaced with exact ownership records and explicit cleanup functions |
| Compressed-only man page was missed | Remove/restore the journaled `.1` and `.1.gz` paths independently; legacy cleanup removes both |
| Package dependencies were removed before Python cleanup | Remove managed Python environments and refresh Nmap first; remove system dependencies afterward |
| `pipx` was used without being installed | Include pipx and source-build prerequisites in dependency installation |
| Katana binary tested as a directory and installed outside the runtime PATH | Install into `/opt/cstk/bin` with a dedicated Go workspace/cache; retain legacy `/root/go/bin/katana` cleanup |
| MimiPenguin scripts were left in `/usr/local/bin` | Journal actual writes and restore/remove those exact destinations |
| Nrich native packages were treated as loose files | Journal package transactions, including dependency repair and partial failures; legacy native-package record supported |
| `make install` for shc could add untracked manual files | Install the built executable explicitly; legacy cleanup includes its manual path |
| Shell completion cleanup used unset variables and broad sed deletion | Record the actual account's rc path and remove only the exact inserted line; preserve later edits and remove empty installer-created rc files |
| Root completion used the invoking user's shell | Resolve root's shell independently |
| Existing system files could be overwritten permanently | Back up the specific file immediately before writing and restore it on uninstall |
| Dependency records omitted transitive dependencies | Compare package inventories around each install/update transaction, including a nonzero result |
| Failed install phases could still lead to a success message | Propagate failures from dependency, source-tool, interface, authentication, and permission phases |
| Failed removal destroyed recovery records | Keep the checkout and ledger on failure; permit retry after successful earlier cleanup steps |
| Removal could cascade into unrelated software | Check APT's simulated removal list; refuse untracked removals. RPM uses an erase dependency test and disables automatic dependency cleanup |
| Clone directory name triggered broad filesystem searching/renaming | Validate the actual checkout; use absolute paths regardless of its folder name |
| Minimal VMs lacked OpenSSL at key validation time | Bootstrap it with dependency accounting before provisioning |
| Kali no longer provides `p7zip-full` in the available package cache | Prefer its `7zip` replacement and retain the old name as a fallback |
| Optional large dataset download proceeded on empty input | Require an explicit yes |
| Updater would recreate old root pipx/Go environments and untracked shc manuals | Use the same managed environments, file-write helpers, and package transaction ledger |

## Artifact ownership

| Artifact | Install | Uninstall |
| --- | --- | --- |
| `/var/lib/cstk` | Private ownership ledger and backups | Removed after successful cleanup |
| `/etc/cstk/lib_decryption.key` | Silent verified provisioning, root:root 600 | Remove key and known provisioning scratch files; retain unrelated files in the directory |
| `/opt/cstk` | Dedicated pipx, Go, caches, app links, configuration/state | Remove the owned directory; refuse to claim an existing unrecorded directory |
| `/usr/local/bin/cstk`, `cstk_wrapper` | Journal originals before writes | Restore originals or remove installed files |
| `/usr/local/bin/shc`, `mongosh`, crypto library, MimiPenguin scripts | Journal actual writes; preserve independent pre-existing tools | Restore originals or remove only journaled destinations |
| CSTK manual | Journal both compressed and uncompressed destinations | Restore originals or remove installed files; refresh manual index |
| Shell completion | Record exact rc paths and inserted line | Remove that line while preserving other content |
| Vulscan | Record ownership before clone so partial clones are removable | Remove recorded clone and refresh Nmap database before removing Nmap |
| System packages | Inventory changes per transaction, including transitive dependencies | Purge recorded APT packages after simulation; retain pre-existing packages |
| Checkout, downloads, installer logs | Retained for retries and runtime | Remove checkout after other cleanup succeeds |
| `~/.local/share/cstk/*` | Private per-user runtime data | Preserve |

## Verification

- Actual installer and uninstaller run in Bubblewrap user/mount/network namespaces.
  Host filesystem and executable base are read-only; writable installation targets
  and the checkout are disposable fixtures. Network access is disabled.
- Lifecycle tests cover fresh install, reinstall, successful uninstall, preserving
  reports and later rc edits, restoring an existing wrapper, failed-install cleanup,
  removal failure/retry, newly created rc file retry, conflicting owned directories,
  refusal of untracked APT removals, and original-ledger legacy cleanup.
- A separate test uses real dpkg and apt-get with two local fixture `.deb` packages
  and a disposable package database. It checks dependency accounting, simulated
  removal, actual purge, and removal of the installed payloads without downloads.
- Key tests verify all five encrypted resources, private permissions, symlink and
  overwrite refusal, repeated provisioning, invalid existing keys, and ARM64 helper
  execution through QEMU where available.
- Read-only APT candidate inspection on this Kali 2026.3 WSL host found that
  `p7zip-full` had no candidate. After mapping it to `7zip`, a real
  `apt-get -s --no-remove install` of the effective dependency list succeeded
  against the existing package cache (110 unique names, three proposed new
  packages including one transitive dependency, no removals). This was a
  simulation on an already populated host, not a fresh-VM install.
- Bash syntax, ShellCheck at warning severity, and the existing Web/TLS regression
  suite are checked. Bubblewrap tests use doubles for remote repositories, builds,
  pipx, Go, and most package operations; they do not download the entire toolkit.

## Practical limits and release check

This is ownership-based uninstallation, not an OS snapshot rollback. System
package upgrades are not downgraded. Shared package-manager indexes/history,
system logs, service accounts, and arbitrary maintainer-script effects are not
fully reversed. Packages later required by unrelated software are retained with
an explicit failure instead of silently deleting that software. No global
`autoremove`, root-cache wipe, or filesystem-wide executable search is used.

Old manifests cannot identify historically unrecorded transitive dependencies or
cache files. Hard-killed package transactions can leave pending inventory files;
cleanup retains the ledger and reports that recovery is needed rather than
claiming all packages were accounted for. Do not delete `/var/lib/cstk` to bypass
that recovery check.

The later live VM test below validates the repaired older installation and its
uninstall. A fresh live install of the reduced dependency list is still needed
to validate its full upstream downloads, source builds and service behavior. DNF/YUM/Homebrew branches are statically checked,
not certified by live distribution tests. The ARM64 helper is exercised under
emulation, not a complete ARM64 installation. No claim of perfect OS restoration
or universal first-run success is made from offline tests.

## 2026-10-22: package journal locale regression

A fresh Kali VM exposed a mismatch: package snapshots used bytewise C sorting,
but `comm` inherited the desktop locale. A package could install successfully,
then fail its journal step with `comm: input is not in sorted order`. This bug
was in the transaction accounting added during the earlier lifecycle changes.

The comparison now explicitly uses `LC_ALL=C` with order validation. Deltas and
the combined ledger are staged privately; the ledger is replaced only after
successful comparison and sorting. An inventory pipeline failure is propagated
even when the caller has not enabled pipefail. A package command's own nonzero
status is preserved while newly installed dependencies are still recorded.

Verification added:

- Full installer/uninstaller roundtrip under `en_US.utf8`, preserving pre-existing
  package names containing punctuation, and forcing all five reported packages
  through installation: apache-users, apktool, argon2, aria2 and arjun.
- Another full roundtrip forces every dependency install invocation instead of
  taking the already-installed branch. Package managers are doubles here.
- Failed package transaction, failed inventory, and invalid snapshot tests verify
  status propagation, ledger preservation and refusal of unsafe cleanup.
- The UTF-8 regression was also run with the locale fix deliberately removed
  from a disposable checkout: it failed, confirming the regression is detected.
- Real dpkg/APT fixture installation and purge now run under `en_US.utf8`.
- Real APT simulation with an empty package database resolved 110 effective
  dependencies: 1,678 newly installed packages planned, zero removals. Full output
  is in `INSTALL_APT_FRESH_SIMULATION.log`. This used existing host Kali indexes;
  it does not verify current mirrors, download artifacts, or maintainer scripts.

Pending records from an already failed installation are intentionally preserved.
Do not delete `/var/lib/cstk` or its `packages.before.*` / `packages.after.*` files:
they contain evidence needed to recover the dependency ledger. The previous
implementation could append comparison output before reporting failure. A new
successful install does not certify that this older ledger is correct. Review
those records on the affected VM before permitting package removal.

Scope: this environment has working Bubblewrap, but Docker daemon access is
denied and passwordless sudo is unavailable. The lifecycle runs use disposable
filesystem mounts and offline command doubles for remote repositories, builds,
Go/pipx, and most package operations. Optional dataset downloads, all alternate
OS/package-manager branches, and a full live 1,678-package Kali deployment have
not been executed. Syntax/static checks and sandbox tests cannot guarantee that
every external command will succeed on another machine. A disposable Kali VM
roundtrip remains required for that broader release validation.

## Katana dependency review

The optional `Osint_enum` source at the maintainer reference tree invokes Katana
once (`-u URL -d 3`) and then GoSpider (`-s URL -d 2`). No dedicated Katana workflow
was found in the launcher. The shipped enumeration executable is compiled; this
review establishes the available source's usage, not binary/source equivalence.
Automatic Katana source builds were removed from installation and updates.
Existing optional runtime hooks and binaries are preserved, and legacy uninstall
cleanup remains. Other uses of the Go toolchain were not removed. Lifecycle tests
reject unexpected Go builds and verify that updater check/update paths skip an
older Katana registry entry without downloading modules.

## Full direct-dependency review

`DEPENDENCY_AUDIT.md` and its JSON companion cover all 121 original direct
system/pipx/source/download entries. System defaults dropped from 111 to 95.
No-reference defaults removed: argon2, cargo, masscan and pyenv-runtime.
Catalogue-only defaults removed: basez, bc, npm, rlwrap and whiptail. A command
example catalogue is not a reason to install every named executable.
Client-only workflows no longer mandate mongodb-server-core, redis,
openssh-server or the BloodHound application. Duplicate golang-any/p7zip-full and
the client's transitive mysql-common requirement were removed from the direct
list. Naminter, the optional BloodHound collector, and the unused Vulscan clone
were removed from default downloads. The prior Katana retirement remains.

The updater skips legacy Katana/Vulscan and retired optional pipx records.
Conservative uninstallation still understands older ledgers; no installed tool,
service, cache or package on the user's VM was deleted by this audit. Tests
exercise the reduced dependency list and preservation of pre-existing retired
packages. Source-match evidence has limits: opaque compiled tools were not
executed or proved equivalent to reference sources. The httpx-toolkit/httpx name
mismatch remains a documented follow-up, without silently installing another
HTTP client. Prerequisites and command aliases were retained rather than removed
from a naive package-name text search. The new APT simulation is saved separately
from the earlier pre-pruning simulation.

Final dependency-pruning verification: all 72 repository tests passed after
retiring Vulscan, plus Bash syntax and ShellCheck with sourced-file following
(`shellcheck -x`). Real fresh-database APT simulation of the 95 direct defaults
planned 1,168 packages with no removals, compared with 1,678 in the earlier
110-effective-package simulation using existing Kali indexes. This is simulated
dependency resolution, not measured disk/download savings or a live VM build.

## Launcher destination validation

The reported directory at `/usr/local/bin/cstk` exposed a reproducible false-success
path: the path journal returned early for an already recorded destination, and
the link function then skipped an existing directory while returning success.
The link function now rejects directory/special-file collisions independently of
journal history and leaves them untouched. GNU ln uses `-T` to target the exact
launcher name; the resolved executable symlink is verified against this checkout.

Before printing completion, the installer verifies the launcher again, verifies
the wrapper matches its template, and runs the installed absolute launcher with
`--help` under a timeout, checking the expected help marker. Output goes to
`log/launcher_check.log`. This checks the installed entry point, not every runtime
security tool. Tests reproduce a previously journaled nested directory, preserve
its contents, reject wrong/dangling links, exercise installed help in the normal
roundtrip, and prevent the completion banner when a link is corrupted after
setup. Later VM checks confirmed a missing launcher followed by a restricted sudo
PATH, as recorded below. No unexpected VM directory was deleted or moved.

The VM subsequently confirmed a separate lookup problem: sudo PATH contained only
/usr/sbin:/usr/bin:/sbin:/bin. The repaired absolute launcher printed version
3.0.5 successfully. Final installer validation now also resolves `cstk` through
its actual PATH and checks that the resolved command targets this checkout.
A missing /usr/local/bin produces an actionable secure_path diagnostic rather
than a completion banner. The installer does not silently change sudoers policy.
A regression verifies that absolute execution works while this restricted PATH
fails lookup validation.

## Pending-ledger recovery before the VM uninstall test

Added `tools/recover_package_ledger.py`, an APT-only read-only-by-default review
utility. It checks a pinned retained baseline, validates continuity of pending
snapshots, protects every baseline package conservatively, preserves later
successful ledger additions, and runs an APT purge simulation. Any proposed
baseline/untracked removal blocks ledger application. This is not an assertion
that the earliest retained snapshot predates CSTK; uncertain earlier dependencies
are retained. The complete saved VM archive validates 39 pending transaction
pairs, with 573 observed additions and 22 baseline entries incorrectly claimed
by that saved ledger. Live later records are assessed on the VM, not inferred
from the old archive.

An explicit apply option backs up original ledger/snapshots outside the checkout
and state directory, atomically replaces only the package ledger, then clears
pending files after preserving their copies. It never installs/removes packages
or runs uninstall. The VM-specific pinned baseline and helper wrapper are staged
in the host shared folder, not committed as general project configuration.

Uninstall now rejects pending before/after snapshots before removing managed
environments, launchers, manual pages or shell completion. The old late check is
also retained as a pre-purge recheck. Tests cover conservative reconstruction,
discontinuity/removal rejection, unsafe package-name rejection, no-write review,
backup/apply without package mutation, untracked APT removal refusal, and early
uninstall refusal that leaves all artifacts and rc contents intact.

The live preflight report subsequently proposed 574 active targets; APT simulated
exactly 574 removals, zero protected/untracked removals, exit 0. A shared-folder
runner now rechecks/applies the ledger repair, preserves the original VM
uninstaller, deploys the guarded uninstaller, and logs the actual test outside
the checkout. A sandbox end-to-end regression verifies that this runner removes
the disposable install, preserves user-created report data and journal backups,
and retains its transcript. This prepares a real VM test; it does not claim the
VM uninstall has already run.

## Live Kali VM uninstall result

The user executed the shared runner after taking a VirtualBox snapshot. Transcript
`uninstall-test.Kgxh52us.log` reports successful ledger repair and guarded
uninstall. Exactly 574 unique package identities appear in actual `Removing`
lines; they match the reviewed live APT targets, with zero unexpected identities
and zero identities from the 2,983-package protected baseline. No APT/dpkg error
or incomplete-cleanup diagnostic was found. The runner's final path checks report
the checkout, /var/lib/cstk, /opt/cstk, key, launcher, wrapper and both CSTK manpage
paths absent. Recovery originals and the transcript remain in the shared folder.

This validates the repaired older installation's uninstall on the user's VM.
It does not certify complete OS snapshot restoration, independently verify all
user-file contents, undo package upgrades/maintainer-script effects, or constitute
a fresh live install of the later 95-entry dependency list. Those limits remain.

Final publication check: all 83 repository tests passed (68.775 seconds), with
Bash syntax, ShellCheck with source following, Python syntax and diff whitespace
checks also passing. No VM-specific baseline, private key, raw recovery archive,
or shared-folder backup is included in the commit.
