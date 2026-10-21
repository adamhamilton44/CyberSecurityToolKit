# CSTK install/uninstall audit

The installer and uninstaller now share a root-owned installation ledger and
isolated managed-tool directories. Existing uncommitted Web/TLS work was retained;
no synced `sources/` references were changed. Changes are local and unpushed.

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

A complete download/install/uninstall on a disposable current Kali VM is still
needed to validate upstream package availability, current source builds, service
behavior, and disk requirements. DNF/YUM/Homebrew branches are statically checked,
not certified by live distribution tests. The ARM64 helper is exercised under
emulation, not a complete ARM64 installation. No claim of perfect OS restoration
or universal first-run success is made from offline tests.
