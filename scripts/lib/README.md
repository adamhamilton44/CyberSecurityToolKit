# CSTK Shared Library

The `scripts/lib/` directory contains resources and interfaces shared by the
main launcher and its runtime tools. These files are part of CSTK's protected
checksum set.

> [!IMPORTANT]
> Start CSTK through `sudo cstk`. Do not rename, move, or directly execute
> unfamiliar library files.

## Contents

| File or pattern | Purpose |
| --- | --- |
| `*.enc` | Encrypted CSTK resources |
| Opaque resource names | Protected support assets referenced by exact filename |
| `GD_*.txt` | Google Dorks guides and reference lists |
| `nmap-scripts.txt` | Nmap NSE selection list used by the Nmap helper |
| `arguments_frame` | Shared terminal banner and argument display |
| `Fonts` | Optional animated-header renderer |
| `cstk_update.sh` | Check-only and confirmed-update manager |
| `cstk_wrapper` | Version-controlled template for the restricted installed wrapper |
| `cstk.1` | Source for the installed `man cstk` page |
| `tab_complete.cstk` | Bash and Zsh command-completion definitions |
| `tty_spawn_shell.md` | Terminal-friendly TTY upgrade guide |
| `CSTK_Zip2Go.zip` | Reviewable, Git LFS-managed portable assessment archive |

## Protected resources

On Linux x86-64 and ARM64, the installer silently provisions the library key
using a bundled static helper before installation checks. It verifies every
`*.enc` resource and stores the key at `/etc/cstk/lib_decryption.key` with root
ownership and mode `600` inside a mode `700` directory. Successful provisioning
removes both bundled helpers from the local checkout. Existing valid keys are
preserved. Other architectures or checkouts without helpers retain the private
key-file (`CSTK_LIB_KEY_SOURCE`) and interactive entry options.

The binaries contain masked, recoverable key material: this discourages casual
inspection but does not keep the key confidential from the machine owner. Never
commit the plaintext key or generated C sources. Maintainers rebuild both Linux
helpers with `python3 scripts/tools/build_provisioner.py /private/path/to/key`, using
`musl-gcc`, `aarch64-linux-gnu-gcc`, and OpenSSL. Generated sources are temporary;
only the binaries belong in `scripts/provision/`. Deletion is ordinary file
removal, not secure erasure; Git retains the distributed binaries.

If a protected file changes unexpectedly, CSTK stops at the integrity screen.
It does not automatically delete itself. Quit and compare the file with a
trusted signed commit.

## Maintenance notes

- Keep exact filenames because launcher routes and encrypted-name mappings
  depend on them.
- Keep ZIP archives under Git LFS.
- Update the manual page and both Bash/Zsh completion routes when public
  options change.
- Runtime helpers receive per-user Loot, Malware, Logs, logging-state, and
  home paths from `cstk_wrapper`; do not write runtime reports beneath the
  program directory.
- Validate shell sources with `bash -n` and ShellCheck before an authorized
  integrity refresh.
- `sudo cstk --refresh-hashes` requires an interactive terminal and the private
  integrity refresh key; it synchronizes installed interfaces and rebuilds the
  manifest. It is not an unauthenticated integrity bypass.

## Portable assessment archive

`CSTK_Zip2Go.zip` extracts into `CSTK_2Go/`. It includes a visible local-assessment
runner, bounded metadata checks, an explicit selected-file HTTP service, the
maintained Web/TLS checker, a permission/traffic guide, checksums, readable
sources, and optional Linux x86-64 shc launchers. It does not require CSTK's
wrapper or root. Rebuild with `python3 scripts/tools/build_zip2go.py`; generated launcher
C sources are included. See `scripts/tools/zip2go/README.md` for maintained scope and verification guidance.
