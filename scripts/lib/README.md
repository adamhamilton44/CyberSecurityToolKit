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
| `tab_complete.cstk` | Shell-completion definitions |
| `tty_spawn_shell.md` | Terminal-friendly TTY upgrade guide |
| `CSTK_Zip2Go.zip` | Password-protected, Git LFS-managed Zip2Go archive |

## Protected resources

The owner-provided library key is installed outside the repository at
`/etc/cstk/lib_decryption.key` with root-only permissions. Never commit,
publish, or pass that key on a command line.

If a protected file changes unexpectedly, CSTK stops at the integrity screen.
It does not automatically delete itself. Quit and compare the file with a
trusted signed commit.

## Maintenance notes

- Keep exact filenames because launcher routes and encrypted-name mappings
  depend on them.
- Keep ZIP archives under Git LFS.
- Update the manual page and completion file when public options change.
- Validate shell sources with `bash -n` and ShellCheck before an authorized
  integrity refresh.
- Use the private recovery flow for authorized checksum updates; there is no
  public integrity-refresh command.
