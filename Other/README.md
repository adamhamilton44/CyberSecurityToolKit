# Other CSTK Resources

This directory contains CSTK documentation, integrity support, wordlists,
runtime downloads, and artwork.

## Directory map

| Path | Purpose |
| --- | --- |
| `LICENSE.txt` | Project license |
| `cstk.png` | CSTK artwork used by the main README |
| `SecurityChecks/check_hashes.sh` | Tracked checksum verification helper |
| `SecurityChecks/sha256.checksum` | Locally generated protected-file manifest; intentionally not committed |
| `Wordlists/` | Wordlists supplied with CSTK |
| `Downloads/` | Third-party repositories installed at runtime; intentionally not committed |

## Integrity behavior

Before CSTK opens its menus or dispatches a tool, it checks the locally
generated SHA-256 manifest. A failed check causes CSTK to stop; it does not
automatically delete the project.

The integrity screen provides two visible choices:

1. Quit without changing anything.
2. Delete CSTK launchers and core program files after a second explicit
   confirmation.

The deletion choice preserves local data, `Bank/` contents, logs, wordlists,
and installed system packages. Authorized maintenance can rebuild the manifest
through a private recovery path that is not exposed as a public command-line
option.

> [!IMPORTANT]
> Do not edit, replace, or publish local security-state files. If an integrity
> warning was not expected, quit and compare the installation with a trusted
> signed Git commit.
