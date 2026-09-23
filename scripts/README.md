# CSTK Runtime Scripts

The `scripts/` tree contains the executables, protected resources, and support
files used by the main `cstk` launcher.

> [!WARNING]
> Do not run unfamiliar files from this directory directly. Many helpers expect
> the restricted CSTK wrapper and launcher environment, and some tools can
> alter files, credentials, services, or system availability.

## `bin/`

The `bin/` directory contains CSTK helper programs and platform-specific
executables. Some files are compiled binaries; others are executable shell or
Python tools.

- Start tools through `sudo cstk`.
- Do not rename files: the launcher dispatch table uses their exact names.
- Do not assume a compiled file is encrypted or safe merely because its source
  is not readable.
- Direct execution is intentionally rejected by many helpers that require CSTK
  caller context.

## `lib/`

The `lib/` directory contains protected resources and shared interfaces,
including:

- encrypted `*.enc` assets;
- Google Dorks reference files (`GD_*.txt`);
- the Nmap script list (`nmap-scripts.txt`);
- menu frames and animated-header support;
- the updater, restricted wrapper template, manual page, and tab completion;
- the TTY shell-upgrade guide; and
- the Git LFS-managed Zip2Go archive.

The local decryption key is installed separately with root-only permissions.
It is not stored in Git.

## Integrity checks

`scripts/bin/` and `scripts/lib/` are part of CSTK's protected checksum set.
Changing a protected file causes CSTK to stop at the integrity screen.

A mismatch does **not** trigger automatic deletion. The user may quit without
changes or explicitly request core-file deletion and confirm it a second time.
Authorized maintenance can rebuild the manifest through the private recovery
path.

For a detailed library inventory, see [lib/README.md](lib/README.md).
