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
- `Etc_cstk_ai` is CSTK's original defensive AI-analysis TUI. It exposes no
  autonomous tools or shell access and does not contain ZimZilla source. Its
  auditable source, bundled phase-two policy engine, offline tests, build spec,
  and provenance record are under `source/cstk_ai/`.

## `source/`

The `source/` directory contains maintainable source and tests for selected
packaged helpers. `source/cstk_ai/Etc_cstk_ai.spec` builds
`bin/Etc_cstk_ai` with PyInstaller and includes the engagement questionnaire.
PyInstaller packaging, stripping, and UPX compression are not encryption; the
source remains authoritative for review and future changes.

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

## Container tools and maintenance

`source/container_tools/cstk_containers.py` builds `bin/cstk_containers`, the
Web Check lifecycle and read-only Trivy project-audit adapter. The AI's `/setup`
form saves non-secret connection metadata; profiles reload on launch and keys
remain session-only.

`tools/` contains build and package-maintenance sources and the maintained
Zip2Go source tree. `tests/` contains repository regression tests; run
`python3 -m unittest discover -s scripts/tests -v` from the repository root.
Compiled maintenance entry points are `bin/maint_*`. Build all release helpers
with `python scripts/tools/build_release_tools.py` in a build environment with
PyInstaller and Textual 8.2.8 plus shc and UPX on PATH.

The Web/TLS shell helper uses private scratch space inside its per-user report
directory, independent of inherited `TMPDIR`, and removes scratch files on exit.
