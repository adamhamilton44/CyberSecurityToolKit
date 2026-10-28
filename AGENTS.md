# CSTK project instructions

## Keep changes synchronized

For every CSTK change, review the related interfaces and supporting files before
considering the work complete. Update every affected surface; do not assume a
change to the primary tool file is sufficient.

Check as applicable:
- `cstk.sh`: interactive menus, dispatch, argument validation, and both `-h` and
  `--help` text (including class-specific help).
- `scripts/lib/cstk.1`: man-page options, examples, behavior, and limitations.
- `README.md` and relevant component guides.
- `scripts/lib/tab_complete.cstk`: Bash and Zsh completion, including short,
  long, and combined class/tool options.
- `scripts/lib/arguments_frame` and other tool banners or helper interfaces.
- Installer, updater, uninstaller, dependency policy, and install tracking when
  dependencies, paths, or lifecycle behavior change.
- Maintained sources, compiled executables, portable archives, build scripts,
  and provenance metadata when packaged code changes.
- Regression tests and runtime integrity manifests when covered files change.

Verify affected help, completion, and dispatch behavior without triggering
installation, remote scans, or integrity-failure deletion paths. Check that
examples and documented option names agree with the implementation.

Report any affected surface that could not be updated or verified, including a
root-owned manifest or installed interface awaiting sudo. Avoid unnecessary
edits to unrelated helpers, but always assess their relevance.
