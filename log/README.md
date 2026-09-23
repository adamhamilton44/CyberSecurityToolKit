# CSTK Logs

The `log/` directory contains installer, updater, and runtime diagnostics. Its
contents are generated locally and are excluded from Git, except for this
guide.

## Common locations

| Path | Purpose |
| --- | --- |
| `log/package_manager/` | Per-package installation results and dependency diagnostics |
| `log/updates/` | Timestamped update checks, downloads, and update results |
| Other `*.log` files | Output written by individual CSTK helpers |

## Handling logs safely

- Review logs when an installation, update, or helper reports a failure.
- Treat logs as potentially sensitive because they may contain usernames,
  target addresses, local paths, or tool output.
- Do not commit logs or attach them to an issue without reviewing and redacting
  sensitive information.
- Remove old logs only after confirming they are no longer needed for
  troubleshooting or audit records.

Authentication preferences, password hashes, package records, and integrity
state are stored under `Other/SecurityChecks/`, not in this directory. Do not
delete those files to bypass authentication or repair an integrity warning.
Use CSTK's menu and documented recovery behavior instead.
