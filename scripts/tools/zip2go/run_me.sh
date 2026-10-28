#!/bin/bash
# shellcheck disable=SC2034  # Shared helpers consume entry-point settings.
set -o pipefail
# Locate the extracted toolkit when invoked through PATH, a symlink, or shc.
entry=$0
[[ "$entry" == */* ]] || entry=$(command -v -- "$entry") || exit 1
if command -v readlink >/dev/null 2>&1; then
    resolved=$(readlink -f -- "$entry" 2>/dev/null) && entry=$resolved
fi
here=$(cd -- "$(dirname -- "$entry")" && pwd -P) || exit 1
KIT_ROOT=''
for candidate in "$here" "$here/../.."; do
    if [[ -f "$candidate/lib/common.sh" ]]; then
        KIT_ROOT=$(cd -- "$candidate" && pwd -P) || exit 1
        break
    fi
done
[[ -n "$KIT_ROOT" ]] || { echo 'Keep this executable inside the extracted Zip2Go directory.' >&2; exit 1; }
# shellcheck source=lib/common.sh
source "$KIT_ROOT/lib/common.sh" || exit 1
USAGE='Usage: run_me.sh [--output DIRECTORY]'
parse_output "$@" || exit $?
init_report baseline || exit 1
note 'This runner performs local metadata checks only. It does not start servers, fetch software, scan hosts, or change system configuration.'
printf 'Starting four local assessment steps. Reports: %s\n' "$REPORT_DIR"
failed=0
for tool in system_info network_info permissions_audit security_config; do
    printf 'Running %s...\n' "$tool"
    if "$KIT_ROOT/$tool.sh" --output "$REPORT_DIR/steps" >> "$REPORT" 2>&1; then
        note "[DONE] $tool"
    else
        status=$?
        note "[FAILED] $tool: $status"
        failed=$((failed + 1))
    fi
done
note 'Individual reports identify permission limits, unavailable commands, and timeouts.'
finish_report
(( failed == 0 ))
