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
USAGE='Usage: system_info.sh [--output DIRECTORY]'
parse_output "$@" || exit $?
init_report system || exit 1
capture 'Kernel and architecture' uname -srm
capture 'Account and groups' id
capture 'Distribution identity' cat /etc/os-release
capture 'Uptime' uptime
capture 'Local filesystem capacity (network mounts excluded)' df -lh
capture 'Memory summary' free -m
capture 'Process names (no command arguments or environment)' ps -eo pid,ppid,user,comm
capture 'Virtualization metadata (informational only)' systemd-detect-virt
finish_report
