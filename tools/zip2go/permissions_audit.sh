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
USAGE='Usage: permissions_audit.sh [--output DIRECTORY]'
parse_output "$@" || exit $?
init_report permissions || exit 1
note 'Only metadata of named configuration files and temporary directories is inspected. No credential file contents are read.'
for path in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /tmp /var/tmp /dev/shm; do
    [[ -e "$path" || -L "$path" ]] || { note "[SKIP] Absent: $path"; continue; }
    capture "Ownership/mode: $path" stat -c '%A %a %U:%G %n' -- "$path"
done
note 'Review write permissions and sticky bits against your policy. Metadata alone does not establish exploitability; ACLs and mounts can change effective access.'
finish_report
