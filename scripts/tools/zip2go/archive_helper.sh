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
if [[ ${1:-} == --help || ${1:-} == -h ]]; then echo 'Usage: archive_helper.sh {list ARCHIVE | extract ARCHIVE NEW_DIRECTORY}'; echo 'ZIP/TAR only; bounded parsing; no links, devices, overwrite, password recovery, or execution.'; exit 0; fi
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required.' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for bounded archive parsing.' >&2; exit 1; }
exec timeout -k 2 30 python3 "$KIT_ROOT/lib/portable_utils.py" archive "$@"
