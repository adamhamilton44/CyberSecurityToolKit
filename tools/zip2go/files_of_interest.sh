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
USAGE='Usage: files_of_interest.sh --path DIRECTORY [--output DIRECTORY]'
path=''
args=()
while (( $# )); do
    case "$1" in
        --path) [[ $# -ge 2 ]] || { echo "$USAGE" >&2; exit 2; }; path=$2; shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
parse_output "${args[@]}" || exit $?
[[ -n "$path" ]] || { echo "$USAGE" >&2; exit 2; }
init_report files-of-interest || exit 1
capture 'Selected configuration/script metadata: depth <= 2, entries examined <= 200; no file contents' python3 "$KIT_ROOT/lib/inventory.py" "$path" --interesting
finish_report
