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
if [[ ${1:-} == --help || ${1:-} == -h ]]; then echo 'Usage: verify.sh — verify extracted toolkit files against SHA256SUMS'; exit 0; fi
[[ $# == 0 ]] || exit 2
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required.' >&2; exit 1; }
cd -- "$KIT_ROOT" || exit 1
sha256sum -c SHA256SUMS
