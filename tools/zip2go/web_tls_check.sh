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
USAGE='Usage: web_tls_check.sh HTTP_OR_HTTPS_URL [--output DIRECTORY]'
[[ ${1:-} == --help || ${1:-} == -h ]] && { echo "$USAGE"; echo 'Explicit active HTTP/TLS check; never run by run_me.sh.'; exit 0; }
[[ $# -ge 1 ]] || { echo "$USAGE" >&2; exit 2; }
url=$1; shift
parse_output "$@" || exit $?
[[ ! -L "$OUTPUT" ]] || { echo 'Refusing a symlink output directory.' >&2; exit 1; }
mkdir -p -- "$OUTPUT" || exit 1
# This maintained checker receives only this explicit portable report destination.
exec env -u user_home CSTK_USER_DATA_DIR="$OUTPUT" CSTK_LOOT_DIR="$OUTPUT" \
    CSTK_LOG_DIR="$OUTPUT/logs" CSTK_LOGGING_ENABLED=off CSTK_LOGGING_LEVEL=off \
    bash "$KIT_ROOT/lib/web_tls_security_assessment.sh" "$url"
