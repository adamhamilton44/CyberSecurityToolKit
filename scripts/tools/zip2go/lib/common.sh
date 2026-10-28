#!/bin/bash
# shellcheck disable=SC2034  # Entry points and the EXIT trap use shared state.
# Shared local-report helpers. No installation, elevation, or wrapper required.
set -o pipefail
umask 077
export LC_ALL=C
OUTPUT="$KIT_ROOT/reports"
REPORT=''
REPORT_COMPLETE=0
REPORT_SKIPS=0

parse_output() {
    while (( $# )); do
        case "$1" in
            --output) [[ $# -ge 2 && -n "$2" ]] || { echo 'Missing output directory.' >&2; return 2; }; OUTPUT="$2"; shift 2 ;;
            --help|-h) printf '%s\n' "$USAGE"; exit 0 ;;
            *) printf 'Unknown argument: %s\n%s\n' "$1" "$USAGE" >&2; return 2 ;;
        esac
    done
}

init_report() {
    local name="$1" directory
    [[ ! -L "$OUTPUT" ]] || { echo 'Refusing a symlink output directory.' >&2; return 1; }
    mkdir -p -- "$OUTPUT" || return 1
    directory=$(mktemp -d "$OUTPUT/$name-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || return 1
    chmod 700 "$directory" || return 1
    REPORT_DIR=$(cd -- "$directory" && pwd -P) || return 1
    REPORT="$REPORT_DIR/report.txt"
    printf 'CSTK Zip2Go assessment: %s\nUTC: %s\nScope: local metadata; permissions are those of the invoking account.\n\n' \
        "$name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$REPORT" || return 1
    chmod 600 "$REPORT" || return 1
    trap 'rc=$?; if (( ! REPORT_COMPLETE )); then printf "\n[INCOMPLETE] exit status %s\n" "$rc" >> "$REPORT"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

note() { printf '%s\n' "$*" >> "$REPORT" || exit 1; }

capture() {
    local label="$1" rc captured bytes
    local -a statuses
    shift
    printf '\n=== %s ===\n' "$label" >> "$REPORT" || exit 1
    if ! command -v "$1" >/dev/null 2>&1; then
        note "[SKIP] Missing command: $1"; REPORT_SKIPS=$((REPORT_SKIPS + 1)); return 0
    fi
    if ! command -v timeout >/dev/null 2>&1; then
        note '[SKIP] timeout is unavailable; bounded command execution was skipped.'
        REPORT_SKIPS=$((REPORT_SKIPS + 1)); return 0
    fi
    # Bound execution and output; remove terminal control bytes from evidence.
    captured=$(mktemp "$REPORT_DIR/.capture-XXXXXX") || exit 1
    timeout -k 2 8 "$@" </dev/null 2>&1 | head -c 65536 > "$captured"
    statuses=("${PIPESTATUS[@]}")
    rc=${statuses[0]}
    if (( statuses[1] != 0 )); then
        rm -f -- "$captured"
        exit 1
    fi
    bytes=$(wc -c < "$captured") || exit 1
    tr -d '\000-\010\013-\037\177' < "$captured" >> "$REPORT" || exit 1
    rm -f -- "$captured"
    if (( bytes >= 65536 )); then
        note '[PARTIAL] Output reached the 64 KiB cap; further evidence may be omitted.'
        REPORT_SKIPS=$((REPORT_SKIPS + 1))
    fi
    if (( rc != 0 )); then
        note "[PARTIAL] Command status $rc (permission denial, timeout, or output cap)."
        REPORT_SKIPS=$((REPORT_SKIPS + 1))
    fi
}

finish_report() {
    note "[COMPLETE] Optional or restricted sections skipped/partial: $REPORT_SKIPS"
    REPORT_COMPLETE=1
    printf 'Report: %s\n' "$REPORT" || return 1
}
