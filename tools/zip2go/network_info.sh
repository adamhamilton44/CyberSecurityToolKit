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
USAGE='Usage: network_info.sh [--output DIRECTORY]'
parse_output "$@" || exit $?
init_report network || exit 1
note 'Local interface/routes/listeners only. No probes, DNS lookups, or connections are initiated.'
capture 'Interface addresses' ip -brief address show
capture 'IPv4 routes' ip -4 route show
capture 'IPv6 routes' ip -6 route show
capture 'Listening TCP/UDP sockets (numeric; no process arguments)' ss -H -lntu
capture 'Resolver nameservers (no lookup)' awk '$1 == "nameserver" {print $0}' /etc/resolv.conf
finish_report
