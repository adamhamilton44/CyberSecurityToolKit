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
USAGE='Usage: security_config.sh [--output DIRECTORY]'
parse_output "$@" || exit $?
init_report security-config || exit 1
capture 'Selected read-only kernel policy values' sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope fs.protected_hardlinks fs.protected_symlinks net.ipv4.ip_forward
capture 'SSH selected directives in main config only' awk '
    /^[[:space:]]*#/ {next}
    {k=tolower($1)}
    k ~ /^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|allowtcpforwarding|gatewayports|maxauthtries)$/ {print $0}
' /etc/ssh/sshd_config
note 'SSH includes, Match blocks, defaults, and command-line overrides are not evaluated. This is not the effective sshd configuration.'
capture 'SELinux enforcement state' getenforce
capture 'AppArmor visibility' aa-status
capture 'Running service names' systemctl --no-pager --no-legend --type=service --state=running
note 'Restricted sections remain partial; the tool does not request elevated privileges.'
finish_report
