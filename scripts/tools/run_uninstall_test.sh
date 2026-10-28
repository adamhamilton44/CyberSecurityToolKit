#!/bin/bash
# Run only after the shared-folder recovery report has been reviewed.
set -o pipefail
umask 077
(( EUID == 0 )) || { echo 'Run this test with sudo.' >&2; exit 1; }
here=$(cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
checkout=$(cat /var/lib/cstk/checkout) || exit 1
[[ "$checkout" == /* && "$checkout" != / && "$checkout" != /home && "$checkout" != /root &&
   -f "$checkout/cstk.sh" && -f "$checkout/uninstall.sh" &&
   ! -L "$checkout/uninstall.sh" && -d "$checkout/scripts/lib" ]] || exit 1
[[ "$here" != "$checkout" && "$here" != "$checkout/"* ]] || {
    echo 'Keep this test and its backups outside the checkout.' >&2; exit 1;
}
for file in check-uninstall.sh recover_package_ledger.py uninstall.sh; do
    [[ -f "$here/$file" && ! -L "$here/$file" ]] || exit 1
done
log=$(mktemp "$here/uninstall-test.XXXXXXXX.log") || exit 1

run_test() {
    echo 'Rechecking APT simulation, backing up the journal, and repairing ownership...'
    bash "$here/check-uninstall.sh" --apply || return 1
    # Preserve the VM's original uninstaller before replacing it with the guard.
    local original
    original=$(mktemp "$here/uninstall-original.XXXXXXXX.sh") || return 1
    cp -- "$checkout/uninstall.sh" "$original" || return 1
    install -m 755 -- "$here/uninstall.sh" "$checkout/uninstall.sh" || return 1
    echo 'Running the guarded uninstaller. The VM snapshot is the fallback.'
    bash "$checkout/uninstall.sh" all || return 1
    echo 'Uninstaller returned success. Remaining paths (originals may have been restored):'
    local path
    for path in "$checkout" /var/lib/cstk /opt/cstk /etc/cstk/lib_decryption.key \
        /usr/local/bin/cstk /usr/local/bin/cstk_wrapper \
        /usr/share/man/man1/cstk.1 /usr/share/man/man1/cstk.1.gz; do
        if [[ -e "$path" || -L "$path" ]]; then
            ls -ld -- "$path"
        else
            printf 'Absent: %s\n' "$path"
        fi
    done
}

echo "Transcript: $log"
run_test 2>&1 | tee "$log"
exit "${PIPESTATUS[0]}"
