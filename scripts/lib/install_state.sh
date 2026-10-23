#!/bin/bash
# shellcheck disable=SC2154
# Root-owned installation journal. Sourced by install.sh and uninstall.sh.
cstk_state_dir=/var/lib/cstk

cstk_state_init() {
    local directory
    umask 077
    for directory in "$cstk_state_dir" /opt/cstk; do
        if [[ -L "$directory" || ( -e "$directory" && ! -d "$directory" ) ]]; then
            echo "Unsafe CSTK state directory: $directory" >&2
            return 1
        fi
    done
    if [[ -d "$cstk_state_dir" ]]; then
        [[ $(stat -c %u "$cstk_state_dir") == 0 &&
           $(stat -c %a "$cstk_state_dir") == 700 ]] || return 1
    elif [[ -e /opt/cstk ]]; then
        echo '/opt/cstk already exists without an installation ledger; refusing to claim it.' >&2
        return 1
    fi
    install -d -m 700 "$cstk_state_dir" "$cstk_state_dir/paths" || return 1
    if [[ -f "$cstk_state_dir/checkout" ]]; then
        [[ $(cat "$cstk_state_dir/checkout") == "$home_dir" ]] || {
            echo 'Another CSTK checkout owns the installation; uninstall it first.' >&2
            return 1
        }
    else
        printf '%s\n' "$home_dir" > "$cstk_state_dir/checkout" || return 1
    fi
    install -d -m 755 /opt/cstk /opt/cstk/bin || return 1
    cstk_state_env
}

cstk_state_env() {
    export PIPX_HOME=/opt/cstk/pipx PIPX_BIN_DIR=/opt/cstk/bin
    export PIPX_MAN_DIR=/opt/cstk/man XDG_CACHE_HOME=/opt/cstk/cache
    export XDG_CONFIG_HOME=/opt/cstk/config XDG_STATE_HOME=/opt/cstk/state PIPX_LOG_DIR=/opt/cstk/log/pipx
    export PIPX_TRASH_DIR=/opt/cstk/trash PIPX_VENV_CACHEDIR=/opt/cstk/cache/pipx
    export PIP_CACHE_DIR=/opt/cstk/cache/pip GOENV=off GOTELEMETRY=off
    export GOPATH=/opt/cstk/go GOBIN=/opt/cstk/bin GOCACHE=/opt/cstk/cache/go-build
    export PATH="/opt/cstk/bin:$PATH"
}

# Journal before modifying a system file; retain the original across reinstalls.
cstk_track_path() {
    local path="$1" id entry
    [[ "$path" == /* && "$path" != *$'\n'* ]] || return 1
    id=$(printf '%s' "$path" | sha256sum) || return 1
    entry="$cstk_state_dir/paths/${id%% *}"
    [[ -f "$entry/path" ]] && return 0
    [[ ! -d "$path" ]] || {
        echo "Refusing to replace directory: $path" >&2; return 1;
    }
    mkdir -p "$entry" || return 1
    if [[ -e "$path" || -L "$path" ]]; then
        cp -a --no-dereference -- "$path" "$entry/original" || return 1
    fi
    printf '%s\n' "$path" > "$entry/path"
}

cstk_package_snapshot() (
    # Inventory failures must not be hidden by a successful sort.
    set -o pipefail
    case "$1" in
        apt-get) dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' |
            awk '$2 != "not-installed" && $2 != "config-files" { print $1 }' | LC_ALL=C sort -u ;;
        dnf|yum) rpm -qa --qf '%{NAME}.%{ARCH}\n' | LC_ALL=C sort -u ;;
        brew) brew list --formula -1 | LC_ALL=C sort -u ;;
        *) return 1 ;;
    esac
)

# Capture transitive dependencies even when a package command partially fails.
cstk_package_transaction() (
    # A subshell confines the EXIT trap, including ordinary interruption cleanup.
    local manager="$1" before after delta merged
    shift
    before=$(mktemp "$cstk_state_dir/packages.before.XXXXXX") || exit 1
    after=$(mktemp "$cstk_state_dir/packages.after.XXXXXX") || { rm -f "$before"; exit 1; }
    if ! cstk_package_snapshot "$manager" > "$before"; then
        rm -f "$before" "$after"; exit 1
    fi
    cstk_finish_transaction() {
        local rc=$?
        trap - EXIT
        # Keep comparison collation identical to snapshot sorting, regardless
        # of the invoking user's locale. Stage the ledger so a failed comparison
        # cannot append a partial or incorrectly compared package list.
        delta=$(mktemp "$cstk_state_dir/packages.delta.XXXXXX") || exit 1
        merged=$(mktemp "$cstk_state_dir/packages.merged.XXXXXX") || exit 1
        if ! cstk_package_snapshot "$manager" > "$after" ||
           ! LC_ALL=C comm --check-order -13 "$before" "$after" > "$delta"; then
            echo 'Unable to record package changes; retain CSTK state for recovery.' >&2
            exit 1
        fi
        if [[ -e "$cstk_state_dir/packages" ]]; then
            cat "$cstk_state_dir/packages" "$delta" > "$merged" || exit 1
        else
            cat "$delta" > "$merged" || exit 1
        fi
        if ! LC_ALL=C sort -u "$merged" -o "$merged" ||
           ! mv -f -- "$merged" "$cstk_state_dir/packages"; then
            echo 'Unable to record package changes; retain CSTK state for recovery.' >&2
            exit 1
        fi
        rm -f -- "$before" "$after" "$delta" || exit 1
        exit "$rc"
    }
    trap cstk_finish_transaction EXIT
    printf '%s\n' "$manager" > "$cstk_state_dir/package-manager" || exit 1
    "$@"
)

# Record Homebrew repositories introduced by CSTK, including partial tap failures.
cstk_brew_tap() {
    local tap="$1"
    if ! brew tap | grep -Fxq -- "$tap"; then
        printf '%s\n' "$tap" >> "$cstk_state_dir/brew-taps" || return 1
    fi
    brew tap "$@"
}

cstk_install_file() {
    local mode="$1" source="$2" destination="$3"
    cstk_track_path "$destination" || return 1
    install -m "$mode" -- "$source" "$destination"
}

cstk_path_owned() {
    local id
    id=$(printf '%s' "$1" | sha256sum) || return 1
    [[ -f "$cstk_state_dir/paths/${id%% *}/path" ]]
}
