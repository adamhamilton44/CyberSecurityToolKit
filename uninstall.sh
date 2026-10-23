#!/bin/bash
# Remove CSTK-owned artifacts, retaining user reports and private runtime data.
set -o pipefail
home_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
# shellcheck source=scripts/lib/install_state.sh
source "$home_dir/scripts/lib/install_state.sh" || exit 1
python_install_file="$home_dir/Other/SecurityChecks/.python_pipx_installed_tools"
package_management_install_file="$home_dir/Other/SecurityChecks/.package_management_installed_tools"
github_install_file="$home_dir/Other/SecurityChecks/.github_installed_tools"
failures=0
legacy=0

failed() { echo "Cleanup failed: $*" >&2; failures=$((failures + 1)); }
recorded() { [[ -f "$github_install_file" ]] && grep -Fxq -- "$1" "$github_install_file"; }

remove_python_tools() {
    local pkg installed_apps
    if (( ! legacy )) && [[ -d /opt/cstk/pipx ]]; then
        # All environments, app links, caches and Go build outputs are private.
        rm -rf -- /opt/cstk || failed /opt/cstk
    elif (( legacy )) && [[ -s "$python_install_file" ]]; then
        command -v pipx >/dev/null 2>&1 || { failed 'pipx unavailable; Python packages retained'; return; }
        installed_apps=$(pipx list --short) || { failed 'cannot inspect legacy pipx environment'; return; }
        while IFS= read -r pkg; do
            [[ -n "$pkg" ]] || continue
            [[ "$pkg" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { failed 'invalid Python package record'; continue; }
            if awk -v wanted="$pkg" '$1 == wanted {found=1} END {exit !found}' <<< "$installed_apps"; then
                pipx uninstall "$pkg" || failed "pipx $pkg"
            fi
        done < "$python_install_file"
    fi
    if (( ! legacy )); then rm -rf -- /opt/cstk || failed /opt/cstk; fi
    if (( legacy )) && [[ -d /opt/cstk ]]; then rmdir --ignore-fail-on-non-empty /opt/cstk || failed /opt/cstk; fi
}

remove_completions() {
    local rc line temp
    [[ -f "$cstk_state_dir/completions" ]] || return 0
    while IFS= read -r rc; do
        [[ -e "$rc" || -L "$rc" ]] || continue
        [[ -f "$rc" && ! -L "$rc" ]] || { failed "unsafe shell file $rc"; continue; }
        line="source \"$home_dir/scripts/lib/tab_complete.cstk\""
        temp=$(mktemp "$cstk_state_dir/rc.XXXXXX") || { failed "$rc"; continue; }
        if awk -v target="$line" '$0 != target' "$rc" > "$temp" && cat "$temp" > "$rc"; then
            if [[ ! -s "$rc" ]] && grep -Fxq -- "$rc" "$cstk_state_dir/completions-created" 2>/dev/null; then
                rm -f -- "$rc" || failed "$rc"
            fi
        else
            failed "$rc"
        fi
        rm -f -- "$temp"
    done < "$cstk_state_dir/completions"
}

restore_paths() {
    local entry path
    for entry in "$cstk_state_dir"/paths/*; do
        [[ -f "$entry/path" ]] || continue
        path=$(cat "$entry/path") || { failed "$entry"; continue; }
        # Shell startup files have line-specific cleanup, preserving later edits.
        if [[ -f "$cstk_state_dir/completions" ]] && grep -Fxq -- "$path" "$cstk_state_dir/completions"; then
            continue
        fi
        [[ "$path" == /* && "$path" != / && ! -d "$path" ]] || { failed "unsafe artifact $path"; continue; }
        if [[ -e "$entry/original" || -L "$entry/original" ]]; then
            rm -f -- "$path" && cp -a --no-dereference -- "$entry/original" "$path" || failed "$path"
        else
            rm -f -- "$path" || failed "$path"
        fi
    done
}

remove_legacy_paths() {
    local path rc temp
    rm -f -- /usr/local/bin/cstk /usr/local/bin/cstk_wrapper \
        /usr/share/man/man1/cstk.1 /usr/share/man/man1/cstk.1.gz || failed 'CSTK launcher/manual'
    if recorded shc; then
        rm -f -- /usr/local/bin/shc /usr/local/share/man/man1/shc.1 /usr/local/share/man/man1/shc.1.gz || failed shc
        rm -rf -- /opt/cstk/shc || failed 'shc source'
    fi
    if recorded katana; then rm -f -- /root/go/bin/katana || failed katana; fi
    if recorded mimipenguin; then
        rm -f -- /usr/local/bin/mimipenguin.sh /usr/local/bin/mimipenguin.py || failed mimipenguin
    fi
    if recorded mongosh-archive; then
        rm -f -- /usr/local/bin/mongosh /usr/local/bin/mongosh_crypt_v1.so \
            /usr/local/bin/mongosh_crypt_v1.dylib || failed mongosh
    fi
    # Older completion installs had no account ledger. Match only the exact line.
    local -a homes=(/root)
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
        path=$(getent passwd "$SUDO_USER") || path=''
        [[ -n "$path" ]] && { IFS=: read -r _ _ _ _ _ path _ <<< "$path"; homes+=("$path"); }
    fi
    for path in "${homes[@]}"; do
        for rc in "$path/.bashrc" "$path/.zshrc"; do
            [[ -f "$rc" && ! -L "$rc" ]] || continue
            temp=$(mktemp) || { failed "$rc"; continue; }
            awk -v target="source \"$home_dir/scripts/lib/tab_complete.cstk\"" '$0 != target' "$rc" > "$temp" &&
                cat "$temp" > "$rc" || failed "$rc"
            rm -f -- "$temp"
        done
    done
}

check_package_journal() {
    local pending
    for pending in "$cstk_state_dir"/packages.before.* "$cstk_state_dir"/packages.after.*; do
        if [[ -e "$pending" || -L "$pending" ]]; then
            failed 'interrupted package transaction requires ledger recovery; no uninstall changes made'
            return 1
        fi
    done
    return 0
}

remove_system_packages() {
    local manager pkg output removal
    local -a packages=()
    local current
    local list="$cstk_state_dir/packages"
    check_package_journal || return 1
    if (( legacy )); then
        list="$package_management_install_file"
        if command -v apt-get >/dev/null; then manager=apt-get
        elif command -v dnf >/dev/null; then manager=dnf
        elif command -v yum >/dev/null; then manager=yum
        elif command -v brew >/dev/null; then manager=brew
        else failed 'no package manager'; return; fi
    else
        [[ -f "$cstk_state_dir/package-manager" ]] || return 0
        manager=$(cat "$cstk_state_dir/package-manager") || { failed 'package manager ledger'; return; }
    fi
    [[ -f "$list" ]] || return 0
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] || continue
        [[ "$pkg" =~ ^[A-Za-z0-9][A-Za-z0-9.+:@_-]*$ ]] || { failed "invalid package record: $pkg"; continue; }
        packages+=("$pkg")
    done < "$list"
    # nrich's older native-package installation used the GitHub ledger.
    if (( legacy )) && recorded nrich; then packages+=(nrich); fi
    current=$(mktemp) || { failed 'package inventory'; return; }
    if ! cstk_package_snapshot "$manager" > "$current"; then
        rm -f "$current"; failed 'package inventory'; return
    fi
    local -a installed=()
    for pkg in "${packages[@]}"; do
        if awk -v wanted="$pkg" '$0 == wanted || index($0, wanted ":") == 1 {found=1} END {exit !found}' "$current"; then
            installed+=("$pkg")
        fi
    done
    rm -f "$current"
    packages=("${installed[@]}")
    (( ${#packages[@]} )) || return 0
    case "$manager" in
        apt-get)
            output=$(mktemp) || { failed 'package simulation'; return; }
            if ! apt-get -s purge -- "${packages[@]}" > "$output" 2>&1; then
                cat "$output" >&2; rm -f "$output"; failed 'APT removal simulation'; return
            fi
            while IFS= read -r removal; do
                local matched=0
                for pkg in "${packages[@]}"; do
                    if [[ "$pkg" == "$removal" || "${pkg%:*}" == "$removal" ]]; then matched=1; break; fi
                done
                if (( ! matched )); then
                    echo "APT would also remove an untracked package: $removal" >&2
                    rm -f "$output"; failed 'dependency removal would affect other software'; return
                fi
            done < <(awk '$1 == "Remv" || $1 == "Purg" {print $2}' "$output")
            rm -f "$output"
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -- "${packages[@]}" || failed 'APT packages'
            ;;
        dnf|yum)
            # Disable automatic cleanup of dependencies not in CSTK's ledger.
            rpm -e --test -- "${packages[@]}" || { failed 'RPM removal would break dependencies'; return; }
            "$manager" --setopt=clean_requirements_on_remove=False remove -y -- "${packages[@]}" || failed 'RPM packages'
            ;;
        brew) brew uninstall --formula -- "${packages[@]}" || failed 'Homebrew packages' ;;
        *) failed "unsupported package manager $manager" ;;
    esac
}

main() {
    local choice checkout
    (( EUID == 0 )) || { echo 'Run uninstall.sh with sudo.' >&2; return 1; }
    # Reject destructive checkout mistakes before any removals.
    [[ "$home_dir" != / && "$home_dir" != /root && "$home_dir" != /home &&
       -f "$home_dir/cstk.sh" && -d "$home_dir/scripts/lib" ]] || return 1
    if [[ -d "$cstk_state_dir" && ! -L "$cstk_state_dir" ]]; then
        [[ $(stat -c %u "$cstk_state_dir") == 0 && $(stat -c %a "$cstk_state_dir") == 700 ]] || return 1
        checkout=$(cat "$cstk_state_dir/checkout") || return 1
        [[ "$checkout" == "$home_dir" ]] || { echo 'This checkout does not own the installation.' >&2; return 1; }
    elif [[ -e "$cstk_state_dir" || -L "$cstk_state_dir" ]]; then
        echo 'Unsafe installation ledger.' >&2; return 1
    else
        legacy=1
        echo 'Legacy install: only recorded dependencies can be removed; historical unrecorded changes cannot be reconstructed.' >&2
    fi
    # Reject unresolved ownership before removing environments, links or rc lines.
    check_package_journal || return 1
    if [[ "${1:-}" != all ]]; then
        read -r -p 'Uninstall CSTK and its recorded dependencies? [y/N] ' choice || return 1
        [[ "$choice" =~ ^[Yy]$ ]] || return 0
    fi
    remove_python_tools
    if recorded vulscan; then
        rm -rf -- /usr/share/nmap/scripts/vulscan || failed vulscan
        if command -v nmap >/dev/null; then nmap --script-updatedb || failed 'Nmap script database'; fi
    fi
    if (( legacy )); then remove_legacy_paths
    else remove_completions; restore_paths; fi
    if command -v mandb >/dev/null; then mandb >/dev/null 2>&1 || failed 'manual index'; fi
    # Python uninstall and nmap must finish before their dependencies are removed.
    if (( failures == 0 )); then
        remove_system_packages
    else
        echo 'System dependencies retained until earlier cleanup failures are resolved.' >&2
    fi
    if [[ -f "$cstk_state_dir/brew-taps" ]]; then
        local tap
        while IFS= read -r tap; do
            [[ -n "$tap" ]] || continue
            if brew tap | grep -Fxq -- "$tap"; then brew untap "$tap" || failed "Homebrew tap $tap"; fi
        done < "$cstk_state_dir/brew-taps"
    fi
    if (( failures )); then
        echo 'Uninstall incomplete. Checkout and installation ledger retained; fix reported errors and rerun.' >&2
        return 1
    fi
    # Remove only CSTK's key, not unrelated files someone put in /etc/cstk.
    [[ ! -L /etc/cstk ]] || { failed 'unsafe key directory'; return 1; }
    rm -f -- /etc/cstk/lib_decryption.key || return 1
    rm -rf -- /etc/cstk/.provision.* || return 1
    rm -f -- /etc/cstk/.lib_decryption.key.* || return 1
    if [[ -d /etc/cstk ]]; then rmdir --ignore-fail-on-non-empty /etc/cstk || return 1; fi
    cd / || return 1
    rm -rf -- "$home_dir" || return 1
    if (( ! legacy )); then rm -rf -- "$cstk_state_dir" || return 1; fi
    echo 'CSTK removed. User-created data in ~/.local/share/cstk was preserved.'
}

main "$@"
