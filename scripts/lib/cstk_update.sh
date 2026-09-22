#!/bin/bash

# CSTK update manager.
# Normal launcher startup never calls this file.  It is used only by the
# explicit --check-updates and --update commands (or the matching menu item).

set -o pipefail

R=$'\e[1;31m'
G=$'\e[1;32m'
Y=$'\e[1;33m'
C=$'\e[1;36m'
X=$'\e[0m'

mode="${1:-check}"
home_dir="${2:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
security_checks="$home_dir/Other/SecurityChecks"
python_install_file="$security_checks/.python_pipx_installed_tools"
package_install_file="$security_checks/.package_management_installed_tools"
github_install_file="$security_checks/.github_installed_tools"
run_stamp="$(date +%Y%m%d-%H%M%S)"
log_dir="$home_dir/log/updates/$run_stamp"

warnings=0
failures=0
self_update_blocked=0
self_updated=0
REPO_CHANGED=0
REPO_STATE="unknown"

declare -a SYSTEM_PACKAGES=()
declare -a PYTHON_PACKAGES=()
declare -a GITHUB_TOOLS=()

info() {
    echo -e "${C}[ ℹ  ] $*${X}"
}

ok() {
    echo -e "${G}[ ✅ ] $*${X}"
}

warn() {
    echo -e "${Y}[ ⚠  ] $*${X}"
    ((warnings++))
    return 0
}

fail() {
    echo -e "${R}[ ❌ ] $*${X}"
    ((failures++))
    return 0
}

valid_registry_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]*$ ]]
}

load_registry() {
    local file="$1"

    [[ -r "$file" ]] || return 0
    awk 'NF && $1 !~ /^#/ {print $1}' "$file" |
        LC_ALL=C sort -u |
        while IFS= read -r entry; do
            if valid_registry_name "$entry"; then
                printf '%s\n' "$entry"
            else
                echo -e "${Y}[ ⚠  ] Ignoring unsafe registry entry: $entry${X}" >&2
            fi
        done
}

load_registries() {
    mapfile -t SYSTEM_PACKAGES < <(load_registry "$package_install_file")
    mapfile -t PYTHON_PACKAGES < <(load_registry "$python_install_file")
    mapfile -t GITHUB_TOOLS < <(load_registry "$github_install_file")
}

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${R}Run the CSTK updater as root through: sudo cstk --update${X}" >&2
        exit 2
    fi
}

validate_home() {
    if [[ ! -f "$home_dir/cstk.sh" || ! -d "$security_checks" ]]; then
        echo -e "${R}Invalid CSTK directory: $home_dir${X}" >&2
        exit 2
    fi
    mkdir -p "$log_dir"
}

print_scope() {
    echo -e "${C}\nCSTK Update Manager${X}"
    echo "  CSTK directory: $home_dir"
    echo "  System packages recorded by CSTK: ${#SYSTEM_PACKAGES[@]}"
    echo "  Python applications recorded by CSTK: ${#PYTHON_PACKAGES[@]}"
    echo "  GitHub/Go tools recorded by CSTK: ${#GITHUB_TOOLS[@]}"
    echo "  Log directory: $log_dir"
    echo
    echo "Only CSTK-managed items are in scope."
    echo "This does not perform a full operating-system upgrade or autoremove packages."
}

repo_git() {
    local path="$1"
    local owner
    shift

    owner="$(stat -c '%U' "$path")" || return 1
    if [[ "$EUID" -eq 0 && "$owner" != "root" ]] && command -v sudo >/dev/null 2>&1; then
        sudo -H -u "$owner" git -c safe.directory="$path" -C "$path" "$@"
    else
        git -c safe.directory="$path" -C "$path" "$@"
    fi
}

check_git_repo() {
    local label="$1"
    local path="$2"
    local local_head upstream_head upstream

    REPO_STATE="unknown"
    if [[ ! -d "$path/.git" ]]; then
        warn "$label cannot be checked because $path is not a Git checkout."
        REPO_STATE="not-git"
        return 2
    fi
    if [[ -n "$(repo_git "$path" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
        warn "$label has tracked local changes; automatic update is disabled."
        REPO_STATE="dirty"
        return 2
    fi
    upstream="$(repo_git "$path" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" || {
        warn "$label has no configured upstream branch."
        REPO_STATE="no-upstream"
        return 2
    }
    if ! repo_git "$path" fetch --quiet --prune >"$log_dir/${label//[^A-Za-z0-9]/_}_fetch.log" 2>&1; then
        warn "$label remote check failed; see the update log."
        REPO_STATE="fetch-failed"
        return 1
    fi
    local_head="$(repo_git "$path" rev-parse HEAD)" || return 1
    upstream_head="$(repo_git "$path" rev-parse "$upstream")" || return 1

    if [[ "$local_head" == "$upstream_head" ]]; then
        ok "$label is current."
        REPO_STATE="current"
    elif repo_git "$path" merge-base --is-ancestor "$local_head" "$upstream_head"; then
        info "$label has an update available."
        REPO_STATE="behind"
    elif repo_git "$path" merge-base --is-ancestor "$upstream_head" "$local_head"; then
        warn "$label is ahead of its upstream; it will not be changed."
        REPO_STATE="ahead"
    else
        warn "$label has diverged from its upstream; it will not be changed."
        REPO_STATE="diverged"
    fi
}

update_git_repo() {
    local label="$1"
    local path="$2"
    local before after

    REPO_CHANGED=0
    check_git_repo "$label" "$path" || true
    case "$REPO_STATE" in
        current)
            return 0
            ;;
        behind)
            ;;
        *)
            return 2
            ;;
    esac

    before="$(repo_git "$path" rev-parse HEAD)" || return 1
    if ! repo_git "$path" pull --ff-only --quiet >"$log_dir/${label//[^A-Za-z0-9]/_}_pull.log" 2>&1; then
        fail "$label fast-forward update failed; see the update log."
        return 1
    fi
    after="$(repo_git "$path" rev-parse HEAD)" || return 1
    if [[ "$before" != "$after" ]]; then
        REPO_CHANGED=1
        ok "$label updated by fast-forward."
    fi
}

check_system_packages() {
    local simulation_log="$log_dir/system_package_check.log"
    local -a upgrades=()

    echo -e "${C}\nSystem package check${X}"
    if [[ "${#SYSTEM_PACKAGES[@]}" -eq 0 ]]; then
        info "No CSTK-installed system packages are recorded."
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Refreshing signed APT package indexes..."
        if ! apt-get update >"$log_dir/apt_update.log" 2>&1; then
            warn "APT index refresh failed; see $log_dir/apt_update.log"
            return 1
        fi
        if apt-get -s --no-remove install --only-upgrade "${SYSTEM_PACKAGES[@]}" >"$simulation_log" 2>&1; then
            mapfile -t upgrades < <(awk '/^Inst / {print $2}' "$simulation_log" | LC_ALL=C sort -u)
            if [[ "${#upgrades[@]}" -eq 0 ]]; then
                ok "Recorded APT packages are current."
            else
                info "Recorded APT packages with updates: ${upgrades[*]}"
            fi
        else
            warn "APT could not simulate the recorded package update; see $simulation_log"
        fi
    elif command -v dnf >/dev/null 2>&1; then
        dnf -q check-update "${SYSTEM_PACKAGES[@]}" >"$simulation_log" 2>&1
        case $? in
            0) ok "Recorded DNF packages are current." ;;
            100) info "Recorded DNF packages have updates available." ;;
            *) warn "DNF update check failed; see $simulation_log" ;;
        esac
    elif command -v yum >/dev/null 2>&1; then
        yum -q check-update "${SYSTEM_PACKAGES[@]}" >"$simulation_log" 2>&1
        case $? in
            0) ok "Recorded YUM packages are current." ;;
            100) info "Recorded YUM packages have updates available." ;;
            *) warn "YUM update check failed; see $simulation_log" ;;
        esac
    elif command -v brew >/dev/null 2>&1; then
        if brew update >"$log_dir/brew_update.log" 2>&1 &&
           brew outdated "${SYSTEM_PACKAGES[@]}" >"$simulation_log" 2>&1; then
            if [[ -s "$simulation_log" ]]; then
                info "Recorded Homebrew packages have updates available."
            else
                ok "Recorded Homebrew packages are current."
            fi
        else
            warn "Homebrew update check failed; see the update log."
        fi
    else
        warn "No supported package manager was found."
    fi
}

update_system_packages() {
    echo -e "${C}\nUpdating recorded system packages${X}"
    [[ "${#SYSTEM_PACKAGES[@]}" -gt 0 ]] || return 0

    if command -v apt-get >/dev/null 2>&1; then
        if APT_LISTCHANGES_FRONTEND=none DEBIAN_FRONTEND=noninteractive \
            apt-get install --only-upgrade --no-remove -y \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                "${SYSTEM_PACKAGES[@]}" >"$log_dir/apt_upgrade.log" 2>&1; then
            ok "Recorded APT packages updated without removals."
        else
            fail "APT package update failed; see $log_dir/apt_upgrade.log"
        fi
    elif command -v dnf >/dev/null 2>&1; then
        if dnf upgrade --refresh -y "${SYSTEM_PACKAGES[@]}" >"$log_dir/dnf_upgrade.log" 2>&1; then
            ok "Recorded DNF packages updated."
        else
            fail "DNF package update failed; see the update log."
        fi
    elif command -v yum >/dev/null 2>&1; then
        if yum update -y "${SYSTEM_PACKAGES[@]}" >"$log_dir/yum_upgrade.log" 2>&1; then
            ok "Recorded YUM packages updated."
        else
            fail "YUM package update failed; see the update log."
        fi
    elif command -v brew >/dev/null 2>&1; then
        if HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade "${SYSTEM_PACKAGES[@]}" >"$log_dir/brew_upgrade.log" 2>&1; then
            ok "Recorded Homebrew packages updated."
        else
            fail "Homebrew package update failed; see the update log."
        fi
    fi
}

check_python_tools() {
    local pkg installed=0

    echo -e "${C}\nPython application check${X}"
    if [[ "${#PYTHON_PACKAGES[@]}" -eq 0 ]]; then
        info "No CSTK-installed pipx applications are recorded."
        return 0
    fi
    if ! command -v pipx >/dev/null 2>&1; then
        warn "pipx is unavailable."
        return 1
    fi
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if pipx list --short 2>/dev/null | awk -v wanted="$pkg" '$1 == wanted {found=1} END {exit !found}'; then
            ((installed++))
        else
            warn "$pkg is recorded by CSTK but is not installed in this pipx environment."
        fi
    done
    info "$installed recorded pipx application(s) will query their indexes if update is approved."
}

update_python_tools() {
    local pkg

    echo -e "${C}\nUpdating recorded Python applications${X}"
    [[ "${#PYTHON_PACKAGES[@]}" -gt 0 ]] || return 0
    command -v pipx >/dev/null 2>&1 || {
        fail "pipx is unavailable."
        return 1
    }

    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if ! pipx list --short 2>/dev/null | awk -v wanted="$pkg" '$1 == wanted {found=1} END {exit !found}'; then
            warn "Skipping missing pipx application: $pkg"
            continue
        fi
        if pipx upgrade --include-injected "$pkg" >"$log_dir/pipx_${pkg}.log" 2>&1; then
            ok "$pkg checked and updated through pipx."
        else
            fail "pipx could not update $pkg; see the update log."
        fi
    done
}

check_github_tools() {
    local tool

    echo -e "${C}\nGitHub and Go tool check${X}"
    if [[ "${#GITHUB_TOOLS[@]}" -eq 0 ]]; then
        info "No CSTK-installed GitHub or Go tools are recorded."
        return 0
    fi

    for tool in "${GITHUB_TOOLS[@]}"; do
        case "$tool" in
            katana)
                info "katana is recorded; its latest Go module will be resolved if update is approved."
                ;;
            mimipenguin)
                check_git_repo mimipenguin "$home_dir/Other/Downloads/mimipenguin" || true
                ;;
            shc)
                check_git_repo shc "$home_dir/Other/Downloads/shc" || true
                ;;
            vulscan)
                check_git_repo vulscan /usr/share/nmap/scripts/vulscan || true
                ;;
            *)
                warn "No verified update recipe exists for recorded tool '$tool'; it will be skipped."
                ;;
        esac
    done
}

update_katana() {
    local katana_path

    command -v go >/dev/null 2>&1 || {
        fail "Go is unavailable; katana cannot be updated."
        return 1
    }
    if CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest \
        >"$log_dir/katana_update.log" 2>&1; then
        katana_path="$(go env GOPATH)/bin/katana"
        if [[ -x "$katana_path" ]]; then
            ok "katana updated through its verified Go module path."
        else
            fail "katana update completed but the expected binary is missing: $katana_path"
        fi
    else
        fail "katana update failed; see $log_dir/katana_update.log"
    fi
}

update_mimipenguin() {
    local path="$home_dir/Other/Downloads/mimipenguin"

    update_git_repo mimipenguin "$path" || return 0
    [[ "$REPO_CHANGED" -eq 1 ]] || return 0
    if make -C "$path" >"$log_dir/mimipenguin_build.log" 2>&1; then
        [[ -f "$path/mimipenguin.sh" ]] && install -m 0755 "$path/mimipenguin.sh" /usr/local/bin/mimipenguin.sh
        [[ -f "$path/mimipenguin.py" ]] && install -m 0755 "$path/mimipenguin.py" /usr/local/bin/mimipenguin.py
        ok "mimipenguin rebuilt and installed."
    else
        fail "mimipenguin updated but its rebuild failed; see the update log."
    fi
}

update_shc() {
    local path="$home_dir/Other/Downloads/shc"

    update_git_repo shc "$path" || return 0
    [[ "$REPO_CHANGED" -eq 1 ]] || return 0
    if (
        cd "$path" || exit 1
        autoreconf -fiv && ./configure && make && make install
    ) >"$log_dir/shc_build.log" 2>&1; then
        ok "shc rebuilt and installed."
    else
        fail "shc updated but its rebuild failed; see the update log."
    fi
}

update_vulscan() {
    update_git_repo vulscan /usr/share/nmap/scripts/vulscan || return 0
    [[ "$REPO_CHANGED" -eq 1 ]] || return 0
    if nmap --script-updatedb >"$log_dir/nmap_script_update.log" 2>&1; then
        ok "Nmap script database refreshed for vulscan."
    else
        fail "vulscan updated but Nmap's script database refresh failed."
    fi
}

update_github_tools() {
    local tool

    echo -e "${C}\nUpdating recorded GitHub and Go tools${X}"
    for tool in "${GITHUB_TOOLS[@]}"; do
        case "$tool" in
            katana) update_katana ;;
            mimipenguin) update_mimipenguin ;;
            shc) update_shc ;;
            vulscan) update_vulscan ;;
            *) warn "Skipped '$tool' because it has no verified update recipe." ;;
        esac
    done
}

check_cstk_self_update() {
    echo -e "${C}\nCSTK self-update check${X}"
    check_git_repo CSTK "$home_dir" || true
    if [[ "$REPO_STATE" == "not-git" ]]; then
        self_update_blocked=1
        echo -e "${Y}CSTK self-update requires an authenticated Git checkout.${X}"
        echo "This copy contains no .git metadata, so CSTK will not overwrite it from an archive."
    fi
}

refresh_installed_interfaces() {
    local manual="$home_dir/scripts/lib/cstk.1"
    local completion="$home_dir/scripts/lib/tab_complete.cstk"
    local wrapper="$home_dir/scripts/lib/cstk_wrapper"
    local system_completion="/usr/share/bash-completion/completions/_cstk"

    if [[ ! -f "$wrapper" ]]; then
        fail "CSTK wrapper template is missing: $wrapper"
        return 1
    fi
    install -m 0750 "$wrapper" /usr/local/bin/cstk_wrapper || return 1

    if [[ -f "$manual" ]]; then
        install -m 0644 "$manual" /usr/share/man/man1/cstk.1 || return 1
        gzip -f /usr/share/man/man1/cstk.1 || return 1
        command -v mandb >/dev/null 2>&1 && mandb >/dev/null 2>&1
    fi
    if [[ -f "$completion" && -e "$system_completion" ]]; then
        install -m 0644 "$completion" "$system_completion" || return 1
    fi
}

update_cstk_self() {
    local before after

    echo -e "${C}\nUpdating CSTK${X}"
    if [[ ! -d "$home_dir/.git" ]]; then
        warn "CSTK self-update skipped: the current installation is not a Git checkout."
        self_update_blocked=1
        return 2
    fi
    if [[ -n "$(repo_git "$home_dir" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
        warn "CSTK self-update skipped because tracked local changes are present."
        self_update_blocked=1
        return 2
    fi
    before="$(repo_git "$home_dir" rev-parse HEAD)" || return 1
    update_git_repo CSTK "$home_dir" || {
        self_update_blocked=1
        return 2
    }
    after="$(repo_git "$home_dir" rev-parse HEAD)" || return 1
    if [[ "$before" != "$after" ]]; then
        self_updated=1
        printf 'previous=%s\nupdated=%s\n' "$before" "$after" >"$log_dir/cstk_commits.log"
        refresh_installed_interfaces || warn "CSTK updated, but an installed manual or completion file could not be refreshed."
        ok "CSTK files updated. The launcher will require the private integrity refresh key before continuing."
    fi
}

confirm_update() {
    local answer

    echo
    echo -e "${Y}The update can download packages and execute verified upstream build steps as root.${X}"
    echo "CSTK will preserve local data, Bank contents, logs, authentication settings, and keys."
    read -r -p "Continue with all recorded CSTK updates? [y/N]: " answer
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

print_summary() {
    echo -e "${C}\nUpdate summary${X}"
    echo "  Warnings: $warnings"
    echo "  Failures: $failures"
    echo "  Logs: $log_dir"
    if [[ "$self_update_blocked" -eq 1 ]]; then
        echo -e "${Y}  CSTK self-update: blocked until this installation has an authenticated Git checkout.${X}"
    fi
}

main() {
    case "$mode" in
        check|update|sync-runtime) ;;
        *)
            echo "Usage: cstk_update.sh {check|update|sync-runtime} [CSTK directory]" >&2
            return 2
            ;;
    esac

    require_root
    validate_home

    if [[ "$mode" == "sync-runtime" ]]; then
        refresh_installed_interfaces
        return $?
    fi

    load_registries
    print_scope
    check_system_packages
    check_python_tools
    check_github_tools
    check_cstk_self_update

    if [[ "$mode" == "check" ]]; then
        print_summary
        return 0
    fi

    if ! confirm_update; then
        echo -e "${Y}Update cancelled; no package or source updates were installed.${X}"
        return 0
    fi

    update_system_packages
    update_python_tools
    update_github_tools
    refresh_installed_interfaces || warn "An installed CSTK manual or completion file could not be refreshed."
    update_cstk_self || true
    print_summary

    if [[ "$self_updated" -eq 1 ]]; then
        return 20
    fi
    if [[ "$failures" -gt 0 ]]; then
        return 1
    fi
    if [[ "$self_update_blocked" -eq 1 ]]; then
        return 2
    fi
}

main "$@"
