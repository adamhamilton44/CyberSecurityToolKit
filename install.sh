#!/bin/bash

# Date: 7/10/2026
# Creator: AdamHamilton44
# Reason: Used as a secondary script in the CyberSecurityToolKit
# URL: https://github.com/adamhamilton44/CyberSecurityToolKit
#
# shellcheck disable=SC1003,SC2016,SC1090

set -o pipefail

# Colors
R=$'\e[1;31m'   # Red
G=$'\e[1;32m'   # Green
Y=$'\e[1;33m'   # Yellow
C=$'\e[1;36m'   # Cyan
X=$'\e[0m'      # Reset

# Directory structure
home_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/install_state.sh
source "$home_dir/scripts/lib/install_state.sh" || exit 1

# Package management, GitHub, and Python downloads are recorded in hidden files.
python_install_file="$home_dir/Other/SecurityChecks/.python_pipx_installed_tools"
package_management_install_file="$home_dir/Other/SecurityChecks/.package_management_installed_tools"
github_install_file="$home_dir/Other/SecurityChecks/.github_installed_tools"
lib_key_dir="/etc/cstk"
lib_decryption_key="$lib_key_dir/lib_decryption.key"
cstk_owner_uid=""
cstk_owner_gid=""
cstk_user=""
cstk_group=""
cstk_user_home=""

config_dirs() {
    # All paths are absolute: a clone need not have a particular folder name.
    [[ -f "$home_dir/cstk.sh" && -f "$home_dir/uninstall.sh" &&
       -d "$home_dir/scripts/lib" && -d "$home_dir/scripts/bin" ]] || {
        echo 'Incomplete CSTK checkout.' >&2
        return 1
    }
}

resolve_cstk_account() {
    local preferred_user passwd_record

    cstk_owner_uid="$(stat -c '%u' -- "$home_dir")" || return 1
    cstk_owner_gid="$(stat -c '%g' -- "$home_dir")" || return 1

    if ! [[ "$cstk_owner_uid" =~ ^[0-9]+$ && "$cstk_owner_gid" =~ ^[0-9]+$ ]]; then
        echo -e "${R}[ ERROR ] Unable to determine the CSTK checkout owner.${X}"
        return 1
    fi

    preferred_user="${SUDO_USER:-}"
    if [[ -n "$preferred_user" && "$preferred_user" != "root" && "$preferred_user" != "nobody" ]]; then
        passwd_record="$(getent passwd "$preferred_user")" || passwd_record=""
    else
        passwd_record=""
    fi

    if [[ -z "$passwd_record" ]]; then
        passwd_record="$(getent passwd "$cstk_owner_uid")" || {
            echo -e "${R}[ ERROR ] Unable to find the CSTK checkout owner account.${X}"
            return 1
        }
    fi

    IFS=: read -r cstk_user _ _ _ _ cstk_user_home _ <<<"$passwd_record"
    cstk_group="$(id -gn "$cstk_user")" || return 1
    cstk_user_home="$(realpath -e "$cstk_user_home")" || return 1

    if [[ -z "$cstk_user" || -z "$cstk_group" ||
          "$cstk_user_home" != /* || ! -d "$cstk_user_home" ]]; then
        echo -e "${R}[ ERROR ] The CSTK checkout owner does not have a usable account.${X}"
        return 1
    fi
}

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Root privileges are required."
        echo "Requesting sudo access..."
        exec sudo bash "${BASH_SOURCE[0]}" "$@"
    fi
}

bash_version() {
    if (( BASH_VERSINFO[0] < 4 )); then
        echo 'CSTK requires Bash 4 or newer.' >&2
        return 1
    fi
}

check_working_dir() {
    local base_dir expected_dir

    base_dir="$(basename "$home_dir")"
    expected_dir="CyberSecurityToolKit"

    if [[ "$base_dir" != "$expected_dir" ]]; then
        cd "$home_dir" || exit 1
    fi
}

keep_sudo_alive() {
    while true; do
        sudo -n -v >/dev/null 2>&1 || break
        sleep 300
    done
}

verify_launcher_link() {
    local expected actual
    expected=$(realpath -e -- "$home_dir/cstk.sh") || return 1
    actual=$(readlink -e -- /usr/local/bin/cstk) || return 1
    [[ -L /usr/local/bin/cstk && -f /usr/local/bin/cstk &&
       -x /usr/local/bin/cstk && "$actual" == "$expected" ]] || {
        echo 'CSTK launcher must be an executable symlink to this checkout.' >&2
        return 1
    }
}

link_main_script() {
    # Check the live destination even when a previous run journaled it already.
    if [[ -e /usr/local/bin/cstk && ! -L /usr/local/bin/cstk &&
          ! -f /usr/local/bin/cstk ]]; then
        echo 'Cannot install launcher: /usr/local/bin/cstk is a directory or special file. Preserve and inspect it before retrying.' >&2
        return 1
    fi
    [[ -f "$home_dir/cstk.sh" && -x "$home_dir/cstk.sh" ]] || {
        echo 'The checkout cstk.sh is missing or not executable.' >&2
        return 1
    }
    cstk_track_path /usr/local/bin/cstk || return 1
    # -T treats the destination as exactly this path, never as a target directory.
    ln -sfnT -- "$home_dir/cstk.sh" /usr/local/bin/cstk || return 1
    verify_launcher_link || return 1
    echo -e "${G}[ 📌 ] The main script cstk.sh is now accessible globally.${X}"
    echo -e "${G}You can run it using 'sudo cstk'.${X}"
    read -r -p "Press Enter to continue..."
}

verify_installed_launcher() {
    local logfile="$home_dir/log/launcher_check.log"
    verify_launcher_link || return 1
    local command_path
    hash -r
    command_path=$(command -v cstk) || {
        echo 'CSTK exists at /usr/local/bin/cstk, but the installer PATH cannot find it. Check sudo secure_path includes /usr/local/bin. No sudoers policy was changed.' >&2
        return 1
    }
    [[ $(readlink -e -- "$command_path") == $(realpath -e -- "$home_dir/cstk.sh") ]] || {
        echo "Another cstk command shadows this checkout: $command_path" >&2
        return 1
    }
    [[ -f /usr/local/bin/cstk_wrapper && ! -L /usr/local/bin/cstk_wrapper &&
       -x /usr/local/bin/cstk_wrapper ]] || return 1
    cmp -s -- "$home_dir/scripts/lib/cstk_wrapper" /usr/local/bin/cstk_wrapper || return 1
    if ! timeout -k 2 15 /usr/local/bin/cstk --help > "$logfile" 2>&1 ||
       ! grep -Fq 'SYNOPSIS:' "$logfile"; then
        echo "CSTK launcher self-check failed. Log: $logfile" >&2
        return 1
    fi
}

make_dir() {
    local dir
    local user_data_dir user_loot user_malware user_logs user_keys

    if [[ -z "$cstk_user_home" || "$cstk_user_home" != /* || ! -d "$cstk_user_home" ]]; then
        echo -e "${R}[ ERROR ] The invoking user does not have a usable home directory.${X}"
        exit 1
    fi

    user_data_dir="$cstk_user_home/.local/share/cstk"
    user_loot="$user_data_dir/Loot"
    user_malware="$user_data_dir/Malware"
    user_logs="$user_data_dir/Logs"
    user_keys="$user_data_dir/Keys"

    if [[ "$(realpath -m "$user_data_dir")" != "$user_data_dir" ]]; then
        echo -e "${R}[ ERROR ] The private CSTK data path must stay inside the user home directory.${X}"
        exit 1
    fi

    for dir in "$user_data_dir" "$user_loot" "$user_malware" "$user_logs" "$user_keys"; do
        if [[ -L "$dir" ]]; then
            echo -e "${R}[ ERROR ] Refusing symbolic-link private data path: $dir.${X}"
            exit 1
        fi
    done

    if [[ "$cstk_user" == "root" ]]; then
        mkdir -p -- "$user_loot" "$user_malware" "$user_logs" "$user_keys"
    elif command -v runuser >/dev/null 2>&1; then
        runuser -u "$cstk_user" -- mkdir -p -- "$user_loot" "$user_malware" "$user_logs" "$user_keys"
    else
        sudo -u "$cstk_user" -- mkdir -p -- "$user_loot" "$user_malware" "$user_logs" "$user_keys"
    fi || {
        echo -e "${R}[ ERROR ] Unable to create private CSTK data folders.${X}"
        exit 1
    }

    if ! chown -R -P -- "$cstk_user:$cstk_group" "$user_data_dir" ||
       ! chmod -R go-rwx -- "$user_data_dir" ||
       ! chmod 700 -- "$user_data_dir" "$user_loot" "$user_malware" "$user_logs" "$user_keys"; then
        echo -e "${R}[ ERROR ] Unable to secure private CSTK data folders.${X}"
        exit 1
    fi

    mkdir -p \
        "$home_dir/Other/SecurityChecks" \
        "$home_dir/Other/Downloads" \
        "$home_dir/log"
}

verify_lib_decryption_key() {
    local candidate_key encrypted_probe
    local -a encrypted_resources
    candidate_key="$1"
    [[ -f "$candidate_key" && -r "$candidate_key" ]] || return 1
    encrypted_resources=("$home_dir"/scripts/lib/*.enc)
    for encrypted_probe in "${encrypted_resources[@]}"; do
        [[ -f "$encrypted_probe" ]] || return 1
        openssl enc -d -aes-256-cbc -salt -pbkdf2 \
            -in "$encrypted_probe" -out /dev/null \
            -pass file:"$candidate_key" 2>/dev/null || return 1
    done
}

remove_lib_provisioners() {
    rm -f -- "$home_dir/scripts/provision/cstk-provision-x86_64" \
        "$home_dir/scripts/provision/cstk-provision-aarch64"
}

provision_bundled_lib_key() {
    local arch helper staging
    arch="$(uname -m)" || return 1
    case "$arch" in
        x86_64|aarch64) ;;
        arm64) arch=aarch64 ;;
        *) return 2 ;;
    esac
    helper="$home_dir/scripts/provision/cstk-provision-$arch"
    [[ -f "$helper" && ! -L "$helper" ]] || return 2
    staging="$(mktemp -d "$lib_key_dir/.provision.XXXXXX")" || return 1
    if ! chmod 700 "$helper" || ! "$helper" "$staging" ||
       ! verify_lib_decryption_key "$staging/lib_decryption.key"; then
        rm -f -- "$staging/lib_decryption.key"
        rmdir -- "$staging"
        echo -e "${R}[ ❌ ] Bundled library key provisioning failed.${X}" >&2
        return 1
    fi
    if ! install -m 600 -o root -g root -- \
        "$staging/lib_decryption.key" "$lib_decryption_key"; then
        rm -f -- "$staging/lib_decryption.key"
        rmdir -- "$staging"
        return 1
    fi
    rm -f -- "$staging/lib_decryption.key"
    rmdir -- "$staging" || return 1
    remove_lib_provisioners
}

install_lib_decryption_key() {
    local first_key second_key source_key temp_key provision_status

    command -v openssl >/dev/null 2>&1 || {
        echo -e "${R}[ ❌ ] Install OpenSSL before running the CSTK installer.${X}" >&2
        return 1
    }
    if [[ -L "$lib_key_dir" || ( -e "$lib_key_dir" && ! -d "$lib_key_dir" ) ]]; then
        echo -e "${R}[ ❌ ] Refusing an unsafe CSTK key directory.${X}" >&2
        return 1
    fi
    install -d -m 700 -o root -g root "$lib_key_dir" || {
        echo -e "${R}[ ❌ ] Failed to create $lib_key_dir.${X}"
        return 1
    }

    if [[ -L "$lib_decryption_key" || ( -e "$lib_decryption_key" && ! -f "$lib_decryption_key" ) ]]; then
        echo -e "${R}[ ❌ ] Refusing to use a symbolic link as the library key file.${X}"
        return 1
    fi

    if [[ -s "$lib_decryption_key" ]]; then
        chown root:root "$lib_decryption_key" || return 1
        chmod 600 "$lib_decryption_key" || return 1
        if ! verify_lib_decryption_key "$lib_decryption_key"; then
            echo -e "${R}[ ❌ ] The installed CSTK library key cannot decrypt the protected resources.${X}"
            return 1
        fi
        remove_lib_provisioners || return 1
        return 0
    fi

    source_key="${CSTK_LIB_KEY_SOURCE:-}"
    if [[ -n "$source_key" ]]; then
        if [[ -L "$source_key" || ! -f "$source_key" || ! -r "$source_key" ]]; then
            echo -e "${R}[ ❌ ] CSTK_LIB_KEY_SOURCE is not a readable regular file.${X}"
            return 1
        fi
        if ! verify_lib_decryption_key "$source_key"; then
            echo -e "${R}[ ❌ ] The supplied key cannot decrypt the protected CSTK resources.${X}"
            return 1
        fi
        install -m 600 -o root -g root -- "$source_key" "$lib_decryption_key" || return 1
        remove_lib_provisioners || return 1
        return 0
    fi

    if provision_bundled_lib_key; then
        return 0
    else
        provision_status=$?
        [[ "$provision_status" -eq 2 ]] || return 1
    fi

    if [[ ! -t 0 ]]; then
        echo -e "${R}[ ❌ ] No CSTK library key is installed and no terminal is available.${X}"
        echo -e "${Y}Set CSTK_LIB_KEY_SOURCE to a protected key file and run the installer again.${X}"
        return 1
    fi

    echo -e "${Y}The encrypted CSTK library files require the owner's decryption key.${X}"
    read -r -s -p "Enter the CSTK library decryption key: " first_key
    echo
    read -r -s -p "Enter it again to confirm: " second_key
    echo

    if [[ -z "$first_key" || "$first_key" != "$second_key" ]]; then
        unset first_key second_key
        echo -e "${R}[ ❌ ] The keys were empty or did not match.${X}"
        return 1
    fi

    temp_key="$(mktemp "$lib_key_dir/.lib_decryption.key.XXXXXX")" || {
        unset first_key second_key
        return 1
    }
    if ! printf '%s\n' "$first_key" > "$temp_key"; then
        unset first_key second_key
        rm -f -- "$temp_key"
        return 1
    fi
    unset first_key second_key

    if ! verify_lib_decryption_key "$temp_key"; then
        rm -f -- "$temp_key"
        echo -e "${R}[ ❌ ] That key cannot decrypt the protected CSTK resources.${X}"
        return 1
    fi

    chown root:root "$temp_key" || return 1
    chmod 600 "$temp_key" || return 1
    mv -f -- "$temp_key" "$lib_decryption_key" || return 1
    remove_lib_provisioners
}

pipx_install() {
    local package="$1"
    local command_name="${2:-$1}"
    local installed_apps

    if command -v "$command_name" >/dev/null 2>&1; then
        echo -e "${G}[ ✔  ] ${command_name} is already installed.${X}"
        return 0
    fi

    if ! command -v pipx >/dev/null 2>&1; then
        echo -e "${R}[ ❌ ] pipx is not installed.${X}"
        return 1
    fi

    installed_apps=$(pipx list --short) || return 1
    if awk -v wanted="$package" '$1 == wanted {found=1} END {exit !found}' <<< "$installed_apps"; then
        echo -e "${G}[ ✔  ] ${package} is already installed.${X}"
    else
        echo -e "${C}[ 📌 ] Installing ${package}${X}"

        if pipx install "$package"; then
            echo "$package" >> "$python_install_file" || return 1
            echo -e "${G}[ ✅ ] ${package} installed successfully.${X}"
        else
            echo -e "${R}[ ❌ ] Failed to install ${package}.${X}"
            return 1
        fi
    fi
}

pipx_run_install() {
    pipx_install droopescan || return 1
    pipx_install holehe || return 1
}

install_man_page() {
    local src dest

    src="$home_dir/scripts/lib/cstk.1"
    dest="/usr/share/man/man1/cstk.1"

    if [[ -f "$src" ]]; then
        install -d -m 755 /usr/share/man/man1 || return 1
        cstk_track_path "$dest.gz" || return 1
        cstk_install_file 644 "$src" "$dest" || {
            echo -e "${R}[ ❌ ] Failed to install the CSTK man page.${X}"
            return 1
        }

        gzip -f "$dest" || {
            echo -e "${R}[ ❌ ] Failed to compress the CSTK man page.${X}"
            return 1
        }

        if command -v mandb >/dev/null 2>&1; then mandb >/dev/null 2>&1 || true; fi

        echo -e "${G}[ ✅ ] Installed man page to ${dest}.gz${X}"
    else
        echo -e "${R}[ ❌ ] Man page not found: $src${X}"
        return 1
    fi
}

install_nrich() {
    local url file os arch newname
    local download_file

    if command -v nrich >/dev/null 2>&1; then
        echo -e "${G}[ ✔  ] nrich is already installed.${X}"
        return 0
    fi
    echo -e "${G}[ 📌 ] Installing nrich...${X}"
    mkdir -p "$home_dir/Other/Downloads"
    pushd "$home_dir/Other/Downloads" >/dev/null || return 1

    os="$(uname -s)"
    arch="$(uname -m)"
    newname="nrich"
    url="https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest"

    case "$os" in

        Linux)
            case "$arch" in
                x86_64|amd64)
                    ;;
                *)
                    echo -e "${R}[ ❌ ] nrich does not provide a Linux binary for architecture: $arch${X}"
                    popd >/dev/null || return
                    return 1
                    ;;
            esac

            if command -v dpkg >/dev/null 2>&1; then

                file="nrich_latest_x86_64.deb"
                download_file="$newname.deb"

                if wget -q --show-progress -O "$download_file" "$url/$file"; then
                    if cstk_package_transaction apt-get dpkg -i "$download_file"; then
                        :
                    else
                        echo -e "${Y}[ ⚠️ ] dpkg reported dependency issues. Attempting to fix them...${X}"
                        cstk_package_transaction apt-get apt-get install -f -y >/dev/null 2>&1 || { popd >/dev/null || return 1; return 1; }
                    fi
                else
                    echo -e "${R}[ ❌ ] Failed to download nrich.${X}"
                    popd >/dev/null || return
                    return 1
                fi

            elif command -v dnf >/dev/null 2>&1; then

                file="nrich_latest_x86-64.rpm"
                download_file="$newname.rpm"

                wget -q --show-progress -O "$download_file" "$url/$file" &&
                    cstk_package_transaction dnf dnf install -y "./$download_file" || { popd >/dev/null || return 1; return 1; }

            elif command -v yum >/dev/null 2>&1; then

                file="nrich_latest_x86-64.rpm"
                download_file="$newname.rpm"

                wget -q --show-progress -O "$download_file" "$url/$file" &&
                    cstk_package_transaction yum yum localinstall -y "./$download_file" || { popd >/dev/null || return 1; return 1; }

            elif command -v rpm >/dev/null 2>&1; then

                file="nrich_latest_x86-64.rpm"
                download_file="$newname.rpm"

                wget -q --show-progress -O "$download_file" "$url/$file" &&
                    cstk_package_transaction dnf rpm -Uvh "$download_file" || { popd >/dev/null || return 1; return 1; }

            elif command -v brew >/dev/null 2>&1; then

                echo -e "${C}[ 📌 ] Installing nrich through Homebrew.${X}"

                if cstk_brew_tap shodan-public/homebrew-shodan \
                    https://gitlab.com/shodan-public/homebrew-shodan &&
                    cstk_package_transaction brew brew install nrich; then
                    :
                else
                    echo -e "${R}[ ❌ ] Failed to install nrich with Homebrew.${X}"
                    popd >/dev/null || return
                    return 1
                fi

            else
                echo -e "${R}[ ❌ ] Unsupported Linux package manager.${X}"
                popd >/dev/null || return
                return 1
            fi
            ;;

        Darwin)
            case "$arch" in
                arm64)
                    file="nrich_latest_Darwin-ARM64.tar.gz"
                    ;;
                x86_64|amd64)
                    file="nrich_latest_Darwin-x86-64.tar.gz"
                    ;;
                *)
                    echo -e "${R}[ ❌ ] Unsupported macOS architecture: $arch${X}"
                    popd >/dev/null || return
                    return 1
                    ;;
            esac

            download_file="$newname.tar.gz"

            if wget -q --show-progress -O "$download_file" "$url/$file"; then
                if tar -xzf "$download_file"; then
                    cstk_install_file 755 nrich /usr/local/bin/nrich || return 1
                else
                    echo -e "${R}[ ❌ ] Failed to extract nrich.${X}"
                    popd >/dev/null || return
                    return 1
                fi
            else
                echo -e "${R}[ ❌ ] Failed to download nrich.${X}"
                popd >/dev/null || return
                return 1
            fi
            ;;

        *)
            echo -e "${R}[ ❌ ] Unsupported operating system: $os${X}"
            popd >/dev/null || return
            return 1
            ;;
    esac

    if command -v nrich >/dev/null 2>&1; then
        echo -e "${G}[ ✅ ] nrich installed successfully.${X}"
        echo "nrich" >> "$github_install_file"
    else
        echo -e "${R}[ ❌ ] Failed to install nrich.${X}"
        popd >/dev/null || return
        return 1
    fi

    rm -f "$newname.deb" "$newname.rpm" "$newname.tar.gz"

    popd >/dev/null || return
}

# Translate the Debian/Kali dependency names used by CSTK into package names
# used by the other supported package-manager families.  Each line is an
# alternative for the same dependency, in preferred order.  The Debian name is
# kept as the final fallback when another distribution may provide it unchanged.
package_candidates() {
    local pkg="$1"
    local pkg_type="$2"

    case "$pkg_type:$pkg" in
        deb:7zip|deb:p7zip-full)
            printf '%s\n' 7zip p7zip-full
            ;;
        deb:default-mysql-client)
            printf '%s\n' default-mysql-client mariadb-client mysql-client
            ;;

        rpm:7zip)
            printf '%s\n' 7zip p7zip-plugins p7zip
            ;;
        rpm:p7zip-full)
            printf '%s\n' 7zip p7zip-plugins p7zip "$pkg"
            ;;
        rpm:apache-users)
            printf '%s\n' httpd-tools "$pkg"
            ;;
        rpm:build-essential)
            printf '%s\n' gcc-c++ "$pkg"
            ;;
        rpm:default-mysql-client)
            printf '%s\n' mariadb mariadb-client mysql-community-client mysql "$pkg"
            ;;
        rpm:golang-any)
            printf '%s\n' golang "$pkg"
            ;;
        rpm:ldap-utils)
            printf '%s\n' openldap-clients "$pkg"
            ;;
        rpm:libc6-dev)
            printf '%s\n' glibc-devel "$pkg"
            ;;
        rpm:mongosh)
            printf '%s\n' mongodb-mongosh "$pkg"
            ;;
        rpm:mysql-common)
            printf '%s\n' mariadb-common "$pkg"
            ;;
        rpm:ncat)
            printf '%s\n' nmap-ncat "$pkg"
            ;;
        rpm:openssh-client)
            printf '%s\n' openssh-clients "$pkg"
            ;;
        rpm:postgresql-client)
            printf '%s\n' postgresql "$pkg"
            ;;
        rpm:pyenv-runtime)
            printf '%s\n' pyenv "$pkg"
            ;;
        rpm:redis)
            printf '%s\n' valkey-compat-redis redis
            ;;
        rpm:redis-tools)
            printf '%s\n' valkey-compat-redis redis "$pkg"
            ;;
        rpm:whiptail)
            printf '%s\n' newt "$pkg"
            ;;
        rpm:xxd)
            printf '%s\n' xxd vim-common
            ;;

        brew:7zip|brew:p7zip-full)
            printf '%s\n' sevenzip p7zip "$pkg"
            ;;
        brew:apache-users)
            printf '%s\n' httpd "$pkg"
            ;;
        brew:build-essential)
            # make is also a separate CSTK dependency.
            printf '%s\n' gcc "$pkg"
            ;;
        brew:default-mysql-client)
            printf '%s\n' mysql-client mysql mariadb "$pkg"
            ;;
        brew:golang|brew:golang-any)
            printf '%s\n' go "$pkg"
            ;;
        brew:ldap-utils)
            printf '%s\n' openldap "$pkg"
            ;;
        brew:libc6-dev)
            # macOS supplies its C library headers through the Command Line Tools.
            ;;
        brew:mysql-common)
            printf '%s\n' mariadb-connector-c mysql-client "$pkg"
            ;;
        brew:ncat)
            printf '%s\n' nmap "$pkg"
            ;;
        brew:openssh-client|brew:openssh-server)
            printf '%s\n' openssh "$pkg"
            ;;
        brew:openssl)
            printf '%s\n' openssl@3 "$pkg"
            ;;
        brew:postgresql-client)
            printf '%s\n' libpq postgresql "$pkg"
            ;;
        brew:pyenv-runtime)
            printf '%s\n' pyenv "$pkg"
            ;;
        brew:python3|brew:python3-pip)
            printf '%s\n' python "$pkg"
            ;;
        brew:redis-tools)
            printf '%s\n' redis "$pkg"
            ;;
        brew:sed)
            printf '%s\n' gnu-sed "$pkg"
            ;;
        brew:tar)
            printf '%s\n' gnu-tar "$pkg"
            ;;
        brew:whiptail)
            printf '%s\n' newt "$pkg"
            ;;
        brew:xxd)
            printf '%s\n' vim xxd
            ;;

        *)
            printf '%s\n' "$pkg"
            ;;
    esac
}

install_dependencies() {
    local PACKAGE_MANAGER PKG_TYPE
    local pkg pid er failures=0
    local -a candidates
    local log_dir="$home_dir/log/package_manager"

    mkdir -p "$log_dir" || return 1
    touch "$package_management_install_file" || return 1

    spinner() {
        local pid="$1"
        local delay=0.1
        local spinstr='|/-\'
        local temp

        while kill -0 "$pid" 2>/dev/null; do
            temp="${spinstr#?}"
            printf " [%c]  " "$spinstr"
            spinstr="${temp}${spinstr%"$temp"}"
            sleep "$delay"
            printf "\b\b\b\b\b\b"
        done
    }
    # Install a package and preserve its individual log.
    install_pkg() {
        local pkg="$1"
        local logfile="$log_dir/${pkg//\//_}.log"
        local retry=0

        echo -e "${C}[ 📌 ] Installing $pkg${X}"
        while (( retry < 2 )); do
            case "$PKG_TYPE" in
                deb)
                    (
                        export DEBIAN_FRONTEND=noninteractive

                        cstk_package_transaction apt-get apt-get install -y \
                            -o Dpkg::Options::="--force-confdef" \
                            -o Dpkg::Options::="--force-confold" \
                            "$pkg"
                    ) >"$logfile" 2>&1 &
                    ;;

                rpm)
                    (
                        cstk_package_transaction "$PACKAGE_MANAGER" "$PACKAGE_MANAGER" install -y "$pkg"
                    ) >"$logfile" 2>&1 &
                    ;;

                brew)
                    (
                        HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 cstk_package_transaction brew brew install "$pkg"
                    ) >"$logfile" 2>&1 &
                    ;;

                *)
                    echo -e "${R}[ ❌ ] Unknown package-manager type.${X}"
                    return 1
                    ;;
            esac

            pid=$!
            spinner "$pid"

            wait "$pid"
            er=$?

            if [[ "$er" -eq 0 ]]; then
                echo -e "${G}[ ✅ ] Installed: $pkg${X}"
                echo "$pkg" >> "$package_management_install_file" || return 1
                return 0
            fi
            # APT-specific recovery.
            # If a mirror/index changed while installing packages,
            # refresh the package lists once and retry the package.
            if [[ "$PKG_TYPE" == "deb" ]] &&
               grep -Eq \
               '404[[:space:]]+Not Found|Unable to fetch some archives|Hash Sum mismatch' \
               "$logfile"; then

                if (( retry == 0 )); then
                    echo -e "${Y}[ ⚠️  ] APT repository information changed while installing $pkg.${X}"
                    echo -e "${Y}[ 🔄 ] Refreshing package lists and retrying once...${X}"

                    DEBIAN_FRONTEND=noninteractive \
                        apt-get update \
                        >"$log_dir/apt_update_retry.log" 2>&1

                    ((retry++))
                    continue
                fi
            fi

            break
        done
        echo -e "${R}[ ❌ ] Failed to install: $pkg${X}"
        echo -e "${Y}[ ℹ️  ] Log: $logfile${X}"
        return 1
    }
    is_pkg_installed() {
        local candidate="$1"

        case "$PKG_TYPE" in
            deb)
                [[ "$(dpkg-query -W -f='${db:Status-Status}' -- "$candidate" 2>/dev/null)" == installed ]]
                ;;
            rpm)
                rpm -q -- "$candidate" &>/dev/null
                ;;
            brew)
                brew list --formula "$candidate" &>/dev/null
                ;;
            *)
                return 1
                ;;
        esac
    }
    # Try the package names for the detected package-manager family.
    try_install_pkg() {
        local logical_pkg="$1"
        local alt
        shift

        for alt in "$@"; do
            if is_pkg_installed "$alt"; then
                echo -e "${G}[ ✔  ] $alt is already installed.${X}"
                return 0
            fi

            if install_pkg "$alt"; then
                return 0
            fi
        done

        echo -e "${R}[ ❌ ] Failed to install $logical_pkg using: $*${X}"
        return 1
    }

    local required_commands=(
        7zip amass apache-users apktool aria2 arjun arp-scan arsenal-ng
        assetfinder autoconf braa build-essential bzip2 cewl commix coreutils
        crackmapexec curl dirb dirsearch dmitry dnsrecon dpkg enum4linux
        exploitdb feroxbuster ffuf fierce fping fzf gcc git
        git-lfs sed gobuster golang gospider grep gzip hashcat
        hping3 httpx-toolkit hydra impacket-scripts john joomscan jq libc6-dev
        lynis make medusa metasploit-framework mxcheck nasm ncrack ncat
        nikto nmap nuclei onesixtyone openssh-client openssl python3 python3-pip
        pipx automake libtool pkg-config wget seclists sherlock skipfish
        smbclient smtp-user-enum snmpcheck sqlmap sslscan subfinder subjack sublist3r
        tar testssl.sh theharvester unrar unzip wafw00f wapiti whatweb
        whois wpscan xxd ldap-utils postgresql-client default-mysql-client redis-tools
    )

    [[ $# -gt 0 ]] && required_commands+=("$@")
    echo -e "${Y}🔧 Installing dependencies...${X}"
    # APT / Debian / Kali
    if command -v apt-get &>/dev/null; then
        PACKAGE_MANAGER="apt-get"
        PKG_TYPE="deb"
        echo -e "${G}[ ✔  ] Package manager detected: apt-get${X}"
        echo -e "${C}[ 📌 ] Checking APT/dpkg state...${X}"
        # Finish configuration of packages that were unpacked but
        # not completely configured during an earlier installation.
        if ! DEBIAN_FRONTEND=noninteractive \
            cstk_package_transaction apt-get dpkg --configure -a \
            >"$log_dir/dpkg_configure.log" 2>&1; then

            echo -e "${Y}[ ⚠️  ] dpkg reported an unfinished package installation.${X}"
        fi
        # Check whether dependencies are currently broken.
        if ! apt-get check >"$log_dir/apt_check.log" 2>&1; then
            echo -e "${Y}[ ⚠️  ] Broken package dependencies detected.${X}"
            echo -e "${C}[ 🔧 ] Attempting automatic repair...${X}"
            if ! DEBIAN_FRONTEND=noninteractive \
                cstk_package_transaction apt-get apt-get --fix-broken install -y \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                >"$log_dir/apt_fix_broken.log" 2>&1; then

                echo -e "${R}[ ❌ ] APT could not repair the package database.${X}"
                echo -e "${Y}[ ℹ️  ] Log: $log_dir/apt_fix_broken.log${X}"
                return 1
            fi
            # Configure anything repaired/unpacked by apt.
            DEBIAN_FRONTEND=noninteractive \
                cstk_package_transaction apt-get dpkg --configure -a \
                >>"$log_dir/dpkg_configure.log" 2>&1
        fi
        # This is critical on Kali Rolling. Package versions move
        # frequently and stale lists commonly produce HTTP 404 errors.
        echo -e "${C}[ 🔄 ] Updating APT package lists...${X}"
        if ! DEBIAN_FRONTEND=noninteractive \
            apt-get update \
            >"$log_dir/apt_update.log" 2>&1; then

            echo -e "${R}[ ❌ ] apt-get update failed.${X}"
            echo -e "${Y}[ ℹ️  ] Log: $log_dir/apt_update.log${X}"
            return 1
        fi
        echo -e "${G}[ ✅ ] APT package lists are current.${X}"
    # DNF
    elif command -v dnf &>/dev/null; then
        PACKAGE_MANAGER="dnf"
        PKG_TYPE="rpm"

        echo -e "${G}[ ✔  ] Package manager detected: dnf${X}"

        dnf makecache -y \
            >"$log_dir/dnf_makecache.log" 2>&1 || return 1
    # YUM
    elif command -v yum &>/dev/null; then

        PACKAGE_MANAGER="yum"
        PKG_TYPE="rpm"

        echo -e "${G}[ ✔  ] Package manager detected: yum${X}"

        yum makecache -y \
            >"$log_dir/yum_makecache.log" 2>&1 || return 1
    # Homebrew
    elif command -v brew &>/dev/null; then

        PACKAGE_MANAGER="brew"
        PKG_TYPE="brew"
        echo -e "${G}[ ✔  ] Package manager detected: brew${X}"
    else
        echo -e "${R}[ ❌ ] No supported package manager found!${X}"
        return 1
    fi
    # Install packages
    for pkg in "${required_commands[@]}"; do
        mapfile -t candidates < <(package_candidates "$pkg" "$PKG_TYPE")

        if [[ "${#candidates[@]}" -eq 0 ]]; then
            echo -e "${G}[ ✔  ] $pkg is supplied by the operating system.${X}"
            continue
        fi

        try_install_pkg "$pkg" "${candidates[@]}" || failures=$((failures + 1))
    done
    # Final package database check
    if [[ "$PKG_TYPE" == "deb" ]]; then

        if ! apt-get check >"$log_dir/apt_final_check.log" 2>&1; then
            echo
            echo -e "${Y}[ ⚠️  ] APT reports unresolved dependencies after installation.${X}"
            echo -e "${Y}[ ℹ️  ] Log: $log_dir/apt_final_check.log${X}"
            failures=$((failures + 1))
        fi

        if [[ -f /var/run/reboot-required ]]; then
            echo
            echo -e "${Y}[ ⚠️  ] A system reboot is recommended.${X}"
            echo -e "${Y}[ ℹ️  ] CSTK will not reboot the machine automatically.${X}"
        fi
    fi
    (( failures == 0 ))
}

install_mongosh() {
    local log_dir log_file package candidate
    local os arch openssl_mode temp_dir metadata_file archive_file
    local release_data url checksum mongosh_bin crypto_lib

    if command -v mongosh >/dev/null 2>&1; then
        echo -e "${G}[ ✔  ] mongosh is already installed.${X}"
        return 0
    fi

    log_dir="$home_dir/log/package_manager"
    log_file="$log_dir/mongosh.log"
    mkdir -p "$log_dir" || return 1
    : > "$log_file"

    # Prefer a configured package repository when it provides mongosh.
    if command -v apt-get >/dev/null 2>&1; then
        for package in mongodb-mongosh mongosh; do
            candidate="$(apt-cache policy "$package" 2>/dev/null |
                awk '/Candidate:/ { print $2; exit }')"
            if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
                continue
            fi

            echo -e "${C}[ 📌 ] Installing $package${X}"
            if DEBIAN_FRONTEND=noninteractive cstk_package_transaction apt-get apt-get install -y \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                "$package" >>"$log_file" 2>&1; then
                grep -Fxq "$package" "$package_management_install_file" ||
                    echo "$package" >> "$package_management_install_file"
                echo -e "${G}[ ✅ ] mongosh installed successfully.${X}"
                return 0
            fi
        done
    elif command -v brew >/dev/null 2>&1; then
        echo -e "${C}[ 📌 ] Installing mongosh through Homebrew.${X}"
        if cstk_brew_tap mongodb/brew >>"$log_file" 2>&1 &&
           HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 cstk_package_transaction brew brew install mongosh >>"$log_file" 2>&1; then
            grep -Fxq mongosh "$package_management_install_file" ||
                echo mongosh >> "$package_management_install_file"
            echo -e "${G}[ ✅ ] mongosh installed successfully.${X}"
            return 0
        fi
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        for package in mongodb-mongosh mongosh; do
            if command -v dnf >/dev/null 2>&1; then
                cstk_package_transaction dnf dnf install -y "$package" >>"$log_file" 2>&1
            else
                cstk_package_transaction yum yum install -y "$package" >>"$log_file" 2>&1
            fi
            if [[ "$?" -eq 0 ]]; then
                grep -Fxq "$package" "$package_management_install_file" ||
                    echo "$package" >> "$package_management_install_file"
                echo -e "${G}[ ✅ ] mongosh installed successfully.${X}"
                return 0
            fi
        done
    fi

    # Kali does not currently ship mongosh. Use MongoDB's official HTTPS release
    # metadata and verify the downloaded archive against its published SHA-256.
    os="$(uname -s)"
    arch="$(uname -m)"
    if [[ "$os" != "Linux" ]]; then
        echo -e "${R}[ ❌ ] No supported mongosh package source is configured.${X}"
        echo -e "${Y}[ ℹ️  ] Log: $log_file${X}"
        return 1
    fi

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            echo -e "${R}[ ❌ ] MongoDB does not publish a CSTK-supported mongosh build for: $arch${X}"
            return 1
            ;;
    esac

    for package in curl jq tar sha256sum; do
        command -v "$package" >/dev/null 2>&1 || {
            echo -e "${R}[ ❌ ] mongosh installation requires: $package${X}"
            return 1
        }
    done

    temp_dir="$(mktemp -d /tmp/cstk-mongosh.XXXXXX)" || return 1
    metadata_file="$temp_dir/mongosh.json"
    archive_file="$temp_dir/mongosh.tgz"

    if ! curl -fsSL --retry 2 --connect-timeout 15 \
        https://downloads.mongodb.com/compass/mongosh.json \
        -o "$metadata_file" >>"$log_file" 2>&1; then
        rm -rf -- "$temp_dir"
        echo -e "${R}[ ❌ ] Failed to download MongoDB release metadata.${X}"
        echo -e "${Y}[ ℹ️  ] Log: $log_file${X}"
        return 1
    fi

    if ldconfig -p 2>/dev/null | grep 'libssl\.so\.3' >/dev/null; then
        openssl_mode="openssl3"
    else
        openssl_mode="bundled"
    fi

    release_data="$(jq -r \
        --arg arch "$arch" \
        --arg openssl_mode "$openssl_mode" \
        '.versions[0].downloads[] |
         select(.distro == "linux" and .arch == $arch) |
         select(if $openssl_mode == "openssl3"
                then .sharedOpenssl == "openssl3"
                else (has("sharedOpenssl") | not)
                end) |
         [.archive.url, .archive.sha256] | @tsv' \
        "$metadata_file" | head -n 1)"
    IFS=$'\t' read -r url checksum <<<"$release_data"

    if [[ "$url" != https://downloads.mongodb.com/* ||
          ! "$checksum" =~ ^[[:xdigit:]]{64}$ ]]; then
        rm -rf -- "$temp_dir"
        echo -e "${R}[ ❌ ] MongoDB release metadata did not contain a valid download.${X}"
        return 1
    fi

    echo -e "${C}[ 📌 ] Downloading the verified MongoDB Shell archive.${X}"
    if ! curl -fsSL --retry 2 --connect-timeout 15 "$url" \
        -o "$archive_file" >>"$log_file" 2>&1 ||
       ! printf '%s  %s\n' "$checksum" "$archive_file" |
            sha256sum -c - >>"$log_file" 2>&1 ||
       ! tar -xzf "$archive_file" -C "$temp_dir" >>"$log_file" 2>&1; then
        rm -rf -- "$temp_dir"
        echo -e "${R}[ ❌ ] Failed to download or verify mongosh.${X}"
        echo -e "${Y}[ ℹ️  ] Log: $log_file${X}"
        return 1
    fi

    mongosh_bin="$(find "$temp_dir" -type f -path '*/bin/mongosh' -print -quit)"
    crypto_lib="$(find "$temp_dir" -type f -path '*/bin/mongosh_crypt_v1.*' -print -quit)"
    if [[ ! -x "$mongosh_bin" ]] ||
       ! "$mongosh_bin" --build-info >>"$log_file" 2>&1; then
        rm -rf -- "$temp_dir"
        echo -e "${R}[ ❌ ] The verified mongosh archive did not contain a working executable.${X}"
        return 1
    fi

    cstk_install_file 0755 "$mongosh_bin" /usr/local/bin/mongosh || {
        rm -rf -- "$temp_dir"
        return 1
    }
    if [[ -n "$crypto_lib" && -f "$crypto_lib" ]]; then
        cstk_install_file 0755 "$crypto_lib" "/usr/local/bin/$(basename "$crypto_lib")" || {
            rm -rf -- "$temp_dir"
            return 1
        }
    fi

    rm -rf -- "$temp_dir"
    grep -Fxq mongosh-archive "$github_install_file" ||
        echo mongosh-archive >> "$github_install_file"
    echo -e "${G}[ ✅ ] mongosh installed successfully from MongoDB's verified archive.${X}"
}

install_mimipenguin() {
    local repo_dir log_dir log_file

    repo_dir="$home_dir/Other/Downloads/mimipenguin"
    log_dir="$home_dir/log/github"
    log_file="$log_dir/mimipenguin_clone.log"
    mkdir -p "$log_dir" || return 1

    if [[ -d "$repo_dir/.git" &&
          ( -f "$repo_dir/mimipenguin.py" || -f "$repo_dir/mimipenguin.sh" ) ]]; then
        echo -e "${G}[ ✔  ] MimiPenguin source is already downloaded.${X}"
    elif [[ -e "$repo_dir" ]]; then
        echo -e "${R}[ ❌ ] MimiPenguin destination exists but is not a valid checkout: $repo_dir${X}"
        return 1
    else
        echo -e "${G}[ 📌 ] Downloading MimiPenguin...${X}"
        if ! git clone --depth 1 \
            https://github.com/huntergregal/mimipenguin.git \
            "$repo_dir" >"$log_file" 2>&1; then
            echo -e "${R}[ ❌ ] Failed to clone MimiPenguin.${X}"
            echo -e "${Y}[ ℹ️  ] Log: $log_file${X}"
            return 1
        fi
    fi

    # CSTK launches the maintained Python or shell implementation directly;
    # the optional C build is not required and needs multilib on 64-bit hosts.
    if [[ -f "$repo_dir/mimipenguin.sh" ]]; then
        [[ -e /usr/local/bin/mimipenguin.sh ]] || cstk_install_file 0755 "$repo_dir/mimipenguin.sh" /usr/local/bin/mimipenguin.sh || return 1
    fi
    if [[ -f "$repo_dir/mimipenguin.py" ]]; then
        [[ -e /usr/local/bin/mimipenguin.py ]] || cstk_install_file 0755 "$repo_dir/mimipenguin.py" /usr/local/bin/mimipenguin.py || return 1
    fi

    grep -Fxq mimipenguin "$github_install_file" ||
        echo mimipenguin >> "$github_install_file"
    echo -e "${G}[ ✅ ] MimiPenguin installed successfully.${X}"
}

install_shc() {

    if ! command -v shc >/dev/null 2>&1; then

        echo -e "${G}[ 📌 ] Installing shc...${X}"

        rm -rf "$home_dir/Other/Downloads/shc"

        git clone \
            https://github.com/neurobin/shc.git \
            "$home_dir/Other/Downloads/shc" &>/dev/null || {
                echo -e "${R}[ ❌ ] Failed to clone shc.${X}"
                return 1
            }

        cd "$home_dir/Other/Downloads/shc" || return 1

        autoreconf -fiv || {
            echo -e "${R}[ ❌ ] autoreconf failed while preparing shc.${X}"
            return 1
        }

        ./configure || {
            echo -e "${R}[ ❌ ] configure failed while preparing shc.${X}"
            return 1
        }

        make && cstk_install_file 755 src/shc /usr/local/bin/shc
        local er=$?

        if [[ "$er" -eq 0 ]]; then
            echo -e "${G}[ ✅ ] shc installed successfully.${X}"
            echo "shc" >> "$github_install_file" || return 1
        else
            echo -e "${R}[ ❌ ] Failed to install shc.${X}"
            exit 1
        fi

        cd "${home_dir}" || return 1

    else
        echo -e "${G}[ ✔  ] shc is already installed.${X}"
    fi
}

install_tab_completion() {

    # Bash: /usr/share/bash-completion/completions/_cstk
    # Zsh:  ~/.zshrc

    local f inv_user inv_home inv_shell passwd_record s target_file
    local ans_user ans_root

    f="$home_dir/scripts/lib/tab_complete.cstk"

    if [[ ! -f "$f" ]]; then
        echo -e "${R}[ ❌ ] Missing $f${X}"
        return 1
    fi

    inv_user="$cstk_user"
    inv_home="$cstk_user_home"
    passwd_record="$(getent passwd "$inv_user")" || return 1
    IFS=: read -r _ _ _ _ _ _ inv_shell <<<"$passwd_record"
    s="${inv_shell##*/}"

    add_to_rc() {

        target_file="$1"

        [[ ! -L "$target_file" ]] || return 1
        if [[ -f "$target_file" ]] && grep -Fxq "source \"$f\"" "$target_file"; then
            return 0
        fi
        printf '%s\n' "$target_file" >> "$cstk_state_dir/completions" || return 1
        if [[ ! -f "$target_file" ]]; then
            printf '%s\n' "$target_file" >> "$cstk_state_dir/completions-created" || return 1
            touch "$target_file" || return 1
            if [[ "$target_file" == "$inv_home/"* ]]; then
                chown "$cstk_user:$cstk_group" "$target_file" || return 1
            fi
        fi
        if [[ -s "$target_file" && -n "$(tail -c 1 "$target_file")" ]]; then
            printf '\n' >> "$target_file" || return 1
        fi
        printf 'source "%s"\n' "$f" >> "$target_file" || return 1

        echo -e "${G}[ ✅ ] Added to $target_file${X}"
    }

    echo
    echo "=== CSTK Tab Completion Installer ==="
    echo "Completion file: $f"
    echo "Detected user: $inv_user ($inv_home)"
    echo "Detected shell: $s"
    echo

    case "$s" in

        bash|zsh)

            local user_rc="$inv_home/.${s}rc"

            echo "Install CSTK auto-completion for NORMAL USER ($inv_user)?"
            echo "1) Yes"
            echo "2) No"

            read -r ans_user

            case "$ans_user" in
                1)
                    add_to_rc "$user_rc" || return 1
                    ;;
                *)
                    echo -e "${R}[ ❌ ] Skipped for normal user.${X}"
                    ;;
            esac
            ;;

        *)
            echo -e "${Y}[ ⚠️ ] Normal user shell $s is not supported for automatic installation.${X}"
            ;;
    esac

    echo
    echo "Install CSTK auto-completion for ROOT user?"
    echo "1) Yes"
    echo "2) No"

    read -r ans_root

    case "$ans_root" in

        1)
            local root_shell root_rc
            root_shell=$(getent passwd root) || return 1
            root_shell=${root_shell##*:}
            root_shell=${root_shell##*/}
            case "$root_shell" in bash|zsh) ;; *) return 0 ;; esac
            root_rc="/root/.${root_shell}rc"
            add_to_rc "$root_rc" || return 1
            ;;

        *)
            echo -e "${R}[ ❌ ] Skipped for root.${X}"
            ;;
    esac

    echo -e "\nDone."
}

create_wrapper() {

    local WRAPPER_PATH WRAPPER_SOURCE

    WRAPPER_PATH="/usr/local/bin/cstk_wrapper"
    WRAPPER_SOURCE="$home_dir/scripts/lib/cstk_wrapper"

    if [[ ! -f "$WRAPPER_SOURCE" ]]; then
        echo -e "${R}[ ❌ ] Wrapper template not found: $WRAPPER_SOURCE${X}"
        return 1
    fi

    cstk_install_file 0750 "$WRAPPER_SOURCE" "$WRAPPER_PATH" || return 1

    if [[ -f "$WRAPPER_PATH" ]]; then
        echo -e "${G}Wrapper script installed at ${C}/usr/local/bin/cstk_wrapper${X}"
        echo -e "${G}Why this wrapper exists:${X}"
        echo -e "${Y}1 - No need to modify ~/.bashrc or ~/.zshrc.${X}"
        echo -e "${Y}2 - Ensures only CSTK commands are executed when needed.${X}"
        echo -e "${Y}3 - Simplifies uninstallation because removing the wrapper removes the PATH changes.${X}"

    else

        echo -e "${R}[ ❌ ] Failed to create wrapper at $WRAPPER_PATH.${X}"
        echo -e "${R}Program will not function without it.${X}"
        echo -e "${Y}Run uninstall.sh to clean up.${X}"
        exit 9
    fi
}

breached_parser() {

    local TORRENT_FILE data space_available ans

    TORRENT_FILE="magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337"

    data="${home_dir}/data"

    if [[ ! -d "$data" ]]; then

        space_available="$(
            df --output=avail -BG "$home_dir" |
            tail -n 1 |
            grep -oE '[0-9]+'
        )"

        if [[ "$space_available" =~ ^[0-9]+$ ]] &&
           (( space_available < 42 )); then

            echo -e "${R}Insufficient space. Need at least 42 GB. Exiting.${X}"
            return
        fi

        echo -e "${C}Would you like to download a large list of compromised emails and their related passwords?${X}"
        echo -e "${C}The download consists of tens of millions of emails and is approximately 42 GB in size.${X}"
        echo -e "${C}Chances are that your email or someone you know may be in the list.${X}"
        echo -e "${C}Download (Y/n)${X}"

        read -r -n 1 ans
        echo

        [[ "$ans" =~ ^[Yy]$ ]] || return 0

        if ! command -v aria2c >/dev/null 2>&1; then

            echo -e "${C}Installing aria2...${X}"

            install_dependencies "aria2"

            if ! command -v aria2c >/dev/null 2>&1; then
                echo -e "${R}[ ❌ ] aria2c could not be installed.${X}"
                return 1
            fi
        fi

        echo -e "${C}[ 📌 ] Downloading BreachCompilation data...${X}"
        echo -e "${C}This may take one to two hours depending on your internet connection.${X}"
        echo -e "${C}You can continue doing other things while the download runs.${X}"

        read -r -p "Press Enter to continue..."

        aria2c \
            --dir="$home_dir" \
            --seed-time=0 \
            "$TORRENT_FILE"

        if [[ ! -d "${home_dir}/BreachCompilation" ]]; then
            echo -e "${R}[ ❌ ] Failed to download BreachCompilation data.${X}"
            echo -e "${R}Please check your internet connection and the torrent information.${X}"
            return 1
        fi

        if [[ -d "${home_dir}/BreachCompilation/data" ]]; then

            mv \
                "${home_dir}/BreachCompilation/data" \
                "${home_dir}/data"

            if [[ -d "${home_dir}/data" ]]; then
                rm -rf "${home_dir}/BreachCompilation"
            fi

        else

            echo -e "${R}[ ❌ ] The BreachCompilation download completed, but the expected data directory was not found.${X}"
            return 1
        fi
    fi
}

# Optional Docker tools: cache images at install time; launch only on demand.
install_container_tools() {
    local answer
    [[ -t 0 ]] || { echo 'Optional Docker tools: images will download on first launch.'; return 0; }
    read -r -p 'Prepare Docker / Web Check / Trivy now? [y/N]: ' answer
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || return 0
    if ! command -v docker >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            cstk_package_transaction apt-get apt-get install -y docker.io || return 1
        else
            echo 'Install Docker with your system package manager, then rerun the image prefetch.'
            return 1
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        command -v systemctl >/dev/null 2>&1 && systemctl start docker || return 1
    fi
    "${home_dir}/scripts/bin/cstk_containers" prefetch
}

set_hashes() {

    local SHA_PATH BIN_DIR LIB_DIR HASH_FILE TEMP_HASH_FILE
    local -a HASH_TARGETS

    SHA_PATH="${home_dir}/Other/SecurityChecks"
    BIN_DIR="${home_dir}/scripts/bin/"
    LIB_DIR="${home_dir}/scripts/lib/"
    HASH_FILE="${SHA_PATH}/sha256.checksum"

    mkdir -p "$SHA_PATH" || return 1

    HASH_TARGETS=(
        "${home_dir}/cstk.sh"
        "${home_dir}/uninstall.sh"
        "$LIB_DIR"
        "$BIN_DIR"
    )

    if [[ -f "/usr/local/bin/cstk_wrapper" ]]; then
        HASH_TARGETS+=("/usr/local/bin/cstk_wrapper")
    fi

    TEMP_HASH_FILE="$(mktemp "$SHA_PATH/.sha256.checksum.XXXXXX")" || {
        echo -e "${R}[ ❌ ] Failed to create the temporary checksum file.${X}"
        return 1
    }

    if ! (
        set -o pipefail
        find "${HASH_TARGETS[@]}" \
            -type f \
            -exec sha256sum {} \; |
            LC_ALL=C sort > "$TEMP_HASH_FILE"
    ); then
        rm -f -- "$TEMP_HASH_FILE"
        echo -e "${R}[ ❌ ] Failed to create the CSTK checksum manifest.${X}"
        return 1
    fi

    chmod 600 "$TEMP_HASH_FILE" || return 1
    mv -f -- "$TEMP_HASH_FILE" "$HASH_FILE"

}

password_protect() {

    local log config_file auth_choice

    log="${home_dir}/log"
    config_file="$log/.auth_config"

    mkdir -p "$log" || return 1

    [[ -f "$config_file" ]] || touch "$config_file" || return 1

    echo
    echo "[ 🔐 ] Do you want to enable username/password authentication?"
    echo "1) Yes (recommended)"
    echo "2) No (skip login at startup)"

    read -rp "Choose [1/2]: " auth_choice

    case "$auth_choice" in

        1)
            echo "on" > "$config_file" || return 1
            echo "[ ✅ ] Authentication enabled"
            ;;

        2)
            echo "off" > "$config_file" || return 1
            echo "[ ⚡ ] Authentication disabled"
            ;;

        *)
            echo "on" > "$config_file" || return 1
            echo "[ ⚠️ ] Invalid choice. Defaulting to ENABLED for security."
            ;;
    esac

    chmod 600 "$config_file"
}

finish_setup() {
    # DEFENSE scripts stay in the managed checkout; no extra system symlinks.
    [[ -f "$home_dir/scripts/bin/web_tls_security_assessment" ]] || return 1
    chmod 750 "$home_dir/scripts/bin/web_tls_security_assessment" || return 1
    if [[ -f "$home_dir/scripts/bin/linux_security_audit" ]]; then
        chmod 750 "$home_dir/scripts/bin/linux_security_audit" || return 1
    fi
    chmod 750 /usr/local/bin/cstk_wrapper || return 1

    find "$home_dir" \
        -type d \
        -exec chmod 750 {} + || return 1

    if [[ -z "$cstk_owner_uid" || -z "$cstk_owner_gid" ]]; then
        echo -e "${R}[ ERROR ] The original CSTK checkout ownership was not recorded.${X}"
        return 1
    fi

    chown -R -P -- "$cstk_owner_uid:$cstk_owner_gid" "$home_dir"
}

# ============================================================================
# Main installation process
# ============================================================================

# Make sure we are root.
need_root "$@"

# Check that Bash is at least version 4.0.
bash_version || exit 1

# Find and configure the CyberSecurityToolKit directory.
config_dirs || exit 1
resolve_cstk_account || exit 1
cstk_state_init || exit 1
trap 'rc=$?; if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true; fi; if (( rc )); then echo "Installation incomplete. State retained in /var/lib/cstk; rerun install.sh or uninstall.sh." >&2; fi' EXIT
# Isolate CSTK-managed Python and Go environments from root's personal tools.
make_dir || exit 1

# Bootstrap decryption prerequisites before provisioning on minimal VMs.
if ! command -v openssl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update || exit 1
        cstk_package_transaction apt-get apt-get install -y openssl || exit 1
    elif command -v dnf >/dev/null 2>&1; then
        cstk_package_transaction dnf dnf install -y openssl || exit 1
    elif command -v yum >/dev/null 2>&1; then
        cstk_package_transaction yum yum install -y openssl || exit 1
    else
        echo 'OpenSSL is required; no supported bootstrap package manager found.' >&2
        exit 1
    fi
fi

# Provision protected resources before installation checks and side effects.
install_lib_decryption_key || exit 1

# Install the man page.
install_man_page || exit 1

# Check the working directory and create required directories.
check_working_dir || exit 1
make_dir || exit 1

# Make sure the tracking files exist.
touch \
    "$python_install_file" \
    "$package_management_install_file" \
    "$github_install_file" || exit 1

# Install all required system dependencies.
install_dependencies || exit 1
install_mongosh || exit 1

# A failed optional image download must not prevent the core installation.
install_container_tools || echo 'Optional Docker preparation failed; retry scripts/bin/cstk_containers prefetch later.'

# Install Python tools through pipx.
pipx_run_install || exit 1

# Install additional GitHub-based tools.
install_shc || exit 1
install_nrich || exit 1
install_mimipenguin || exit 1

# Check the working directory again.
check_working_dir || exit 1

# Add CSTK tab completion.
install_tab_completion || exit 1

# Create the CSTK wrapper.
create_wrapper || exit 1

# Create the global link to cstk.sh.
link_main_script || exit 1

# Ask the user whether CSTK authentication should be enabled.
password_protect || exit 1

# Keep sudo credentials alive while the installer is running.
if [[ -n "$SUDO_USER" ]]; then
    keep_sudo_alive &
    SUDO_KEEPALIVE_PID=$!
fi

# Prepare and optionally download BreachCompilation data.
check_working_dir || exit 1
breached_parser || exit 1

# Create CSTK integrity hashes.
set_hashes || exit 1

# Finalize permissions and ownership.
finish_setup || exit 1

# A success banner requires a working installed command, not just completed writes.
verify_installed_launcher || exit 1

# Stop the sudo keep-alive process.
if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null
    wait "$SUDO_KEEPALIVE_PID" 2>/dev/null
fi

echo
echo -e "${G}Installation complete! You can now run CSTK using the command 'sudo cstk'.${X}"
echo -e "${Y}If you need help, run 'sudo cstk --help' for long options or 'sudo cstk -h' for shorter help output.${X}"
echo -e "${C}Thank you for using CyberSecurityToolKit!${X}"
echo -e "${C}For updates and support, visit: https://github.com/adamhamilton44/CyberSecurityToolKit${X}"

exit 0
