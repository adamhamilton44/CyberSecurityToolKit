#!/bin/bash

# Date: 7/10/2026
# Creator: AdamHamilton44
# Reason: Used as a secondary script in the CyberSecurityToolKit
# URL: https://github.com/adamhamilton44/CyberSecurityToolKit
#
# shellcheck disable=SC1003,SC2016,SC1090

# Colors
R=$'\e[1;31m'   # Red
G=$'\e[1;32m'   # Green
Y=$'\e[1;33m'   # Yellow
C=$'\e[1;36m'   # Cyan
X=$'\e[0m'      # Reset

# Directory structure
home_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Package management, GitHub, and Python downloads are recorded in hidden files.
python_install_file="$home_dir/Other/SecurityChecks/.python_pipx_installed_tools"
package_management_install_file="$home_dir/Other/SecurityChecks/.package_management_installed_tools"
github_install_file="$home_dir/Other/SecurityChecks/.github_installed_tools"
lib_key_dir="/etc/cstk"
lib_decryption_key="$lib_key_dir/lib_decryption.key"

config_dirs() {
    local base_dir expected_dir zip_download
    base_dir="$(basename "$home_dir")"
    expected_dir="CyberSecurityToolKit"
    zip_download="CyberSecurityToolKit-main"

    if [[ "$base_dir" != "$expected_dir" ]]; then

        if [[ "$base_dir" == "$zip_download" ]]; then
            echo "It looks like you downloaded this repository as a ZIP file."
            echo "The directory needs to be renamed."
            echo "Changing CyberSecurityToolKit-main to CyberSecurityToolKit."

            cd .. || exit 1

            if [[ -e "$expected_dir" ]]; then
                echo -e "${R}[ ❌ ] $expected_dir already exists.${X}"
                echo "Please remove or rename the existing directory before continuing."
                exit 1
            fi

            mv "$zip_download" "$expected_dir" || {
                echo -e "${R}[ ❌ ] Failed to rename $zip_download to $expected_dir.${X}"
                exit 1
            }

            cd "$expected_dir" || exit 1
            home_dir="$PWD"

            echo -e "${G}[ ✅ ] Directory renamed successfully.${X}"
        else
            echo "I do not see the CyberSecurityToolKit repository where expected."
            echo "Searching the file system for a CyberSecurityToolKit directory..."

            declare -a my_repo
            mapfile -t my_repo < <(
                find / -type d -name CyberSecurityToolKit -print 2>/dev/null
            )

            if [[ "${#my_repo[@]}" -eq 0 ]]; then
                echo -e "${R}[ ❌ ] Could not find a CyberSecurityToolKit directory.${X}"
                echo "Please move the repository into a CyberSecurityToolKit directory."
                exit 6
            fi

            echo
            echo "The following CyberSecurityToolKit directories were found:"
            select repo in "${my_repo[@]}"; do
                if [[ -n "$repo" ]]; then
                    echo "Using repository: $repo"

                    if [[ "$(realpath "${BASH_SOURCE[0]}")" != "$repo/install.sh" ]]; then
                        cp "${BASH_SOURCE[0]}" "$repo/install.sh" || {
                            echo -e "${R}[ ❌ ] Failed to copy install.sh to $repo.${X}"
                            exit 1
                        }
                    fi

                    cd "$repo" || exit 1
                    home_dir="$PWD"
                    return
                fi

                echo "Invalid selection."
            done
        fi
    fi

    if ! [[ -h /usr/local/bin/cstk ]]; then
        home_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    else
        home_dir="$(dirname "$(realpath /usr/local/bin/cstk)")"
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
    local min_bash_version current_bash_version
    min_bash_version=4.0

    current_bash_version="$(
        bash --version |
        head -n 1 |
        awk '{print $4}' |
        awk -F '(' '{print $1}'
    )"

    if [[ "$(printf '%s\n' "$min_bash_version" "$current_bash_version" | sort -V | head -n 1)" != "$min_bash_version" ]]; then
        echo -e "${R}[ ❌ ] Error: This script requires Bash $min_bash_version or higher.${X}"
        echo -e "${R}You have Bash $current_bash_version.${X}"
        exit 1
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

link_main_script() {
    if [[ ! -h /usr/local/bin/cstk ]]; then
        ln -s "${home_dir}/cstk.sh" /usr/local/bin/cstk

        echo -e "${G}[ 📌 ] The main script cstk.sh is now accessible globally.${X}"
        echo -e "${G}You can run it using 'sudo cstk'.${X}"

        read -r -p "Press Enter to continue..."
    fi
}

make_dir() {
    local KEYS dir folders inv_user inv_group inv_home passwd_record
    local user_data_dir user_loot user_malware

    KEYS="${home_dir}/etc/keys"
    inv_user="${SUDO_USER:-${USER:-root}}"
    passwd_record="$(getent passwd "$inv_user")" || {
        echo -e "${R}[ ERROR ] Unable to find the invoking user account: $inv_user.${X}"
        exit 1
    }
    IFS=: read -r _ _ _ _ _ inv_home _ <<<"$passwd_record"
    inv_home="$(realpath -e "$inv_home")" || exit 1
    inv_group="$(id -gn "$inv_user")" || exit 1

    if [[ -z "$inv_home" || "$inv_home" != /* || ! -d "$inv_home" ]]; then
        echo -e "${R}[ ERROR ] The invoking user does not have a usable home directory.${X}"
        exit 1
    fi

    user_data_dir="$inv_home/.local/share/cstk"
    user_loot="$user_data_dir/Loot"
    user_malware="$user_data_dir/Malware"

    if [[ "$(realpath -m "$user_data_dir")" != "$user_data_dir" ]]; then
        echo -e "${R}[ ERROR ] The private CSTK data path must stay inside the user home directory.${X}"
        exit 1
    fi

    for dir in "$user_data_dir" "$user_loot" "$user_malware"; do
        if [[ -L "$dir" ]]; then
            echo -e "${R}[ ERROR ] Refusing symbolic-link private data path: $dir.${X}"
            exit 1
        fi
    done

    if [[ "$inv_user" == "root" ]]; then
        mkdir -p -- "$user_loot" "$user_malware"
    elif command -v runuser >/dev/null 2>&1; then
        runuser -u "$inv_user" -- mkdir -p -- "$user_loot" "$user_malware"
    else
        sudo -u "$inv_user" -- mkdir -p -- "$user_loot" "$user_malware"
    fi || {
        echo -e "${R}[ ERROR ] Unable to create private CSTK data folders.${X}"
        exit 1
    }

    if ! chown -R -P -- "$inv_user:$inv_group" "$user_data_dir" ||
       ! chmod -R go-rwx -- "$user_data_dir" ||
       ! chmod 700 -- "$user_data_dir" "$user_loot" "$user_malware"; then
        echo -e "${R}[ ERROR ] Unable to secure private CSTK data folders.${X}"
        exit 1
    fi

    folders=("$KEYS")
    for dir in "${folders[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir" || {
                echo -e "${R}[ ERROR ] Failed to create $dir.${X}"
                exit 1
            }
        fi
    done

    mkdir -p \
        "$home_dir/Other/SecurityChecks" \
        "$home_dir/Other/Downloads" \
        "$home_dir/log"
}

verify_lib_decryption_key() {
    local candidate_key encrypted_probe probe_output
    candidate_key="$1"
    encrypted_probe="$home_dir/scripts/lib/HCDOUNASIXNTM7Q3YR-X-encoded.enc"

    [[ -f "$candidate_key" && -r "$candidate_key" && -f "$encrypted_probe" ]] || return 1

    probe_output="$(mktemp /tmp/cstk-key-check.XXXXXX)" || return 1
    chmod 600 "$probe_output"
    if openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in "$encrypted_probe" \
        -out "$probe_output" \
        -pass file:"$candidate_key" 2>/dev/null && [[ -s "$probe_output" ]]; then
        rm -f -- "$probe_output"
        return 0
    fi

    rm -f -- "$probe_output"
    return 1
}

install_lib_decryption_key() {
    local first_key second_key source_key temp_key

    install -d -m 700 -o root -g root "$lib_key_dir" || {
        echo -e "${R}[ ❌ ] Failed to create $lib_key_dir.${X}"
        return 1
    }

    if [[ -L "$lib_decryption_key" ]]; then
        echo -e "${R}[ ❌ ] Refusing to use a symbolic link as the library key file.${X}"
        return 1
    fi

    if [[ -s "$lib_decryption_key" ]]; then
        chown root:root "$lib_decryption_key"
        chmod 600 "$lib_decryption_key"
        if ! verify_lib_decryption_key "$lib_decryption_key"; then
            echo -e "${R}[ ❌ ] The installed CSTK library key cannot decrypt the protected resources.${X}"
            return 1
        fi
        echo -e "${G}[ ✔  ] The root-only CSTK library key is already installed.${X}"
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
        echo -e "${G}[ ✅ ] Installed the CSTK library key from the protected source file.${X}"
        return 0
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

    chown root:root "$temp_key"
    chmod 600 "$temp_key"
    mv -f -- "$temp_key" "$lib_decryption_key"
    echo -e "${G}[ ✅ ] Installed the root-only CSTK library key.${X}"
}

pipx_install() {
    local package="$1"

    if ! command -v pipx >/dev/null 2>&1; then
        echo -e "${R}[ ❌ ] pipx is not installed.${X}"
        return 1
    fi

    if pipx list 2>/dev/null | grep -qE "^[[:space:]]*package ${package}[[:space:]]"; then
        echo -e "${G}[ ✔  ] ${package} is already installed.${X}"
    else
        echo -e "${C}[ 📌 ] Installing ${package}${X}"

        if pipx install "$package"; then
            echo "$package" >> "$python_install_file"
            echo -e "${G}[ ✅ ] ${package} installed successfully.${X}"
        else
            echo -e "${R}[ ❌ ] Failed to install ${package}.${X}"
            return 1
        fi
    fi
}

pipx_run_install() {
    pipx_install droopescan
    pipx_install naminster
    pipx_install holehe
    pipx_install bloodhound-python
}

install_man_page() {
    local src dest

    src="$home_dir/scripts/lib/cstk.1"
    dest="/usr/share/man/man1/cstk.1"

    if [[ -f "$src" ]]; then
        sudo cp "$src" "$dest" || {
            echo -e "${R}[ ❌ ] Failed to install the CSTK man page.${X}"
            return 1
        }

        sudo gzip -f "$dest" || {
            echo -e "${R}[ ❌ ] Failed to compress the CSTK man page.${X}"
            return 1
        }

        sudo mandb >/dev/null 2>&1

        echo -e "${G}[ ✅ ] Installed man page to ${dest}.gz${X}"
    else
        echo -e "${Y}[ ⚠️ ] Man page not found: $src${X}"
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
                    if sudo dpkg -i "$download_file"; then
                        :
                    else
                        echo -e "${Y}[ ⚠️ ] dpkg reported dependency issues. Attempting to fix them...${X}"
                        sudo apt-get install -f -y >/dev/null 2>&1
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
                    sudo dnf install -y "./$download_file"

            elif command -v yum >/dev/null 2>&1; then

                file="nrich_latest_x86-64.rpm"
                download_file="$newname.rpm"

                wget -q --show-progress -O "$download_file" "$url/$file" &&
                    sudo yum localinstall -y "./$download_file"

            elif command -v rpm >/dev/null 2>&1; then

                file="nrich_latest_x86-64.rpm"
                download_file="$newname.rpm"

                wget -q --show-progress -O "$download_file" "$url/$file" &&
                    sudo rpm -Uvh "$download_file"

            elif command -v brew >/dev/null 2>&1; then

                echo -e "${C}[ 📌 ] Installing nrich through Homebrew.${X}"

                if brew tap shodan-public/homebrew-shodan \
                    https://gitlab.com/shodan-public/homebrew-shodan &&
                    brew install nrich; then
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
                    sudo install -m 755 nrich /usr/local/bin/nrich
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
    local pkg pid er
    local -a candidates
    local log_dir="$home_dir/log/package_manager"

    mkdir -p "$log_dir"
    touch "$package_management_install_file"

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

                        apt-get install -y \
                            -o Dpkg::Options::="--force-confdef" \
                            -o Dpkg::Options::="--force-confold" \
                            "$pkg"
                    ) >"$logfile" 2>&1 &
                    ;;

                rpm)
                    (
                        "$PACKAGE_MANAGER" install -y "$pkg"
                    ) >"$logfile" 2>&1 &
                    ;;

                brew)
                    (
                        HOMEBREW_NO_AUTO_UPDATE=1 brew install "$pkg"
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
                echo "$pkg" >> "$package_management_install_file"
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
                dpkg -s -- "$candidate" &>/dev/null
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
        7zip amass apache-users apktool argon2 aria2 arjun arp-scan arsenal-ng assetfinder autoconf basez bc bloodhound braa build-essential bzip2 cargo cewl commix coreutils crackmapexec curl dirb dirsearch dmitry dnsrecon dpkg enum4linux exploitdb feroxbuster ffuf fierce fping fzf gcc git git-lfs sed gobuster golang golang-any gospider grep gzip hashcat hping3 httpx-toolkit hydra impacket-scripts john joomscan jq libc6-dev lynis make masscan medusa metasploit-framework mongodb-server-core mxcheck mysql-common nasm ncrack ncat nikto nmap npm nuclei onesixtyone openssh-client openssh-server openssl p7zip-full pyenv-runtime python3 python3-pip redis rlwrap seclists sherlock skipfish smbclient smtp-user-enum snmpcheck sqlmap sslscan subfinder subjack sublist3r tar testssl.sh theharvester unrar unzip wafw00f wapiti whatweb whiptail whois wpscan xxd ldap-utils postgresql-client default-mysql-client redis-tools mongosh
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
            dpkg --configure -a \
            >"$log_dir/dpkg_configure.log" 2>&1; then

            echo -e "${Y}[ ⚠️  ] dpkg reported an unfinished package installation.${X}"
        fi
        # Check whether dependencies are currently broken.
        if ! apt-get check >"$log_dir/apt_check.log" 2>&1; then
            echo -e "${Y}[ ⚠️  ] Broken package dependencies detected.${X}"
            echo -e "${C}[ 🔧 ] Attempting automatic repair...${X}"
            if ! DEBIAN_FRONTEND=noninteractive \
                apt-get --fix-broken install -y \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                >"$log_dir/apt_fix_broken.log" 2>&1; then

                echo -e "${R}[ ❌ ] APT could not repair the package database.${X}"
                echo -e "${Y}[ ℹ️  ] Log: $log_dir/apt_fix_broken.log${X}"
                return 1
            fi
            # Configure anything repaired/unpacked by apt.
            DEBIAN_FRONTEND=noninteractive \
                dpkg --configure -a \
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
            >"$log_dir/dnf_makecache.log" 2>&1
    # YUM
    elif command -v yum &>/dev/null; then

        PACKAGE_MANAGER="yum"
        PKG_TYPE="rpm"

        echo -e "${G}[ ✔  ] Package manager detected: yum${X}"

        yum makecache -y \
            >"$log_dir/yum_makecache.log" 2>&1
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

        try_install_pkg "$pkg" "${candidates[@]}"
    done
    # Final package database check
    if [[ "$PKG_TYPE" == "deb" ]]; then

        if ! apt-get check >"$log_dir/apt_final_check.log" 2>&1; then
            echo
            echo -e "${Y}[ ⚠️  ] APT reports unresolved dependencies after installation.${X}"
            echo -e "${Y}[ ℹ️  ] Log: $log_dir/apt_final_check.log${X}"
        fi

        if [[ -f /var/run/reboot-required ]]; then
            echo
            echo -e "${Y}[ ⚠️  ] A system reboot is recommended.${X}"
            echo -e "${Y}[ ℹ️  ] CSTK will not reboot the machine automatically.${X}"
        fi
    fi
}

install_mimipenguin() {
    if ! command -v mimipenguin >/dev/null 2>&1; then
        echo -e "${G}[ 📌 ] Installing mimipenguin...${X}"
        git clone \
            https://github.com/huntergregal/mimipenguin.git \
            "$home_dir/Other/Downloads/mimipenguin" &>/dev/null || {
            echo -e "${R}[ ❌ ] Failed to clone mimipenguin.${X}"
            return 1
            }

        cd "$home_dir/Other/Downloads/mimipenguin" || return 1
        make
        local er=$?
        if [[ "$er" -eq 0 ]]; then
            echo -e "${G}[ ✅ ] mimipenguin installed successfully.${X}"
            echo "mimipenguin" >> "$github_install_file"
            if [[ -f "$home_dir/Other/Downloads/mimipenguin/mimipenguin.sh" ]]; then
                cp "$home_dir/Other/Downloads/mimipenguin/mimipenguin.sh" /usr/local/bin/
                chmod 755 /usr/local/bin/mimipenguin.sh
            fi

            if [[ -f "$home_dir/Other/Downloads/mimipenguin/mimipenguin.py" ]]; then
                cp "$home_dir/Other/Downloads/mimipenguin/mimipenguin.py" /usr/local/bin/
                chmod 755 /usr/local/bin/mimipenguin.py
            fi
        else
            echo -e "${R}[ ❌ ] Failed to build mimipenguin.${X}"
            return 1
        fi
    else
        echo -e "${G}[ ✔  ] mimipenguin is already installed.${X}"
    fi
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

        make && make install
        local er=$?

        if [[ "$er" -eq 0 ]]; then
            echo -e "${G}[ ✅ ] shc installed successfully.${X}"
            echo "shc" >> "$github_install_file"
        else
            echo -e "${R}[ ❌ ] Failed to install shc.${X}"
            exit 1
        fi

        cd "${home_dir}" || return 1

    else
        echo -e "${G}[ ✔  ] shc is already installed.${X}"
    fi
}

install_vulscan() {

    if [[ ! -d /usr/share/nmap/scripts/vulscan ]]; then

        echo -e "${G}[ 📌 ] Installing Nmap vulscan...${X}"

        git clone \
            https://github.com/scipag/vulscan \
            /usr/share/nmap/scripts/vulscan || {
                echo -e "${R}[ ❌ ] Failed to clone Nmap vulscan.${X}"
                return 1
            }

        nmap --script-updatedb || {
            echo -e "${R}[ ❌ ] Failed to update the Nmap script database.${X}"
            return 1
        }

        echo -e "${G}[ ✅ ] Nmap vulscan.nse installed successfully.${X}"
        echo "vulscan" >> "$github_install_file"

    else
        echo -e "${G}[ ✔  ] Nmap vulscan.nse is already installed.${X}"
    fi
}

install_katana() {
    local katana_dir co
    katana_dir="/root/go/bin/katana"

    if [[ -x "$katana_dir" ]]; then
        echo -e "${G}[ ✔  ] katana is already present.${X}"
        return 0
    fi

    echo -e "${C}[ 📌 ] Installing katana...${X}"

    CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
    co=$?

    if [[ "$co" -eq 0 && -x "$katana_dir" ]]; then
        echo -e "${G}[ ✅ ] Installed: katana.${X}"
        echo "katana" >> "$github_install_file"
    else
        echo -e "${R}[ ❌ ] Failed to install katana.${X}"
        return 1
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

    inv_user="${SUDO_USER:-${USER:-root}}"
    passwd_record="$(getent passwd "$inv_user")" || {
        echo -e "${R}[ ERROR ] Unable to find account: $inv_user.${X}"
        return 1
    }
    IFS=: read -r _ _ _ _ _ inv_home inv_shell <<<"$passwd_record"
    s="${inv_shell##*/}"

    add_to_rc() {

        target_file="$1"

        [[ -f "$target_file" ]] || touch "$target_file"

        if grep -qF "$f" "$target_file" 2>/dev/null; then
            echo -e "${C}[ ℹ️ ] Already present in $target_file — skipping.${X}"
            return 0
        fi

        echo "source \"$f\"" >> "$target_file"

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
                    add_to_rc "$user_rc"
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
            local root_rc="/root/.${s}rc"
            add_to_rc "$root_rc"
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

    install -m 0750 "$WRAPPER_SOURCE" "$WRAPPER_PATH" || return 1

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

        [[ "$ans" =~ [Nn] ]] && return

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

set_hashes() {

    local SHA_PATH BIN_DIR LIB_DIR CHECK_SCRIPT HASH_FILE TEMP_HASH_FILE
    local -a HASH_TARGETS

    SHA_PATH="${home_dir}/Other/SecurityChecks"
    BIN_DIR="${home_dir}/scripts/bin/"
    LIB_DIR="${home_dir}/scripts/lib/"
    CHECK_SCRIPT="${SHA_PATH}/check_hashes.sh"
    HASH_FILE="${SHA_PATH}/sha256.checksum"

    mkdir -p "$SHA_PATH"

    HASH_TARGETS=(
        "${home_dir}/cstk.sh"
        "${home_dir}/uninstall.sh"
        "$LIB_DIR"
        "$BIN_DIR"
        "$CHECK_SCRIPT"
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

    chmod 600 "$TEMP_HASH_FILE"
    mv -f -- "$TEMP_HASH_FILE" "$HASH_FILE"

}

password_protect() {

    local log config_file auth_choice

    log="${home_dir}/log"
    config_file="$log/.auth_config"

    mkdir -p "$log"

    [[ -f "$config_file" ]] || touch "$config_file"

    echo
    echo "[ 🔐 ] Do you want to enable username/password authentication?"
    echo "1) Yes (recommended)"
    echo "2) No (skip login at startup)"

    read -rp "Choose [1/2]: " auth_choice

    case "$auth_choice" in

        1)
            echo "on" > "$config_file"
            echo "[ ✅ ] Authentication enabled"
            ;;

        2)
            echo "off" > "$config_file"
            echo "[ ⚡ ] Authentication disabled"
            ;;

        *)
            echo "on" > "$config_file"
            echo "[ ⚠️ ] Invalid choice. Defaulting to ENABLED for security."
            ;;
    esac

    chmod 600 "$config_file"
}

finish_setup() {

    local cstk_user

    cstk_user="$(echo ${SUDO_USER:-$(whoami)})"

    chmod 750 /usr/local/bin/cstk_wrapper

    find "$home_dir" \
        -type d \
        -exec chmod 750 {} \;

    chown -R "$cstk_user:$cstk_user" "$home_dir"
}

# ============================================================================
# Main installation process
# ============================================================================

# Make sure we are root.
need_root "$@"

# Check that Bash is at least version 4.0.
bash_version

# Find and configure the CyberSecurityToolKit directory.
config_dirs

# Install the man page.
install_man_page

# Check the working directory and create required directories.
check_working_dir
make_dir
install_lib_decryption_key || exit 1

# Make sure the tracking files exist.
touch \
    "$python_install_file" \
    "$package_management_install_file" \
    "$github_install_file"

# Install all required system dependencies.
install_dependencies

# Install Python tools through pipx.
pipx_run_install

# Install additional GitHub-based tools.
install_shc
install_vulscan
install_katana
install_nrich
install_mimipenguin

# Check the working directory again.
check_working_dir

# Add CSTK tab completion.
install_tab_completion

# Create the CSTK wrapper.
create_wrapper

# Create the global link to cstk.sh.
link_main_script

# Ask the user whether CSTK authentication should be enabled.
password_protect

# Keep sudo credentials alive while the installer is running.
if [[ -n "$SUDO_USER" ]]; then
    keep_sudo_alive &
    SUDO_KEEPALIVE_PID=$!
fi

# Prepare and optionally download BreachCompilation data.
check_working_dir
breached_parser

# Create CSTK integrity hashes.
set_hashes || exit 1

# Finalize permissions and ownership.
finish_setup

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
