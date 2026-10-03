#!/bin/bash

# Date: 7/10/2026
# Creater: AdamHamilton44
# Reason: Used as a secondary script in the CyberSecurityToolKit
# URL: https://github.com/adamhamilton44/CyberSecurityToolKit
#

# color variables
R=$'\e[1;31m' G=$'\e[1;32m' Y=$'\e[1;33m' C=$'\e[1;36m' X=$'\e[0m'
# find home
if [[ -f /usr/local/bin/cstk ]]; then
    home_dir="$(dirname "$(realpath /usr/local/bin/cstk)")"
else
    home_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
# If we call uninstall.sh from within the cstk.sh because of a checksum issue
# Then use a arguement ( all ) to go into auto delete without asking questions
answer="$1"
# used for pulling packages in /opt/cstk directory from file .installed_with_cstk
we_installed="$(grep --basic-regexp $1 $home_dir/Other/SecurityChecks/$2  &>/dev/null)"

python_install_file="$home_dir/Other/SecurityChecks/.python_pipx_installed_tools"
package_management_install_file="$home_dir/Other/SecurityChecks/.package_management_installed_tools"
github_install_file="$home_dir/Other/SecurityChecks/.github_installed_tools"
# package_management = 7zip amass apache-users apktool argon2 aria2 arjun arp-scan assetfinder autoconf basez bc bloodhound braa build-essential bzip2 cargo cewl commix coreutils crackmapexec curl dirb dirsearch dmitry dnsrecon dpkg enum4linux exploitdb feroxbuster ffuf fierce fping fzf gcc git git-lfs sed gobuster golang golang-any gospider grep gzip hashcat hping3 httpx-toolkit hydra impacket-scripts john joomscan jq libc6-dev make masscan medusa metasploit-framework mongodb-server-core mxcheck mysql-common nasm ncrack ncat nikto nmap npm nuclei onesixtyone openssh-client openssh-server openssl p7zip-full pyenv-runtime python3 python3-pip redis rlwrap seclists sherlock skipfish smbclient smtp-user-enum snmpcheck sqlmap sslscan subfinder subjack sublist3r tar testssl.sh theharvester unrar unzip wafw00f wapiti whatweb whiptail whois wpscan xxd
# github_downloads = mimipenguin,shc,vulscan,katana,nrich,mongosh-archive,msfpc,lynis,mig-logcleaner-resurrected,apktool,socat
# pipx_installs = droopescan,holehe,naminter,bloodhound-ce,updog

# make sure user is root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "${R}This script must be run as root.${X}"
        exit 1
    fi
}

# remove our man page
remove_man_pages() {
    local dest
    dest="/usr/share/man/man1/cstk.1"
    if [[ -f "$dest" ]]; then
        rm -rf "$dest"
        rm -rf "$dest.gz"
        mandb >/dev/null 2>&1
        echo -e "${G}✅ Removed manpage to $dest.gz ${RE}"
    fi
}

# shc
remove_shc() {
    "$we_installed" "shc" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]] && [[ -d /opt/cstk/shc ]]; then
        rm -rf /opt/cstk/shc
        echo -e "${Y}[✓] Removed shc directory.${X}"
        rm -f /usr/local/bin/shc
    fi
}

pipx_uninstall() {
    local package="$1"
    if pipx list 2>/dev/null | grep -qE "^[[:space:]]*package ${package}[[:space:]]"; then
        pipx uninstall "${package}" &>/dev/null
    fi
}

# Uninstall all pipx packages recorded during install.
remove_pipx_installed_tools() {
    local pkg

    if [[ -f "$python_install_file" ]]; then
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            if pipx list 2>/dev/null | grep -qE "^[[:space:]]*package ${pkg}[[:space:]]"; then
                pipx uninstall "$pkg" &>/dev/null &&
                    echo -e "${Y}[✓] Removed ${pkg}. ${X}"
            fi
        done < "$python_install_file"
    fi
}

# holehe
remove_holehe() {
    "$we_installed" "holehe" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]]; then
        if pipx list | grep -q "^holehe\b"; then
            pipx uninstall holehe &>/dev/null
            echo -e "${Y}[✓] Removed holehe. ${X}"
	    fi
	fi
}

# katana
remove_katana() {
    "$we_installed" "katana" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]] && [[ -d /root/go/bin/katana ]]; then
            rm -rf /root/go/bin/katana
            echo -e "${Y}[✓] Removed katana directory.${X}"
    fi
}

# nosqlmap
remove_nosqlmap() {
    "$we_installed_opt" "nosqlmap" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]] && [[ -d /opt/cstk/NoSQLMap ]]; then
            rm -rf /opt/cstk/NoSQLMap
            find / -type f -name nosqlmap -exec rm -rf {} \;
            echo -e "${Y}[✓] Removed nosqlmap directory and files.${X}"
    fi
}

# vulscan
remove_vulscan() {
    "$we_installed" "vulscan" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]] && [[ -d /usr/share/nmap/scripts/vulscan ]]; then
        rm -rf /usr/share/nmap/scripts/vulscan &>/dev/null
        nmap --script-updatedb
        echo -e "${G}✅ nmap vulscan.nse uninstalled successfully ${X}"
    else
        echo -e "${G}✔  nmap vulscan.nse already installed not removing. ${X}"
    fi
}

# droopescan and Naminter
remove_droop_naminter() {
    pipx_uninstall droopescan
    pipx_uninstall naminter
}
# tab completion removal
remove_tab_completion() {
    local inv_user inv_home a2 f
    f="$home_dir/scripts/lib/tab_complete.cstk"
    if [[ -n "$SUDO_USER" ]]; then
        inv_user="$SUDO_USER"
        inv_home="$(eval echo "~$SUDO_USER")"
    else
        inv_user="$USER"
        inv_home="$HOME"
    fi
    local s="${SHELL##*/}"
    clean_rc() {
        local rc="$1"
        if [[ ! -f "$rc" ]]; then
            echo "⚠️ RC file not found: $rc"
            return
        fi
        if grep -q "$target" "$rc"; then
           sed -i "/$target/d" "$rc"
           echo -e "${Y}✓ Removed tab completion entry from $rc ${X}"
        else
            echo -e "${R}ℹ️ No tab completion entry found in  $rc ${X}"
        fi
    }
    echo -e "${B}===${Y} CSTK Tab Completion Uninstaller${B} ===${X}"
    case "$s" in
        bash|zsh|ksh)
            local user_rc="$inv_home/.${s}rc"
            echo -e "${G} Removing tab completion from NORMAL USER ($inv_user)? ${X}"
            clean_rc "$user_rc" &>/dev/null
            ;;
        *)
            echo -e "${R}⚠️ $s shell unsupported for user uninstall. ${X}"
            ;;
    esac
    echo -e "${G}Removing tab completion from root and $user ${X}"
    local root_rc="/root/.${s}rc"
    local user_rc="/$user/.${s}rc"
    clean_rc "$root_rc" &>/dev/null
    clean_rc "$user_rc" &>/dev/null
}

# nrich
remove_nrich() {
    "$we_installed" "nrich" "$github_install_file"
    installed="$?"
    if [[ "$installed" = 0 ]] && [[ -f /usr/bin/nrich ]]; then
        rm /usr/bin/nrich &>/dev/null
        echo -e "${Y}[!] Removing nrich... ${X}"
    fi
}

remove_mongosh_archive() {
    if [[ -f "$github_install_file" ]] &&
       grep -Fxq mongosh-archive "$github_install_file"; then
        rm -f /usr/local/bin/mongosh /usr/local/bin/mongosh_crypt_v1.so
        echo -e "${Y}[✓] Removed the CSTK-installed mongosh archive.${X}"
    fi
}

# everyone else
remove_all() {
    rm -f /usr/local/bin/cstk_wrapper
    rm -f /usr/local/bin/cstk
    rm -rf -- /etc/cstk
    echo -e "${Y}[✓] Removed CSTK binaries from /usr/local/bin.${X}"

    if [[ -d "$home_dir" ]]; then
        echo -e "${Y}[!] Removing CSTK folder at: $home_dir${X}"
        rm -rf "$home_dir"
    fi
}

# downloads from users package management tool
remove_package_management_tools() {
    spinner() {
        local pid delay spinstr temp
        pid=$1
        delay=0.1
        spinstr='|/-\'
        while kill -0 "$pid" 2>/dev/null; do
            temp=${spinstr#?}
            printf " [%c]  " "$spinstr"
            spinstr=$temp${spinstr%"$temp"}
            sleep "$delay"
            printf "\b\b\b\b\b\b"
        done
    }
    [[ -f "$package_management_install_file" ]] || {
        echo -e "${R}❌ Package list not found.${RE}"
        return 1
    }
    check_cmd="$(grep -v '/' "$package_management_install_file")"
    echo -e "${Y}🔧 Removing dependencies...${RE}"
    if command -v apt >/dev/null 2>&1; then
        remove_cmd="apt remove -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        remove_cmd="yum remove -y"
    elif command -v dnf >/dev/null 2>&1; then
        remove_cmd="dnf remove -y"
    elif command -v brew >/dev/null 2>&1; then
        remove_cmd="brew remove"
    else
        echo -e "${R}❌ No supported package manager found!${RE}"
        return 1
    fi
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        echo -e "${C}[...] Removing $line${RE}"
        bash -c "$remove_cmd \"$line\"" >/dev/null 2>&1 &
        pid=$!
        spinner "$pid"
        wait "$pid"
        er=$?
        if [[ $er -eq 0 ]]; then
            echo -e "${G}✅ Removed: $line${RE}"
        else
            echo -e "${R}❌ Failed to remove: $line${RE}"
        fi
    done <<< "$check_cmd"
}

# confirmation & main removal method
# skip confirmation if arguement 'all' is called by cstk.sh file
# because of a sha256 check sum failure
confirm_uninstall() {
    if [[ "$answer" = 'all' ]]; then
        remove_package_management_tools
        remove_shc
        remove_pipx_installed_tools
        remove_nrich
        remove_mongosh_archive
        remove_katana
        remove_nosqlmap
        remove_vulscan
        remove_man_pages
        remove_tab_completion
        remove_all
    else
        echo -e "${R}Are you sure you want to uninstall CyberSecurityToolKit? (y/N)${X}"
        read -r -p "==> " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "${C}Uninstalling...${X}"
            sleep 1
            remove_package_management_tools
            remove_shc
            remove_pipx_installed_tools
            remove_nrich
            remove_mongosh_archive
            remove_katana
            remove_nosqlmap
            remove_vulscan
            remove_man_pages
            remove_tab_completion
            remove_all
            echo -e "\n${G}CyberSecurityToolKit has been uninstalled successfully.${X}"
        else
            echo -e "${G}Uninstall cancelled.${X}"
            exit 0
        fi
    fi
}

# root check then confirm uninstall
check_root
confirm_uninstall
