#!/bin/bash

home_dir="$PWD"

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Enter Password"
        sudo bash -c "${BASH_SOURCE[0]}" 
    fi
}

bash_version() {
    min_bash_version=4.0
    current_bash_version=$(bash --version | head -n 1 | awk '{print $4}' | awk -F '(' '{print $1}')
    if [[ "$(echo "$current_bash_version < $min_bash_version" | bc -l)" -eq 1 ]]; then
        echo "Error: This script requires Bash $min_bash_version or higher. You have $current_bash_version."
        exit 1
    fi
}

check_working_dir() {
    move_me=$(find / -type d -name CyberSecurityToolKit 2>/dev/null)
    if [[ -d ./Bank ]] && [[ -d ../CyberSecurityToolKit ]]; then
        echo ""
    else
        cd "$move_me"
        if [[ -d ./Bank ]] && [[ -d ../CyberSecurityToolKit ]]; then
            declare -g home_dir
            home_dir="$PWD"
        else
            echo "There seem to be issues with the directory structure, Please remove this repo and download again."
            exit 99
        fi
    fi
}


keep_sudo_alive() {
    while true; do
        sudo -v
        sleep 300
    done

}


link_main_script() {
    if ! [ -h /usr/local/bin/cstk ]; then
        chmod +x "${home_dir}"/cstk.sh
        ln -sr "${home_dir}"/cstk.sh /usr/local/bin/cstk
        echo "The main script cstk.sh is now accessible globally. You can  run it using 'cstk'."
    fi
}


make_dir() {
    LOOT="${home_dir}/Bank/Loot"
    MALWARE="${home_dir}/Bank/Malware"
    KEYS="{$home_dir}/etc/keys"
    folders=( "$LOOT" "$MALWARE" "$KEYS" )

    for dir in "${folders[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
        fi
    done
}

install_dependencies() {
    # Spinner for aesthetics
    spinner() {
        local pid=$1
        local delay=0.1
        local spinstr='|/-\'
        while kill -0 "$pid" 2>/dev/null; do
            local temp=${spinstr#?}
            printf " [%c]  " "$spinstr"
            spinstr=$temp${spinstr%"$temp"}
            sleep $delay
            printf "\b\b\b\b\b\b"
        done
    }

    local required_commands=(
        whiptail seclists hydra medusa ncrack john hashcat crackmapexec cewl basez
        build-essential gcc libc6-dev golang metasploit-framework bc cargo git npm
        coreutils python3 python3-pip openssl curl jq grep fzf autoconf xxd tar
        rlwrap bzip2 netcat-openbsd unrar gzip unzip dpkg 7zip nmap whois sublist3r
        sqlmap nikto whatweb gobuster wpscan
    )

    # Append extra args
    [[ $# -gt 0 ]] && required_commands+=("$@")

    # Setup colors
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[1;36m'
    RESET='\033[0m'

    echo -e "${YELLOW}🔧 Installing dependencies...${RESET}"

    # Detect OS package manager
    if command -v apt &>/dev/null; then
        manager="apt"
        install_cmd="apt install -y -qq"
        check_cmd="dpkg -s"
    elif command -v yum &>/dev/null; then
        manager="yum"
        install_cmd="yum install -y"
        check_cmd="rpm -q"
    elif command -v dnf &>/dev/null; then
        manager="dnf"
        install_cmd="dnf install -y"
        check_cmd="rpm -q"
    elif command -v brew &>/dev/null; then
        manager="brew"
        install_cmd="brew install"
        check_cmd="brew list"
    else
        echo -e "${RED}❌ No supported package manager found!${RESET}"
        exit 1
    fi

    for pkg in "${required_commands[@]}"; do
        if $check_cmd "$pkg" &>/dev/null; then
            echo -e "${GREEN}[✔] $pkg already installed.${RESET}"
        else
            echo -e "${CYAN}[...] Installing $pkg${RESET}"
            bash -c "$install_cmd $pkg" &>/dev/null &
            pid=$!
            spinner $pid
            wait $pid
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}[+] Installed: $pkg${RESET}"
            else
                echo -e "${RED}[!] Failed to install: $pkg${RESET}"
            fi
        fi
    done
}


install_shc() {
    if ! command -v shc &>/dev/null; then
        echo "Installing shc..."
        mkdir -p /opt/cstk && pushd /opt/cstk || return
        git clone https://github.com/neurobin/shc.git
        cd shc || return
        autoreconf -fiv  # Ensures correct configuration
        ./configure
        make && make install
        popd || return
    else
        echo "shc is already installed."
    fi
}


install_vulscan() {
    if ! [ -d /usr/share/nmap/scripts/vulscan ]; then
        git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
        nmap --script-updatedb
    fi
}


install_holehe() {
    holehe_path="$home_dir/Malware_of_All_Types/OSINT_Email-Social"
    pw="$(echo 'RlBjWnV6SnVQNW00SWdIRmZobTNUR3dWWDdtQW1peVNjMmlUbVhLeAo=' | base64 -d)"
    pw2="$(echo 'IFCECTKBIRAU2QKEJVAU2RCBJVCECRCNIFGUITKBIRGUCTKEJVCE2QKEJVAU2RCLIFCEWQKOJNAU4QKLIRHECS2EJZFUCTSBIRAUSRCBJFHUISCJIRHUQQKPJFEEISKPJBAU6SKBJBCE6SKIIREU6QJTGMZAU===' | base32plain -d)"
    if command -v pip &> /dev/null; then
        pip install holehe &> /dev/null
        status=$?
        if [[ "$status" != 0 ]]; then
            mkdir -P "$holehe_path" &>/dev/null
            pushd "$holehe_path" || return &> /dev/null
            git clone https://github.com/megadose/holehe.git &> /dev/null
            cd holehe &> /dev/null || return
            status=$?
            popd || return &>/dev/null
            if [[ "$status" != 0 ]]; then
                openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "${holehe_path}/holehe.enc" -out "${holehe_path}/holehe-1.61-py3.12.egg.zip" -pass pass:"$pw2"
                unzip -P "$pw" "${holehe_path}/holehe-1.61-py3.12.egg.zip"
                if [ -d /usr/local/lib/python3.12/dist-packages/ ]; then
                    mv "${holehe_path:?}/holehe-1.61-py3.12.egg" /usr/local/lib/python3.12/dist-packages
                    mv "${holehe_path:?}/usr/local/bin/holehe" /usr/local/bin/holehe
                    rm -rf "${holehe_path:?}/usr" "${holehe_path}/holehe-1.61-py3.12.egg.zip"
                else
                    python_version="$(find /usr/local/lib/ -type d -iname 'python3.*')"
                    mv "${holehe_path}/holehe-1.61-py3.12.egg" "$python_version/dist-packages"
                    mv "${holehe_path}/usr/local/bin/holehe" /usr/local/bin/holehe
                    rm -rf "${holehe_path:?}/usr" "${holehe_path}/holehe-1.61-py3.12.egg.zip"
                fi
            else
                python3 setup.py install &> /dev/null
                cd ../ &> /dev/null || return
                rm -rf holehe &> /dev/null
            fi
        fi
    fi
}


install_tab_completion() {
    cstk_tab_complete="${home_dir}"/bin/tab_complete.cstk
    rc="/root/.bashrc" ;;
    if ! grep -q 'tab_complete.cstk' "$rc"; then
        echo -e "Tab completion is available! To enable it, add a 'source' command to $rc."
        echo -e "1 - Add it now\n2 - I'll add it manually\n3 - No tab completion"
        read -r -p "Enter 1, 2, or 3: " opt

        case "$opt" in
            1) echo "source $cstk_tab_complete" >> "$rc" && echo "Added to $rc." ;;
            2) echo "Manually add: source $cstk_tab_complete" ;;
            3) echo "Tab completion skipped. Add 'source $cstk_tab_complete' later if needed." ;;
            *) echo "Invalid option. Manually add: source $cstk_tab_complete" ;;
        esac
    fi
}


create_wrapper() {
    BIN_DIR="${home_dir}/bin"
    WRAPPER_PATH="/usr/local/bin/cstk_wrapper"

    if [[ ! -f "$WRAPPER_PATH" ]]; then
        {
            echo '#!/bin/bash'
            echo '[[ $- == *i* ]] && { echo "This script cannot be run interactively"; exit 1; }'
            echo 'if [[ -z "$CSTK_MAIN_RUNNER" ]]; then'
            echo '    echo "This option is not available."'
            echo '    exit 1'
            echo 'else'
            echo '    CSTK_WRAPPER_RUNNER=1'
            echo '    export PATH="'"$BIN_DIR"':$PATH"'
            echo '    exec env -i PATH="$PATH" "$@"'
            echo 'fi'
        } > "$WRAPPER_PATH"

        # Verify wrapper creation
        if [[ -f "$WRAPPER_PATH" ]]; then
            chmod 500 "$WRAPPER_PATH"
            echo "Wrapper script installed at /usr/local/bin/cstk_wrapper."
            echo "Why this wrapper exists:"
            echo "1 - No need to modify ~/.bashrc or ~/.zshrc."
            echo "2 - Ensures only CSTK commands are executed when needed."
            echo "3 - Simplifies uninstallation, as removing the wrapper removes PATH changes."
        else
            echo "Failed to create wrapper at $WRAPPER_PATH."
            echo "Program will not function without it. Run uninstall.sh to clean up."
            exit 9
        fi
    fi
}


breached_parser() {
    data="${home_dir}/data"
    TORRENT_FILE="magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337"

    if ! [[ -d "$data" ]]; then
        local space_available=$(df --output=avail -BG . | tail -n 1 | grep -o '[0-9]\+')
        if (( space_available < 42 )); then
            echo "Insufficient space. Need at least 42GB. Exiting."
            return
        fi

        echo "Download 42GB BreachCompilation? (Y/N)"
        read -r -n 1 ans
        echo
        [[ "$ans" =~ [Nn] ]] && return

        if ! command -v aria2c &>/dev/null; then
                install_dependencies "aria2"
        fi

        aria2c --dir="${home_dir/}" --seed-time=0 "$TORRENT_FILE"

        if [ -d "${home_dir}/BreachCompilation" ] && [ -d "{$home_dir}/BreachCompilation/data" ]; then
                mv "${home_dir}/BreachCompilation/data" "${home_dir}"
                rm -rf "${home_dir}/BreachCompilation" &> /dev/null
        fi
    fi
}


set_hashes() {
    K_ROOT_KITS="${home_dir}/Malware_of_All_Types/RootKits/kernel"
    U_ROOT_KITS="${home_dir}/Malware_of_All_Types/RootKits/userland"
    P_BOMBS="${home_dir}/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
    Z_BOMBS="${home_dir}/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
    SHA_PATH="${home_dir}/Other/SecurityChecks"
    find "${home_dir}/cstk.sh" "${home_dir}/uninstall.sh" "${home_dir}/lib" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper"  -type f -exec sha256sum {} \; | sort >> "$SHA_PATH/sha256.checksum"
    cp "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"
}


finish_setup() {
        chmod 750 /usr/local/bin/cstk_wrapper
        find "$home_dir" -type d -exec chmod 750 {} \;
}


need_root
bash_version
check_working_dir
make_dir
install_dependencies
install_shc
install_vulscan
install_holehe
install_tab_completion
create_wrapper
link_main_script
keep_sudo_alive &
check_working_dir
breached_parser
set_hashes
finish_setup
exit 0