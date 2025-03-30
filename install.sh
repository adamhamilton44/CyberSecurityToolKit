#!/usr/bin/env bash

set -e  # Exit on any error
LOG_FILE="$PWD/log/install.log"
exec > >(tee -a "$LOG_FILE") 2>&1
# Function to keep sudo alive
keep_sudo_alive() {
    while true; do
        sudo -v
        sleep 300
    done
}

# Start the keep-alive function in the background
trap "kill -- -$$" EXIT
keep_sudo_alive &

link_main_script() {
    if ! [ -h /usr/local/bin/cstk ]; then
        chmod +x ./cstk.sh
        ln -sr ./cstk.sh /usr/local/bin/cstk
        echo "The main script cstk.sh is now accessible globally. You can  run it using 'cstk'."
        REAL_PATH="$(realpath /usr/local/bin/cstk)"
        declare -g home_dir
        home_dir="$(dirname "$REAL_PATH")"
    else
        REAL_PATH="$(realpath /usr/local/bin/cstk)"
        declare -g home_dir
        home_dir="$(dirname "$REAL_PATH")"
    fi
}


# Define variables
USER=$(echo $SUDO_USER)
HOME=$(eval echo ~$USER)
log="${home_dir}/log"
bin="${home_dir}/bin"
data="${home_dir}/data"
LOOT="${home_dir}/Bank/Loot"
MALWARE="${home_dir}/Bank/Malware"
KEYS="$home_dir}/etc/keys"
cstk_tab_complete="$bin/tab_complete.cstk"
cstk_install="$log/cstk_install.log"
TORRENT_FILE="magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337"


# Function to check if running as root
need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Enter Password"
        exec sudo bash "$0" "$@"
    fi
}

# Function to check Bash version
bash_version() {
    min_bash_version=4.0
    current_bash_version=$(bash --version | head -n 1 | awk '{print $4}' | awk -F '(' '{print $1}')
    if [[ "$(echo "$current_bash_version < $min_bash_version" | bc -l)" -eq 1 ]]; then
        echo "Error: This script requires Bash $min_bash_version or higher. You have $current_bash_version."
        exit 1
    fi
}

make_dir() {
    folders=( "$LOOT" "$MALWARE" "$KEYS" )

    for dir in "${folders[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
        fi
    done
}
# Function to install required commands in bulk
install_dependencies() {
    required_commands=( basez build-essential gcc libc6-dev golang metasploit-framework bc cargo rustup git npm coreutils python3 python3-pip openssl john curl jq grep fzf autoconf xxd tar rlwrap bzip2 netcat-openbsd unrar gzip unzip dpkg 7zip nmap whois sublist3r nmap sqlmap nikto whatweb gobuster wpscan )

    if command -v apt &> /dev/null; then
        apt update -qq && apt install -qq -y "${required_commands[@]}"
    elif command -v yum &> /dev/null; then
        yum install -y "${required_commands[@]}"
    elif command -v dnf &> /dev/null; then
        dnf install -y "${required_commands[@]}"
    elif command -v brew &> /dev/null; then
        brew install "${required_commands[@]}"
    else
        echo "Error: Unsupported package manager. Install dependencies manually."
        exit 1
    fi
}

# Function to install SHC
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

# Function to download BreachedParser database
breached_parser() {
    exec > >(tee -a /dev/null) 2>&1
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

    aria2c --dir="$home_dir" --seed-time=0 "$TORRENT_FILE"

    if [ -d "$home_dir/BreachCompilation" ] && [ -d "$home_dir/BreachCompilation/data" ]; then
        mv "$home_dir/BreachCompilation/data" "$home_dir"
        rm -rf "$home_dir/BreachCompilation" &> /dev/null
    fi

}

# Function to install Nmap Vulscan
install_vulscan() {
    if ! [ -d /usr/share/nmap/scripts/vulscan ]; then
        git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
        nmap --script-updatedb
    fi
}

# Function to install Obfuscator
install_obs() {
    if ! command -v bash-obfuscate &>/dev/null; then
        npm install -g bash-obfuscate
    fi
}

install_holehe() {
    holehe_path="$home_dir/Malware_Of_All_Types/OSINT_Email-Social"
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
    shell=$(basename -- "$SHELL")

    case "$shell" in
        zsh)  rc="/root/.zshrc" ;;
        bash) rc="/root/.bashrc" ;;
        fish) rc="/root/.config/fish/config.fish" ;;
        ksh)  rc="/root/.kshrc" ;;
        tcsh) rc="/root/.tcshrc" ;;
        *)
            echo "Unknown shell detected. Please manually add 'source $cstk_tab_complete' to your shell configuration file."
            read -r -n 1 -p "Press Enter to continue without tab completion support."
            return 0
            ;;
    esac

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

set_hashes() {
    K_ROOT_KITS="$home_dir/Malware_of_All_Types/RootKits/kernel"
    U_ROOT_KITS="$home_dir/Malware_of_All_Types/RootKits/userland"
    P_BOMBS="$home_dir/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
    Z_BOMBS="$home_dir/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
    SHA_PATH="$home_dir/Other/SecurityChecks"
    find "$home_dir/cstk.sh" "$home_dir/uninstall.sh" "$home_dir/lib" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper"  -type f -exec sha256sum {} \; | sort >> "$SHA_PATH/sha256.checksum2"
    cp "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"
}

# Function to create wrapper script
create_wrapper() {
    INSTALL_DIR="$home_dir"
    BIN_DIR="$INSTALL_DIR/bin"
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

# Main execution
need_root
bash_version
make_dir
link_main_script
install_dependencies
install_shc
install_vulscan
install_obs
install_holehe
install_tab_completion
breached_parser
set_hashes
create_wrapper

# Final cleanup
chmod 750 /usr/local/bin/cstk_wrapper
find "$home_dir" -type d -exec chmod 750 {} \;
rm -- "$0"

exit 0
