#!/bin/bash

# CyberSecurityToolKit Installation Script
# This script sets up the CyberSecurityToolKit environment, installs dependencies,
# creates necessary directories, and configures the system for optimal use.
R=$'\e[1;31m' # red
G=$'\e[1;32m' # green
Y=$'\e[1;33m' # yellow
C=$'\e[1;36m' # cyan
RE=$'\e[0m' # reset
home_dir="$PWD"
# Function to check if the script is run as root
# If not, it will prompt for the password and re-run the script with sudo.
# This is necessary for installing packages and creating directories in system locations.
need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Enter Password"
        sudo bash -c "${BASH_SOURCE[0]}"
    fi
}
# Function to check the current Bash version
# It ensures that the script is run with at least Bash version 4.0.
# If the current version is lower, it will exit with an error message.
bash_version() {
    min_bash_version=4.0
    current_bash_version=$(bash --version | head -n 1 | awk '{print $4}' | awk -F '(' '{print $1}')
    if [[ "$(echo "$current_bash_version < $min_bash_version" | bc -l)" -eq 1 ]]; then
        echo -e "${R}Error: This script requires Bash $min_bash_version or higher. You have $current_bash_version."
        exit 1
    fi
}
# Function to check the current working directory
# It verifies if the script is being run from the correct directory structure.
# If not, it attempts to find the CyberSecurityToolKit directory and change to it.
# If the directory structure is still incorrect, it will exit with an error message.
# It also sets the global variable home_dir to the current working directory.
# This is important for the script to function correctly, as it relies on this variable for paths
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
            echo -e "${R}There seem to be issues with the directory structure, Please remove this repo and download again.${RE}"
            exit 99
        fi
    fi
}

# Function to keep sudo alive
# This function runs in an infinite loop, refreshing the sudo timestamp every 5 minutes.
# This is useful for long-running scripts that require sudo privileges.
# It prevents the user from being prompted for a password during the script execution.
# The loop will run indefinitely until the script is terminated.
keep_sudo_alive() {
    while true; do
        sudo -v
        sleep 300
    done
    
}

# Function to create a symbolic link for the main script
# It checks if the symbolic link already exists in /usr/local/bin/cstk.
# If it does not exist, it creates a symbolic link to the main script cstk.sh
# in the /usr/local/bin directory, making it globally accessible.
# It also sets the execute permission for the script.
# After creating the link, it prompts the user to press Enter to continue.
# This allows the user to run the script using the command 'cstk' from anywhere in the system.
# The function does not return any value, but it provides feedback to the user about
# the successful creation of the link.
# It is important to ensure that the script has the correct permissions and is executable.
# This function is called at the end of the installation process to finalize the setup.
link_main_script() {
    if ! [ -h /usr/local/bin/cstk ]; then
        ln -s "${PWD}/cstk.sh" /usr/local/bin/cstk
        echo -e "${G}The main script cstk.sh is now accessible globally. You can  run it using 'cstk'.${RE}"
        read -r -p "Press Enter to continue..."
    fi
}

# Function to create necessary directories
# It checks if the required directories exist in the home directory.
# If they do not exist, it creates them.
# The directories created are:
# - Bank/Loot: For storing loot files
# - Bank/Malware: For storing malware files
# - etc/keys: For storing keys
# This function is called at the beginning of the installation process to ensure that
# the necessary directory structure is in place before proceeding with the installation.
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
# Function to install dependencies
# This function installs a list of required packages and tools for the CyberSecurityToolKit.
# It uses the system's package manager (apt, yum, dnf, or brew)
# to install the packages.
# It checks if each package is already installed, and if not, it installs it.
# A spinner is displayed during the installation process for aesthetics.
# The function accepts additional arguments to install extra packages if needed.
# It also handles errors during installation and provides feedback to the user.
# The list of required packages includes tools for penetration testing, network scanning,
# password cracking, and other security-related tasks.
# The function is called during the installation process to ensure that all necessary dependencies are installed.
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
        sqlmap nikto whatweb gobuster wpscan aria2 dirb nasm openssl apktool nrich
        exploitdb make openssh-client openssh-server wafw00f sublist3r
        
    )
    
    # Append extra args
    [[ $# -gt 0 ]] && required_commands+=("$@")
    
    
    
    echo -e "${Y}🔧 Installing dependencies...${RE}"
    
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
        echo -e "${R}❌ No supported package manager found!${RE}"
        exit 1
    fi
    
    for pkg in "${required_commands[@]}"; do
        if $check_cmd "$pkg" &>/dev/null; then
            echo -e "${G}[✔] $pkg already installed.${RE}"
        else
            echo -e "${C}[...] Installing $pkg${RE}"
            bash -c "$install_cmd $pkg" &>/dev/null &
            pid=$!
            spinner $pid
            wait $pid
            if [[ $? -eq 0 ]]; then
                echo -e "${G}[+] Installed: $pkg${RE}"
            else
                echo -e "${R}[!] Failed to install: $pkg${RE}"
            fi
        fi
    done
}

# Function to install shc (Shell Script Compiler)
# This function checks if shc is already installed.
# If it is not installed, it clones the shc repository from GitHub,
# compiles it, and installs it to /usr/local/bin.
# It also creates a directory /opt/cstk to store the shc source code.
# If shc is already installed, it simply informs the user.
# This function is called during the installation process to ensure that shc is available for use.
install_shc() {
    if ! command -v shc &>/dev/null; then
        echo -e "${G}Installing shc...${RE}"
        mkdir -p /opt/cstk && pushd /opt/cstk || return
        git clone https://github.com/neurobin/shc.git
        cd shc || return
        autoreconf -fiv  # Ensures correct configuration
        ./configure
        make && make install
        if [[ $? -eq 0 ]]; then
            echo -e "${G}[✔] shc installed successfully.${RE}"
        else
            echo -e "${R}[!] Failed to install shc. Please check the output for errors.${RE}"
            exit 1
        fi
        popd || return
    else
        echo -e "${G}[✔] shc is already installed.${RE}"
    fi
}

# Function to install vulscan for Nmap
# This function checks if the vulscan directory exists in the Nmap scripts directory.
# If it does not exist, it clones the vulscan repository from GitHub into the Nmap scripts directory.
# After cloning, it updates the Nmap script database to include the new vulscan scripts.
# This function is called during the installation process to ensure that Nmap has the vulscan scripts available for use.
# It is useful for vulnerability scanning and assessment.
install_vulscan() {
    if ! [ -d /usr/share/nmap/scripts/vulscan ]; then
        git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
        nmap --script-updatedb
    fi
}

# Function to install Holehe
# This function checks if pip is installed and then attempts to install Holehe using pip.
# If the installation fails, it clones the Holehe repository from GitHub into a specified directory
# and installs it from there.
# It also handles the case where the installation is done from a pre-compiled egg file.
# The function uses OpenSSL to decrypt the egg file if necessary.
# It is important to ensure that the required dependencies are installed before running this function.
# The function also sets up the necessary paths for Holehe to work correctly.
# It uses base64 and base32plain to decode the password and the egg file.
# This function is called during the installation process to ensure that Holehe is available for use.
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

# Function to install tab completion for CSTK
# This function checks if the tab completion script exists in the bin directory.
# If it does not exist, it prompts the user to enable tab completion.
# It provides options to add the source command to the user's .bashrc file,
# to manually add it later, or to skip tab completion.
# If the user chooses to add it now, it appends the source command to the .bashrc file.
# If the user chooses to add it manually, it provides instructions on how to do so.
# If the user chooses to skip tab completion, it informs them that they can add it later.
# The function uses colors for better user experience and feedback.
# It is called during the installation process to ensure that tab completion is available for CSTK commands.
# The tab completion script is located in the bin directory of the home directory.
install_tab_completion() {
    cstk_tab_complete="${home_dir}"/bin/tab_complete.cstk
    rc="/root/.bashrc"
    if ! grep -q 'tab_complete.cstk' "$rc"; then
        echo -e "{C}Tab completion is available! To enable it, add a 'source' command to $rc."
        echo -e "${G}1 - Add it now\n${Y}2 - I'll add it manually\n${R}3 - No tab completion${RE}"
        read -r -p "Enter 1, 2, or 3: " opt
        
        case "$opt" in
            1) echo "source $cstk_tab_complete" >> "$rc" && echo -e "${G}Added to $rc.${RE}" ;;
            2) echo -e "${Y}Manually add:${R} source $cstk_tab_complete ${RE}" ;;
            3) echo "${R}Tab completion skipped.${Y} Add 'source $cstk_tab_complete' later if needed.${RE}" ;;
            *) echo "${R}Invalid option. Manually add: source $cstk_tab_complete${RE}" ;;
        esac
    fi
}

# Function to create a wrapper script for CSTK
# This function creates a wrapper script at /usr/local/bin/cstk_wrapper.
# The wrapper script checks if the CSTK_MAIN_RUNNER environment variable is set.
# If it is not set, it informs the user that the option is not available and exits.
# If it is set, it sets the CSTK_WRAPPER_RUNNER environment variable to 1,
# adds the home directory's bin directory to the PATH, and executes the command with
# the provided arguments in a clean environment.
# The wrapper script is designed to prevent interactive execution and ensure that only CSTK commands are executed
# when needed.
# It also provides feedback to the user about the wrapper's purpose and installation.
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
            echo -e "${G}Wrapper script installed at${C} /usr/local/bin/cstk_wrapper.${RE}"
            echo -e "${G}Why this wrapper exists:"
            echo -e "${Y}1 - No need to modify ~/.bashrc or ~/.zshrc."
            echo "2 - Ensures only CSTK commands are executed when needed."
            echo "3 - Simplifies uninstallation, as removing the wrapper removes PATH changes.${RE}"
        else
            echo "${R}Failed to create wrapper at $WRAPPER_PATH.${RE}"
            echo "${R}Program will not function without it. Run${G} uninstall.sh to clean up.${RE}"
            exit 9
        fi
    fi
}

# Function to parse and download the BreachCompilation data
# This function checks if the BreachCompilation data directory exists.
# If it does not exist, it checks if there is sufficient disk space (at least 42GB).
# If there is sufficient space, it prompts the user to confirm downloading the BreachCompilation data.
# If the user confirms, it checks if aria2c is installed, and if not, it installs it.
# It then uses aria2c to download the BreachCompilation data using a specified torrent file.
# After downloading, it moves the downloaded data to the home directory
# and cleans up any unnecessary directories.
# The function uses colors for better user experience and feedback.
# It is called during the installation process to ensure that the BreachCompilation data is available for use.
# The BreachCompilation data contains compromised email/password lists and is approximately 42GB in size.
breached_parser() {
    data="${home_dir}/data"
    TORRENT_FILE="magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337"
    
    if ! [[ -d "$data" ]]; then
        local space_available=$(df --output=avail -BG . | tail -n 1 | grep -o '[0-9]\+')
        if (( space_available < 42 )); then
            echo -e "${R}Insufficient space. Need at least 42GB. Exiting.${RE}"
            return
        fi
        
        echo -e "${C}Do you want to Download 42GB BreachCompilation compromised email/password lists ? (Y/N) ${RE}"
        read -r -n 1 ans
        echo
        [[ "$ans" =~ [Nn] ]] && return
        
        if ! command -v aria2c &>/dev/null; then
            echo -e "${C}Installing aria2...${RE}"
            # Install aria2 if not already installed
            install_dependencies "aria2"
        fi
        echo -e "${C}Downloading BreachCompilation data...\nThis will take around two hours depending on internet connection\nPlease fill free to do other stuff as needed.${RE}"
        read -r -p "Press Enter to continue..."
        aria2c --dir="${home_dir/}" --seed-time=0 "$TORRENT_FILE"
        if [[ -d BreachCompilation ]] && [[ -d BreachCompilation/data ]]; then
           mv BreachCompilation/data .                     
           if [[ -d data ]]; then                 
               rm -rf BreachCompilation 
           fi                                                   
       fi 
        
    fi
}

# Function to set hashes for various files and directories
# This function calculates the SHA256 checksums for specific files and directories
# related to the CyberSecurityToolKit.
# It includes the main script, uninstall script, libraries, rootkits (both kernel and userland),
# DOS bombs (image and zip), and security checks.
# The checksums are stored in a file named sha256.checksum in the Other/SecurityChecks directory.
# It also creates a backup of the checksums in sha256.checksum2.
# This function is called at the end of the installation process to ensure that the checksums are
# up-to-date and can be used for integrity checks in the future.
set_hashes() {
    K_ROOT_KITS="${home_dir}/Malware_of_All_Types/RootKits/kernel"
    U_ROOT_KITS="${home_dir}/Malware_of_All_Types/RootKits/userland"
    P_BOMBS="${home_dir}/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
    Z_BOMBS="${home_dir}/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
    SHA_PATH="${home_dir}/Other/SecurityChecks"
    find "${home_dir}/cstk.sh" "${home_dir}/uninstall.sh" "${home_dir}/lib" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper"  -type f -exec sha256sum {} \; | sort >> "$SHA_PATH/sha256.checksum"
    cp "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"
}

# Function to set permissions for the wrapper script and directories
# This function sets the permissions for the wrapper script located at /usr/local/bin/cstk_wrapper
# It ensures that the script is executable by the owner and readable by the group and others.
# It also sets the permissions for all directories in the home directory to 750,
# allowing the owner to read, write, and execute, while the group can read and execute,
# and others have no permissions.
# This is important for security and to ensure that only authorized users can access the directories.
finish_setup() {
    chmod 750 /usr/local/bin/cstk_wrapper
    find "$home_dir" -type d -exec chmod 750 {} \;
}

# Main script execution starts here
# Check if the script is run as root
need_root
# Check the current Bash version
bash_version
# Check the current working directory and set home_dir
check_working_dir
# Create necessary directories
make_dir
# Install dependencies
install_dependencies
# Install shc (Shell Script Compiler)
install_shc
# Install vulscan for Nmap
install_vulscan
# Install Holehe
install_holehe
# Install tab completion for CSTK
install_tab_completion
# Create a wrapper script for CSTK
create_wrapper
# Create a symbolic link for the main script
link_main_script
# Keep sudo alive in the background
keep_sudo_alive &
# Set up the BreachCompilation data parser
check_working_dir
# Parse and download the BreachCompilation data
breached_parser
# Set hashes for various files and directories
set_hashes
# Set permissions for the wrapper script and directories
finish_setup
# Inform the user that the installation is complete
echo -e "${G}Installation complete! You can now run CSTK using the command 'cstk'.${RE}"
echo -e "${Y}For help, run 'cstk --help'.${RE}"
echo -e "${C}Thank you for using CyberSecurityToolKit!${RE}"
echo -e "${C}For updates and support, visit: https://github.com /adamhamilton44/CyberSecurityToolKit${RE}"
# Exit the script successfully
exit 0