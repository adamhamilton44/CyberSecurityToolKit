#!/bin/bash

# Function to keep sudo alive
keep_sudo_alive() {
    while true; do
        sudo -v
        sleep 300
    done
}

# Start the keep-alive function in the background
keep_sudo_alive &
move_or_link_main_script() {
    if ! [ -h /usr/local/bin/cstk ]; then
    	chmod 750 cstk.sh
        ln -sr "$home_dir/cstk.sh" /usr/local/bin/cstk
        echo "The main script cstk.sh is now accessible globally. You can  run it using 'cstk'." | tee -a "$LOG_FILE"
    fi
}
move_or_link_main_script

if ! [ -h /usr/local/bin/cstk ]; then
    home_dir="$PWD"
else
    REAL_PATH="$(realpath /usr/local/bin/cstk)"
    home_dir="$(dirname "$REAL_PATH")"
fi
log="$home_dir/log"
lib="$home_dir/lib"
bin="$home_dir/bin"
data="$home_dir/data"
cstk_tab_complete="$bin/tab_complete.cstk"
cstk_install="$log/cstk_install.log"
DATE="$(date)"
USER="$SUDO_USER"
HOME="${HOME:-$(getent passwd "$USER" 2>/dev/null | cut -d: -f6)}" # get users home path
shell=$(basename "$SHELL")
TORRENT_FILE="magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337"
DOWNLOAD_DIR="$data"
LOG_FILE="$cstk_install"

echo -e "Todays Date: $DATE \nUser who installed CyberSecurityToolKit: $USER \nHome Path: $HOME \nUsers default shell: $shell \nInstall Output:" | tee -a "$LOG-FILE" &>/dev/null

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        sudo "$0"
    fi
}

bash_version() {
	# Minimum Bash version required
	min_bash_version=4.0
	# Get current Bash version
	current_bash_version=$(bash --version | head -n 1 | awk '{print $4}' | awk -F '(' '{print $1}')
	# Compare versions
	if [[ "$min_bash_version" > "$current_bash_version" ]]; then
	    echo "Error: This script requires Bash version $min_bash_version or higher. You are using version $current_bash_version." | tee -a "$LOG-FILE"
	    exit 12
	fi
}

required_commands=( bc cargo rustup git npm coreutils add-apt-repository python3 python3-pip openssl john curl jq grep fzf nc autoconf xxd netcat tar rlwrap bunzip2 ncat unrar gunzip unzip uncompress dpkg 7z nmap )

install_command() {
  local cmd=$1
  if ! command -v "$cmd" &> /dev/null; then
    echo "Installing $cmd..." | tee -a "$LOG-FILE"
    if command -v apt &> /dev/null; then
      apt install -y "$cmd"
    elif command -v yum &> /dev/null; then
      yum install -y "$cmd"
    elif command -v dnf &> /dev/null; then
      dnf install -y "$cmd"
    elif command -v brew &> /dev/null; then
      brew install "$cmd"
    else
      echo "Error: Package manager not found. Please install $cmd manually." | tee -a "$LOG-FILE"
      exit 13
     fi
  else
    echo "$cmd is already installed." | tee -a "$LOG-FILE"
  fi
}

install_vulscan() {
	    if ! [ -d /usr/share/nmap/scripts/vulscan ]; then
		    pushd /usr/share/nmap/scripts || return
		    git clone https://github.com/scipag/vulscan || return
		    ln -s /usr/share/nmap/scripts/vulscan/vulscan.nse /usr/share/nmap/scripts/vulscan
		    nmap --script-updatedb
		    echo "vulscan nmap vulnability script added to nmap scripting engine in /usr/share/nmap/scripts/" | tee -a "$LOG-FILE"
		    popd || return
		else
			echo "Nmap vulscan looks to be installed" | tee -a "$LOG-FILE"
	    fi
}

install_shc() {
    if ! command -v shc &>/dev/null ; then
        echo "Installing shc..." | tee -a "$LOG-FILE"
        mkdir -p /opt/cstk && pushd /opt/cstk || return
        git clone https://github.com/neurobin/shc.git
        cd shc || return
        ./configure
		if ! [ -f config/config.guess ] || ! [ -f config/config.sub ]; then
			automake --add-missing
		fi
		make
		if [ "$?" -ne 0 ]; then
			bash autogen.sh
		fi
        make install
		popd || return
        echo "shc installed successfully." | tee -a "$LOG-FILE"
    else
        echo "shc is already installed." | tee -a "$LOG-FILE"
    fi
}

breached_parser() {
    if ! [ -d "$data" ]; then
		space_available=$(df -h . | awk '{print $4}' | awk 'NR%3==2')
		available_size=$(echo "$space_available" | grep -oE '[0-9]+') # Extract numeric value and unit (e.g., 124G -> 124 and G)
		available_unit=$(echo "$space_available" | grep -oE '[A-Za-z]')
		case "$available_unit" in  # Convert size to gigabytes for easier comparison
	    	G) available_gb=$available_size ;; # Already in gigabytes, no conversion needed
	    	M) available_gb=$(awk "BEGIN {print $available_size / 1024}") ;; # Convert from megabytes to gigabytes
	    	T) available_gb=$(awk "BEGIN {print $available_size * 1024}") ;; # Convert from terabytes to gigabytes
	    	*) available_gb=0 ;; # If it is not G, M, or T, it is too small
		esac

		if (( $(echo "$available_gb < 42" | bc -l) )); then # Check if available space is less than 42GB
			space="f"
		else
			space="t"
		fi
		if [[ "$space" = t ]]; then
			clear
			echo -e "\nThere is a tool in the CyberSecurityToolKit program that will enable you to quickly search through millions of breached emails with there corresponding passwords." | tee -a "$LOG-FILE"
			echo -e "\nThe file once downloaded and extracted is 42 GB and because of the size is only available through bittorrent." | tee -a "$LOG-FILE"
			echo -e "\nYou are seeing this message because you do have the available space in the current directory for the download." | tee -a "$LOG-FILE"
			echo -e "\nYou can decline to download the breached email/password combo list if you choose, just keep in mind some tools will not work as intended." | tee -a "$LOG-FILE"
			echo -e "\nIf aria2c is available and you want to include the email/passwords list, i will download it now, with 'aria2c' if not installed." | tee -a "$LOG-FILE"
			echo -e "\nWould you like me to set this up for you now ?" | tee -a "$LOG-FILE"
			echo -e "\nAnswer with: Y = yes  N = no" | tee -a "$LOG-FILE"
			read -r -n 1 -p "==> " ans
			if [[ "$ans" =~ [Nn] ]]; then
				echo "Not downloading email/password word list" | tee -a "$LOG-FILE"
				echo "Keep in mind you can not run the breached emails tool in the OSINT class." | tee -a "$LOG-FILE"
			elif [[ "$ans" =~ [Yy] ]]; then
				if ! command -v aria2c &> /dev/null; then
					if command -v apt &> /dev/null; then
      					apt install -y aria2
    				elif command -v yum &> /dev/null; then
      					yum install -y aria2
    				elif command -v dnf &> /dev/null; then
      					dnf install -y aria2
    				elif command -v brew &> /dev/null; then
      					brew install aria2
    				else
      					echo "Error: Package manager not found. Please install aria2 manually." | tee -a "$LOG-FILE"
      					read -r -p "Press Enter/Return key after aria2 in downloaded or press N to skip install" ans
      					if [[ "$ans" =~ [Nn] ]]; then
      						aria2="f"
      					else
      						aria2="t"
      					fi
    				fi
				else
					aria2c="t"
				fi
			else
				echo "Bad Option Expected: Y or y for yes N or n for no" | tee -a "$LOG-FILE"
				breached_parser
			fi

			if [[ "$aria2c" = t ]]; then
				echo -e "\nSit back and relax or go find something fun to do this will take between 1 and 3 hours depending on your internet connection" | tee -a "$LOG-FILE"
		    	download="$(aria2c --dir="$PWD" --seed-time=0 "$TORRENT_FILE")"
		    	eval "$download"
		    	sleep 10

		    	if [ -d "$PWD/BreachCompilation" ] && [ -d "$PWD/BreachCompilation/data" ]; then
		    		mv "$PWD/BreachCompilation/data" "."
		    		if [ -d "$PWD/data" ]; then
		    			rm -rf "$PWD/BreachCompilation" &> /dev/null
		    		fi
		    	fi
			else
		    	echo "No supported torrent client installed." | tee -a "$LOG-FILE"
			fi
		else
			echo -e "After checking the available space on your drive \nYou do not have enough room to download the email/password parser tool." | tee -a "$LOG-FILE"
			echo "Keep in mind you can not run the breached emails tool in the OSINT class." | tee -a "$LOG-FILE"
		fi
	fi
}

create_wrapper() {
    INSTALL_DIR="$PWD"
    BIN_DIR="$INSTALL_DIR/bin"
    WRAPPER_PATH="/usr/local/bin/cstk_wrapper"
    if ! [ -f "$WRAPPER_PATH" ]; then

    	{
		echo '#!/bin/bash'
		echo '[[ $- == *i* ]] && { echo "This script cannot be run interactively"; exit 1; }'
		echo 'if [[ -z "$CSTK_MAIN_RUNNER" ]]; then'
    	echo '		echo "This option is not available."'
    	echo '		exit 1'
		echo 'else'
		echo '		CSTK_WRAPPER_RUNNER=1'
		echo "		export PATH=$BIN_DIR:\$PATH"
		echo '		exec "$@"'
		echo 'fi'
    	} > "$WRAPPER_PATH"

    	# Check if the wrapper script was successfully created
    	if [[ $? -eq 0 ]]; then
        	chmod 500 "$WRAPPER_PATH"
        	echo "I installed a Wrapper script in /usr/local/bin/ folder, Please dont move or change the file or this program will not work." | tee -a "$LOG-FILE"
			echo "I did this for 3 reasons." | tee -a "$LOG-FILE"
			echo "1 - so we dont need to source the full bin directory in your shells rc." | tee -a "$LOG-FILE"
			echo "2 - so we dont need to add multipal files to PATH." | tee -a "$LOG-FILE"
			echo "3 - Should you ever decide to remove this program the cleanup process is much easier and safer." | tee -a "$LOG-FILE"
    	else
        	echo "Failed to create the wrapper script at $WRAPPER_PATH" | tee -a "$LOG-FILE"
        	echo "This program will not work without the script." | tee -a "$LOG-FILE"
        	echo "Best option is to run the uninstall.sh script." | tee -a "$LOG-FILE"
        	exit 9
		fi
    fi
}


install_obs() {
	if ! command -v bash-obfuscate &> /dev/null; then
		npm install -g bash-obfuscate &>/dev/null
	fi
}

holehe_install() {
    if command -v pip3 &> /dev/null; then
        pip3 install holehe &> /dev/null
		status=$?
	else
		mkdir -p /opt/cstk/ && pushd /opt/cstk || return
		git clone https://github.com/megadose/holehe.git &> /dev/null
		cd holehe || return &> /dev/null
		python3 setup.py install &> /dev/null
		status=$?
    fi
    if [ "$status" -ge 1 ]; then
    	echo "There was a problem with downloading holehe the email check tool please download from github."
    	echo -e "Use command: 'pip install holehe' if available. \nIf pip is not available \nUse command: git clone https://github.com/megadose/holehe.git"
    fi
}


link_dir_structure() {
    # Create necessary directories first unless this is a update
    if ! [ -d /usr/local/lib/CyberSecurityToolKit ]; then
    	mkdir -p /usr/local/lib/CyberSecurityToolKit
		if [ -d "$home_dir/lib" ]; then
			for files in "$home_dir/lib"/*; do
				[ -e "$files" ] && ln -sr "$files" /usr/local/lib/CyberSecurityToolKit/ &>/dev/null
			done
		fi
    fi
	if ! [ -d /usr/share/doc/CyberSecurityToolKit ]; then
    	mkdir -p /usr/share/doc/CyberSecurityToolKit
    	if [ -d "$home_dir/doc" ]; then
    		for files in "$home_dir/doc"/*; do
    			[ -e "$files" ] && ln -sr "$files" /usr/share/doc/CyberSecurityToolKit/ &>/dev/null
    		done
    	fi
    fi
	if ! [ -d /var/lib/CyberSecurityToolKit ]; then
    	mkdir -p /var/lib/CyberSecurityToolKit
    	if [ -d "$home_dir/data" ]; then
    		for files in "$home_dir/data"/*; do
    			[ -e "$files" ] && ln -sr "$files" /var/lib/CyberSecurityToolKit/ &>/dev/null
    		done
    	fi
    fi
	if ! [ -d /etc/CyberSecurityToolKit/keys ]; then
    	mkdir -p /etc/CyberSecurityToolKit/keys
    	if [ -d "$home_dir/etc/keys" ]; then
    		for files in "$home_dir/etc/keys"/*; do
    			[ -e "$files" ] && ln -sr "$files" /etc/CyberSecurityToolKit/keys/ &>/dev/null
    		done
    	fi
    fi
	if ! [ -d /var/log/CyberSecurityToolKit ]; then
    	mkdir -p /var/log/CyberSecurityToolKit
    	if [ -d "$home_dir/log" ]; then
    		for files in "$home_dir/log"/*; do
    			[ -e "$files" ] && ln -sr "$files" /var/log/CyberSecurityToolKit/ &>/dev/null
    		done
    	fi
    fi
}


install_tab_completion() {
        if [ "$shell" = "zsh" ]; then
            rc="/root/.zshrc"
        elif [ "$shell" = "bash" ]; then
            rc="/root/.bashrc"
        elif [ "$shell" = "fish" ]; then
            rc="/root/.config/fish/config.fish"
        elif [ "$shell" = "ksh" ]; then
            rc="/root/.kshrc"
        elif [ "$shell" = "tcsh" ]; then
            rc="/root/.tcshrc"
        else
            echo "Unknown shell ($shell) detected. Please manually add the line 'source $cstk_tab_complete' to your shell configuration file." | tee -a "$LOG_FILE"
            return 0 # End function here for unknown shell
        fi
		complete="$(grep 'tab_complete.cstk' $rc)"
		if [[ "$complete" != *[tab_complete.cstk] ]]; then
        	# Inform user about tab completion setup
        	echo "If you enjoy using tab completion with scripts, you're in luck!" | tee -a "$LOG_FILE"
        	echo "A tab completion script is available for you to use." | tee -a "$LOG_FILE"
        	echo "To enable tab completion, you need to add a 'source' command to the /root/$rc file." | tee -a "$LOG_FILE"
        	echo "I will not modify your personal files without permission." | tee -a "$LOG_FILE"

        	# Prompt user for permission
        	echo -e "Please select an option:\n1 - Add 'source' to $rc file now.\n2 - I will add the line manually.\n3 - No tab completion." | tee -a "$LOG_FILE"
        	read -r -p "Enter 1, 2, or 3: " opt

        	case "$opt" in
            	1)
                	echo "Adding the source command to your $rc file." | tee -a "$LOG_FILE"
                	echo "source $cstk_tab_complete" >> "/root/$rc"
                	echo "File sourced in /root/$rc." | tee -a "$LOG_FILE"
                	;;
            	2)
                	echo "Please add the following line to your $rc file manually:" | tee -a "$LOG_FILE"
                	echo "source $cstk_tab_complete" | tee -a "$LOG_FILE"
                	;;
            	3)
                	echo "You opted out of tab completion." | tee -a "$LOG_FILE"
                	echo "If you change your mind, add this line to your $rc file:" | tee -a "$LOG_FILE"
                	echo "source $cstk_tab_complete" | tee -a "$LOG_FILE"
                	;;
            	*)
                	echo "Invalid option! If you want tab completion, manually add this line to your $rc file:" | tee -a "$LOG_FILE"
                	echo "source $cstk_tab_complete" | tee -a "$LOG_FILE"
                	;;
        	esac
    	fi
}
set_hashes() {
	SHA_PATH="$home_dir/Other/SecurityChecks"
	sudo find "$home_dir/cstk.sh" "$home_dir/uninstall.sh" "$home_dir/bin/" "$home_dir/lib/" "$home_dir/Malware_of_All_Types/DOS_Bombs/Image-Bombs/" "$home_dir/Malware_of_All_Types/DOS_Bombs/Zip-Bombs/" "$home_dir/Malware_of_All_Types/RootKits/kernel/" "$home_dir/Malware_of_All_Types/RootKits/userland/" "/usr/local/bin/cstk_wrapper" -type f -exec sha256sum {} \; | sort > "$SHA_PATH/sha256.checksum"
	cat "$SHA_PATH/sha256.checksum" > "$SHA_PATH/sha256.checksum2"
}

#######################
# SCRIPT STARTS HERE  #
#######################

need_root
bash_version
link_dir_structure
create_wrapper
install_tab_completion
for cmd in "${required_commands[@]}"; do
  install_command "$cmd"
done
install_vulscan
install_obs
install_shc
holehe_install
breached_parser
set_hashes
read -n 1 -p "Install script is done, Press any key to finish, If you had any errors while running this script then check the log directory for futher information." | tee -a "$LOG_FILE"
rm -- "$0"
exit 0
