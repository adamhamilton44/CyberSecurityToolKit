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
keep_sudo_pid=$!
# Ensure that the background process is stopped when the script finishes
cleanup() {
    kill "$keep_sudo_pid" 2>/dev/null
}

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
trap 'echo "An error occurred. Exiting."; exit 1' ERR

echo -e "Todays Date: $DATE \nUser who installed CyberSecurityToolKit: $USER \nHome Path: $HOME \nUsers default shell: $shell \nInstall Output:" &>/dev/null

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        sudo "$0" "$@"
        return 1
    fi
}

bash_version() {
	exec > >(tee -a "$LOG_FILE") 2>&1
	# Minimum Bash version required
	min_bash_version=4.0
	# Get current Bash version
	current_bash_version=$(bash --version | head -n 1 | awk '{print $4}' | awk -F '(' '{print $1}')
	# Compare versions
	if [[ "$min_bash_version" > "$current_bash_version" ]]; then
	    echo "Error: This script requires Bash version $min_bash_version or higher. You are using version $current_bash_version."
	    exit 12
	fi
}

required_commands=( bc cargo rustup git npm coreutils add-apt-repository python3 python3-pip openssl john curl jq grep fzf nc autoconf xxd netcat tar rlwrap bunzip2 ncat unrar gunzip unzip uncompress dpkg 7z nmap )

install_command() {
	exec > >(tee -a "$LOG_FILE") 2>&1
  local cmd=$1
  if ! command -v "$cmd" &> /dev/null; then
    echo "Installing $cmd..."
    if command -v apt &> /dev/null; then
      apt install -y "$cmd"
    elif command -v yum &> /dev/null; then
      yum install -y "$cmd"
    elif command -v dnf &> /dev/null; then
      dnf install -y "$cmd"
    elif command -v brew &> /dev/null; then
      brew install "$cmd"
    else
      echo "Error: Package manager not found. Please install $cmd manually."
      exit 13
     fi
  else
    echo "$cmd is already installed."
  fi
}

install_vulscan() {
		exec > >(tee -a "$LOG_FILE") 2>&1
	    if ! [ -d /usr/share/nmap/scripts/vulscan ]; then
		    pushd /usr/share/nmap/scripts
		    git clone https://github.com/scipag/vulscan
		    ln -s "$PWD/vulscan/vulscan.nse" "$PWD/vulscan"
		    nmap --script-updatedb
		    echo "vulscan nmap vulnability script added to nmap scripting engine in /usr/share/nmap/scripts/"
		    popd
		else
			echo "Nmap vulscan looks to be installed"
	    fi
}

install_shc() {
	exec > >(tee -a "$LOG_FILE") 2>&1
    if ! command -v shc &>/dev/null ; then
        echo "Installing shc..."
        mkdir -p /opt/compiler && pushd /opt/compiler
        git clone https://github.com/neurobin/shc.git
        cd shc
        ./configure
		if ! [ -f config/config.guess ] || ! [ -f config/config.sub ]; then
			automake --add-missing
		fi
		make
		if [ "$?" -ne 0 ]; then
			bash autogen.sh
		fi
        make install
		popd
        echo "shc installed successfully."
    else
        echo "shc is already installed."
    fi
}

breached_parser() {
	 exec > >(tee -a /dev/null) >1
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
			echo "There is a tool in the CyberSecurityToolKit program that will enable you to quickly search through millions of breached emails with there corresponding password."
			echo "The file once downloaded and extracted is 42 GB and because of the size is only available through a bittorrent."
			echo "You are only seeing this message if you have the available space in the current directory."
			echo "I will need to use a CLI bittorrent for the download and it does take some time to finish."
			echo "And of course you can decline to download the breached email/password combo list if you choose, just keep in mind some tools will not work as intended."
			echo "If aria2c is available and you want to include the email/passwords list, i will download the aria2c if not installed and then continue with the download of the breached emails."
			echo "Would you like me to set this up for you now?"
			echo "Please answer with only a Y|y for yes, or N|n for no"
			read -r -n 1 -p "==> " ans
			if [[ "$ans" =~ [Nn] ]]; then
				echo "Not downloading email/password word list"
				echo "Keep in mind you can not run the breached emails tool in the OSINT class."
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
      					echo "Error: Package manager not found. Please install $cmd manually."
      					return 13
    				fi
				else
					aria2c="t"
				fi
			else
				echo "Bad Option"
				breached_parser
			fi

			if [[ "$aria2c" = t ]]; then
		    	download="$(aria2c --dir="$PWD" --seed-time=0 "$TORRENT_FILE")"
		    	eval "$download"
		    	sleep 10
				exec > >(tee -a "$LOG_FILE") 2>&1
		    	if [ -d "$PWD/BreachCompilation" ] && [ -d "$PWD/BreachCompilation/data" ]; then
		    		mv "$PWD/BreachCompilation/data" "."
		    		if [ -d "$PWD/data" ]; then
		    			rm -rf "$PWD/BreachComplation" &> /dev/null
		    		fi
		    	fi
			else
		    	echo "No supported torrent client installed."
			fi
		else
			echo -e "After checking the available space on your drive \nYou do not have enough room to download the email/password parser tool."
			echo "Keep in mind you can not run the breached emails tool in the OSINT class."
		fi
	fi
}

create_wrapper() {
    INSTALL_DIR="$home_dir"
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
        	exec > >(tee -a "$LOG_FILE") 2>&1
        	echo "I installed a Wrapper script in /usr/local/bin/ folder, Please dont move or change or this program will not work."
			echo "I did this for 3 reasons."
			echo "1 - so we dont need to source the full bin directory in your bashrc."
			echo "2 - so we dont need to add multipal files to PATH."
			echo "3 - Should you ever decide to remove this program the cleanup process is much easier and safer."
    	else
        	echo "Failed to create the wrapper script at $WRAPPER_PATH"
        	echo "This program will not work without the script."
        	echo "Best option is to run the uninstall.sh script."
        	exit 9
		fi
    fi
}


install_obs() {
	exec > >(tee -a "$LOG_FILE") 2>&1
	if ! command -v bash-obfuscate &> /dev/null; then
		npm install -g bash-obfuscate &>/dev/null
	fi
}

holehe_install() {
	exec > >(tee -a "$LOG_FILE") 2>&1
    holehe_path="$home_dir/Malware_Of_All_Types/OSINT_Email-Social"
    pw="$(echo 'RlBjWnV6SnVQNW00SWdIRmZobTNUR3dWWDdtQW1peVNjMmlUbVhLeAo=' | base64 -d)"
    pw2="$(echo 'IFCECTKBIRAU2QKEJVAU2RCBJVCECRCNIFGUITKBIRGUCTKEJVCE2QKEJVAU2RCLIFCEWQKOJNAU4QKLIRHECS2EJZFUCTSBIRAUSRCBJFHUISCJIRHUQQKPJFEEISKPJBAU6SKBJBCE6SKIIREU6QJTGMZAU===' | base32plain -d)"
    if command -v pip &> /dev/null; then
        pip install holehe &> /dev/null
        status=$?
        if [[ "$status" != 0 ]]; then
            cd "$home_dir/Malware_Of_All_Types/OSINT_Email-Social" &> /dev/null
            git clone https://github.com/megadose/holehe.git &> /dev/null
            cd holehe &> /dev/null
            status=$?
            if [[ "$status" != 0 ]]; then
                openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$holehe_path/holehe.enc" -out "$holehe_path/holehe-1.61-py3.12.egg.zip" -pass pass:"$pw2"
                unzip -P "$pw" "$holehe_path/holehe-1.61-py3.12.egg.zip"
                if [ -d /usr/local/lib/python3.12/dist-packages/ ]; then
                    mv "$holehe_path/holehe-1.61-py3.12.egg" /usr/local/lib/python3.12/dist-packages
                    mv "$holehe_path/usr/local/bin/holehe" /usr/local/bin/holehe
                    rm -rf "$holehe_path/usr" "$holehe_path/holehe-1.61-py3.12.egg.zip"
                else
                    python_version="$(find /usr/local/lib/ -type d -iname 'python3.*')"
                    mv "$holehe_path/holehe-1.61-py3.12.egg" "$python_version/dist-packages"
                    mv "$holehe_path/usr/local/bin/holehe" /usr/local/bin/holehe
                    rm -rf "$holehe_path/usr" "$holehe_path/holehe-1.61-py3.12.egg.zip"
                fi
            else
                python3 setup.py install &> /dev/null
                cd ../ &> /dev/null
                rm -rf holehe &> /dev/null
            fi
        fi
    fi
}


link_dir_structure() {
	exec > >(tee -a "$LOG_FILE") 2>&1
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

move_or_link_main_script() {
	exec > >(tee -a "$LOG_FILE") 2>&1
	if ! [ -h /usr/local/bin/cstk ]; then
		ln -sr "$home_dir/cstk.sh" /usr/local/bin/cstk
		echo "The main script cstk.sh is now accessible globally. You can  run it using 'cstk'."
	fi
}

install_tab_completion() {
	exec > >(tee -a "$LOG_FILE") 2>&1

        if [ "$shell" = "zsh" ]; then
            complete="$(grep 'tab_complete.cstk' /root/.zshrc)"
        elif [ "$shell" = "bash" ]; then
            complete="$(grep 'tab_complete.cstk' /root/.bashrc)"
        elif [ "$shell" = "fish" ]; then
            complete="$(grep 'tab_complete.cstk' /root/.config/fish/config.fish)"
        elif [ "$shell" = "ksh" ]; then
            complete="$(grep 'tab_complete.cstk' /root/.kshrc)"
        elif [ "$shell" = "tcsh" ]; then
            complete="$(grep 'tab_complete.cstk' /root/.tcshrc)"
        else
            echo "Unknown shell ($shell) detected. Please manually add the line 'source $cstk_tab_complete' to your shell configuration file."
            read -r -n 1 -p "Press Enter to continue without tab completion support."
            return 0 # End function here for unknown shell
        fi

		if [[ "$complete" != 0 ]]; then
        	# Inform user about tab completion setup
        	echo "If you enjoy using tab completion with scripts, you're in luck!"
        	echo "A tab completion script is available for you to use."
        	echo "To enable tab completion, you need to add a 'source' command to the /root/$rc file."
        	echo "I will not modify your personal files without permission."

        	# Prompt user for permission
        	echo -e "Please select an option:\n1 - Add 'source' to $rc file now.\n2 - I will add the line manually.\n3 - No tab completion."
        	read -r -p "Enter 1, 2, or 3: " opt

        	case "$opt" in
            	1)
                	echo "Adding the source command to your $rc file."
                	echo "source $cstk_tab_complete" >> "/root/$rc"
                	echo "File sourced in /root/$rc."
                	;;
            	2)
                	echo "Please add the following line to your $rc file manually:"
                	echo "source $cstk_tab_complete"
                	;;
            	3)
                	echo "You opted out of tab completion."
                	echo "If you change your mind, add this line to your $rc file:"
                	echo "source $cstk_tab_complete"
                	;;
            	*)
                	echo "Invalid option! If you want tab completion, manually add this line to your $rc file:"
                	echo "source $cstk_tab_complete"
                	;;
        	esac
    	fi
}
set_hashes() {
	exec > >(tee -a "$LOG_FILE") 2>&1
	K_ROOT_KITS="$PWD/Malware_of_All_Types/RootKits/kernel"
	U_ROOT_KITS="$PWD/Malware_of_All_Types/RootKits/userland"
	P_BOMBS="$PWD/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
	Z_BOMBS="$PWD/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
	SHA_PATH="$PWD/Other/SecurityChecks"
	find "$PWD/cstk.sh" "$PWD/uninstall.sh" "$PWD/lib" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper"  -type f -exec sha256sum {} \; | sort >> "$SHA_PATH/sha256.checksum2"
	cat "$SHA_PATH/sha256.checksum" > "$SHA_PATH/sha256.checksum"
}

#######################
# SCRIPT STARTS HERE  #
#######################

need_root
bash_version
move_or_link_main_script
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
chown -R root:root "$PWD"
chmod 750 ./cstk.sh
chmod 750 /usr/local/bin/cstk
chmod 750 /usr/local/bin/cstk_wrapper
find . -type d -exec chmod 750 {} \;
read -n 1 -p "Install script is done, Press any key to finish, If you had any errors while running this script then check the log directory for futher information."
rm -- "$0"
trap cleanup EXIT
exit 0
