#!/bin/bash

check_root() {
	# Ensure script is run as root
	if [[ "$EUID" -ne 0 ]]; then
	    echo "This script must be run as root"
	    exit 1
	fi
}

remove_shc() {
	# Remove the shc directory and its contents
	if [ -d /opt/cstk/shc ]; then
		rm -rf /opt/cstk/shc &>/dev/null
		if [ -f /usr/local/bin/shc ]; then
			rm -rf /usr/local/bin/shc &>/dev/null
		fi
	fi
}

remove_holehe() {
	# Remove the holehe directory and its contents
	if [ -d /opt/cstk/holehe ]; then
		rm -rf /opt/cstk/holehe &>/dev/null
		if [ -f /usr/local/bin/holehe ]; then
			rm -rf /usr/local/bin/holehe &>/dev/null
		fi
	fi
}

remove_all() {
	# Remove symbolic links and directories related to CyberSecurityToolKit
	rm -f /usr/local/bin/cstk_wrapper &>/dev/null
	rm -f /usr/local/bin/cstk &>/dev/null
	rm -rf /opt/cstk &>/dev/null
	find / -type d -name "CyberSecurityToolKit" -exec rm -rf {} + &>/dev/null
    echo "All symbolic links and directories related to CyberSecurityToolKit have been removed."
	rm -- "$0" &>/dev/null
}

delete_script() {
	# Prompt user for confirmation before uninstalling
	echo -e "Are you sure you want to delete the CyberSecurityToolKit program?  y/n \n"
    read -r -p "Type a 'Y' or 'y' for yes Type a 'N' or 'n' for 'no'  ==> " ans
    if [[ "$ans" =~ [Yy] ]]; then
        echo "Uninstalling CyberSecurityToolKit..."
		sleep 3
		remove_links
		remove_shc
		remove_holehe
		remove_all
		echo -e "\nCyberSecurityToolKit has been uninstalled successfully."
		echo "Thank you for using CyberSecurityToolKit!"
		exit 0
	else 
		echo "I am glad you changed your mind. CyberSecurityToolKit will not be uninstalled."
		exit
	fi
}

check_root
delete_script

