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
	if [ -d /opt/cstk ] && [ -e /opt/cstk/shc ]; then
		rm -rf /opt/cstk &>/dev/null
		if [ -f /usr/local/bin/shc ]; then
			rm -rf /usr/local/bin/shc &>/dev/null
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

remove_links() {
	# Remove symbolic links created by the script
	if [ -L /usr/local/bin/cstk_wrapper ]; then
		rm -f /usr/local/bin/cstk_wrapper &>/dev/null
	fi
	if [ -L /usr/local/bin/cstk ]; then
		rm -f /usr/local/bin/cstk &>/dev/null
	fi
	echo "All symbolic links have been removed."
}

delete_script() {
	# Prompt user for confirmation before uninstalling
	echo -e "1 - Remove Soft Links only \n2 - Remove all \n"
    read -r -n 1 -p "==> " ans
    if [[ "$ans" -eq 2 ]]; then
        echo "Uninstalling CyberSecurityToolKit..."
		sleep 3
		remove_links
		remove_shc
		remove_all
		echo -e "\nCyberSecurityToolKit has been uninstalled successfully."
		echo "Thank you for using CyberSecurityToolKit!"
		exit 0
	elif [[ "$ans" -eq 1 ]]; then
		echo "Uninstalling CyberSecurityToolKit Links..."
		sleep 3
		remove_links
		echo -e "\nCyberSecurityToolKit links have been removed successfully."
		echo "Thank you for using CyberSecurityToolKit!"
		exit 0
	else
		echo "Incorrect option"
		exit
	fi
}

check_root
delete_script

