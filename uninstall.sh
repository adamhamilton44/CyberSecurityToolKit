#!/bin/bash

check_root() {
	# Ensure script is run as root
	if [[ "$EUID" -ne 0 ]]; then
	    echo "This script must be run as root"
	    exit 1
	fi
}

remove_shc() {
	if [ -d /opt/cstk ] && [ -e /opt/cstk/shc ]; then
		rm -rf /opt/cstk &>/dev/null
		if [ -f /usr/local/bin/shc ]; then
			rm -rf /usr/local/bin/shc &>/dev/null
		fi
	fi
}

remove_links() {
	rm -f /usr/local/bin/cstk &>/dev/null
    echo "All symbolic links and directories related to CyberSecurityToolKit have been removed."
}

remove_all() {
	rm -rf /usr/local/bin/cstk_wrapper &>/dev/null
	find / -type d -name CyberSecurityToolKit -exec rm -rf {} &>/dev/null \;
	rm -- "$0" &>/dev/null
}

delete_script() {
        echo -e "1 - Remove Everything \n2 - Remove Soft Links only \n"
        read -r -n 1 -p "==> " ans
        if [[ "$ans" -eq 1 ]]; then
        	echo "Uninstalling CyberSecurityToolKit..."
			sleep 3
			remove_links
			remove_shc
			remove_all
		elif [[ "$ans" -eq 2 ]]; then
			echo "Uninstalling CyberSecurityToolKit Links..."
			sleep 3
			remove_links
		else
			echo "Incorrect option"
			exit
		fi
		echo "Uninstallation completed."
}

check_root
delete_script

