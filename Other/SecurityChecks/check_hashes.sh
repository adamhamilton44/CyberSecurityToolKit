#!/bin/bash

# Run the script as root if not already
[[ "$EUID" -ne 0 ]] && exec sudo "$0" "$@"

# Paths and variables
real_path="$(realpath /usr/local/bin/cstk)"
base_dir="$(dirname "$real_path")"
K_ROOT_KITS="$base_dir/Malware_of_All_Types/RootKits/kernel"
U_ROOT_KITS="$base_dir/Malware_of_All_Types/RootKits/userland"
P_BOMBS="$base_dir/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
Z_BOMBS="$base_dir/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
SHA_PATH="$base_dir/Other/SecurityChecks"

(set -o noclobber; echo > /tmp/check-hashes.lock) || { echo 'Failed to acquire lock. Another instance is already running.'; exit 1; }
trap 'rm -f /tmp/check-hashes.lock' EXIT

# Password hash file
PASSWORD_HASH_FILE="$SHA_PATH/password.hash"
SALT='MosesandAdamsittingnatreeK-i-s-s-ing!!!'

remove_shc() {
    if [ -d /opt/compiler ] && [ -e /opt/compiler/shc ]; then
        rm -rf /opt/compiler/shc &>/dev/null
        if [ -f /usr/local/bin/shc ]; then
            rm -rf /usr/local/bin/shc &>/dev/null
        fi
    fi
}

remove_links() {
    rm -f /usr/local/bin/cstk &>/dev/null
    rm -rf /usr/local/lib/CyberSecurityToolKit &>/dev/null
    rm -rf /usr/share/doc/CyberSecurityToolKit &>/dev/null
    rm -rf /var/lib/CyberSecurityToolKit &>/dev/null
    rm -rf /etc/CyberSecurityToolKit/keys &>/dev/null
    rm -rf /var/log/CyberSecurityToolKit &>/dev/null
    rm -rf /etc/CyberSecurityToolKit &>/dev/null
}

remove_all() {
    rm -rf /usr/local/bin/cstk_wrapper &>/dev/null
    find / -type d -name CyberSecurityToolKit -exec rm -rf {} &>/dev/null \;
    rm -rf "$0" &>/dev/null
}

# Function to hash the input password
hash_password() {
    local password="$1"
    echo -n "${SALT}${password}" | openssl dgst -sha256 | awk '{print $2}'
}

# Check if the entered password matches the stored hash
check_password() {
    local input_password="$1"
    local input_hash stored_hash

    # Generate input hash
    input_hash=$(hash_password "$input_password")

    # Read stored hash from the file
    if [[ -f "$PASSWORD_HASH_FILE" ]]; then
        stored_hash=$(<"$PASSWORD_HASH_FILE")
    else
        echo "Password hash file not found."
        exit 1
    fi

    if [[ "$input_hash" == "$stored_hash" ]]; then
        echo "Password validated."
        reset_hash
    else
        echo "Invalid password."
        exit 1
    fi
}

# Reset file hashes
reset_hash() {
    sudo find "$base_dir/cstk.sh" "$base_dir/uninstall.sh" "$base_dir/bin/" "$base_dir/lib/" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper" -type f -exec sha256sum {} \; | sort > "$SHA_PATH/sha256.checksum"
    cp "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"
    echo "Hashes reset successfully."
}

# Check file hashes
check_hash() {
    sudo find "$base_dir/cstk.sh" "$base_dir/uninstall.sh" "$base_dir/bin/" "$base_dir/lib/" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper" -type f -exec sha256sum {} \; | sort > "$SHA_PATH/sha256.checksum2"

    if ! diff "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"; then
        echo -e "Files hashes do not match!\nDO NOT RUN any executables in this program!\nFiles may have been tampered with. Please reinstall to ensure safety."
        echo "The program will now exit."
        # Uncomment to remove the program completely
        remove_shc
        remove_links
        remove_all
        exit 1
    else
        echo "All files are verified. No compromise detected."
    fi
}

# Main logic
if [[ -n "$1" ]]; then
    check_password "$1"
else
    check_hash
fi
