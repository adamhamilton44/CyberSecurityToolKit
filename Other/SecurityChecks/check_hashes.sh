#!/bin/bash

[[ "$EUID" -ne 0 ]] && exec sudo "$0" "$@"

real_path="$(realpath /usr/local/bin/cstk)"
base_dir="$(dirname "$real_path")"
K_ROOT_KITS="$base_dir/Malware_of_All_Types/RootKits/kernel"
U_ROOT_KITS="$base_dir/Malware_of_All_Types/RootKits/userland"
P_BOMBS="$base_dir/Malware_of_All_Types/DOS_Bombs/Image-Bombs"
Z_BOMBS="$base_dir/Malware_of_All_Types/DOS_Bombs/Zip-Bombs"
SHA_PATH="$base_dir/Other/SecurityChecks"

(set -o noclobber; echo > /tmp/check-hashes.lock) || { echo 'Failed to acquire lock. Another instance is already running.'; exit 1; }

trap 'rm -f /tmp/check-hashes.lock' EXIT

PASSWORD_HASH_FILE="$SHA_PATH/password.hash"
SALT='MosesandAdamsittingnatreeK-i-s-s-ing!!!'

hash_password() {
    local password="$1"
    echo -n "${SALT}${password}" | openssl dgst -sha256 | awk '{print $2}'
}

check_password() {
    local input_password="$1"
    local input_hash stored_hash
    input_hash=$(hash_password "$input_password")

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

reset_hash() {
    sudo find "$base_dir/cstk.sh" "$base_dir/uninstall.sh" "$base_dir/bin/" "$base_dir/lib/" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper" -type f -exec sha256sum {} \; | sort > "$SHA_PATH/sha256.checksum"
    cp "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"
    echo "Hashes reset successfully."
}

check_hash() {
    sudo find "$base_dir/cstk.sh" "$base_dir/uninstall.sh" "$base_dir/bin/" "$base_dir/lib/" "$K_ROOT_KITS/" "$U_ROOT_KITS/" "$P_BOMBS/" "$Z_BOMBS/" "/usr/local/bin/cstk_wrapper" -type f -exec sha256sum {} \; | sort > "$SHA_PATH/sha256.checksum2"

    if ! diff "$SHA_PATH/sha256.checksum" "$SHA_PATH/sha256.checksum2"; then
        echo  "Files hashes do not match!"
        read -p "Enter key to continue"
    else
        echo "All files are verified. No compromise detected."
    fi
}

if [[ -n "$1" ]]; then
    check_password "$1"
else
    check_hash
fi
