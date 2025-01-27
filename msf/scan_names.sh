#!/usr/bin/env bash

# Define arrays
ARCH=("aarch64" "armbe" "armle" "x64" "x86")
CONNECT_TYPE=("meterpreter" "shell")
RESPOND_TYPE=("bind_tcp" "reverse_tcp")

# Directory to scan
DIR="$PWD"

# Check if directory exists
if [[ -d "$DIR" ]]; then
    # Iterate over all files in the directory
    for file in "$DIR"/*; do
        # Ensure it's a regular file
        if [[ -f "$file" ]]; then
            # Process each line in the file
            while IFS= read -r line; do
                # Extract components from the line
                for arch in "${ARCH[@]}"; do
                    for connect_type in "${CONNECT_TYPE[@]}"; do
                        for respond_type in "${RESPOND_TYPE[@]}"; do
                            # Match line with optional ARCH, and required CONNECT_TYPE and RESPOND_TYPE
                            if [[ "$line" =~ (^.*/)?($arch/)?$connect_type[/_]$respond_type$ ]]; then
                                if [[ "$line" = */cmd/* ]]; then
                                    continue
                                fi
                                echo "$line" >> CSTK_MSFP2.txt
                            fi
                        done
                    done
                done
            done < "$file"
        fi
    done
fi
