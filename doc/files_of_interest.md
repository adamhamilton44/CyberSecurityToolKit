# Files of Interest Script

This guide explains how to use the "Files of Interest" script to collect various system and user data from a Linux file system. The script gathers a wide range of information, such as user data, system configurations, logs, and network settings, and saves them into a designated directory.

## Script Overview

The script performs the following steps:

1. **Set Up Directories**: Creates a directory to store the collected data.
2. **Collect Information**: Collects various types of information, including user data, system files, configuration files, and network details.
3. **Save Output**: Saves the gathered information into text files within a designated "Files_of_Interest" directory.
4. **Optional Archiving**: Provides an option to compress and archive the collected data into a `.tar.gz` file.

## Usage

### Step 1: Run the Script

Execute the script with appropriate permissions (e.g., `sudo`). The script will:

- Create a directory named `Files_of_Interest` within the `Loot` folder to store the output files.
- Begin scanning the system for various files and information.

### Step 2: Data Collection

The script collects information and saves it into text files, such as:

- **User Data**: Lists files in the user's home directory, browser configuration, and cache files.
- **System Files**: Extracts content from system files like `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, and more.
- **System Configuration**: Gathers details from `/etc/systemd/system`, `/etc/cron`, `/var/spool/cron`, and `/etc/anacron`.
- **Network Information**: Collects network-related information from NetworkManager, DHCP, and active network connections.
- **Logs and Histories**: Retrieves logs from `/var/log` and command histories from bash, zsh, nano, and other shells.
- **Processes and Partitions**: Lists running processes, partitions, and system information from `/proc`.
- **Additional Files**: Searches for files with specific permissions, executables, and commonly modified configuration files.

### Step 3: Archiving Collected Data

Once the data collection is complete, the script will prompt you with the option to compress the collected files:


- **Yes (`y`)**: The script will compress the collected files into a `Files_of_interest.tar.gz` archive and delete the original text files.
- **No (`n`)**: The script will leave all the collected files as individual text files in the `Files_of_Interest` directory.

### Step 4: Output Location

- If you choose to archive the files, they will be saved as `Files_of_interest.tar.gz` in the `Loot` folder.
- If you choose not to archive the files, the collected data will remain in the `Files_of_Interest` directory.

## Code Explanation

- **Directory Setup**: 
  - Determines the script's directory and sets up the `Loot` and `Files_of_Interest` directories for storing outputs.
- **Data Collection**:
  - Uses `ls`, `cat`, and other commands to gather data from various directories and system files.
  - The collected data is saved into text files within the `Files_of_Interest` directory.
- **Archiving Option**:
  - If the user opts to archive the files, the script compresses them into a `.tar.gz` file and moves it to the `Loot` folder.
  - Deletes the original text files after archiving to save space.
- **Error Handling**:
  - Removes empty files generated during the process to avoid clutter.

## Security Considerations

- **Permissions**: The script requires elevated permissions (e.g., `sudo`) to access some system files.
- **Sensitive Data**: Be cautious with the collected data, as it may contain sensitive information like passwords, user configurations, and system settings.
- **Usage**: Use this script responsibly and ensure you have proper authorization to collect this information on the target system.

## Conclusion

The "Files of Interest" script is a powerful tool for gathering a wide range of system and user data on a Linux system. It automates the process of collecting and optionally archiving the data, making it useful for system audits, troubleshooting, and forensic analysis.
