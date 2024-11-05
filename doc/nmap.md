# Nmap Helper Script: IP-Sweeper-Wizard

This guide explains how to use the Nmap helper script, "IP-Sweeper-Wizard." This interactive script provides a user-friendly way to run various Nmap scans and ping sweeps on specified targets, with options to customize the scans for different use cases.

## Script Overview

The script offers the following key functionalities:

1. **IP-Sweeper Ping Scan**: Allows you to run a ping scan over a range of IP addresses (e.g., 192.168.1.1-255).
2. **Nmap Scanning**: Offers a variety of Nmap scan types, including SYN scans, UDP scans, and more.
3. **Advanced Scan Customization**: Provides options to select specific ports, timing templates, and masking the real IP address with decoys.
4. **Nmap Scripting Engine (NSE)**: Optionally includes Nmap scripting engine options for in-depth scanning.
5. **Output Management**: Allows you to save scan results in different formats (normal text, XML, grepable).

## Usage

### Step 1: Start the Script

Run the script to begin:

- Displays ASCII art and a welcome message.
- Prompts you to choose between running an IP-Sweeper ping scan or an Nmap scan:
    ```
    1. Run IP-Sweeper ping scan on a (255) ip range
    2. Run an nmap scan against a target host(s)
    3. Exit the script
    ```

### Step 2: Choose an Option

- **Option 1**: Runs a ping scan on a specified IP range.
- **Option 2**: Proceeds to configure an Nmap scan.
- **Option 3**: Exits the script.

### Step 3: Configure Nmap Scan (Option 2)

If you select an Nmap scan:

1. **Select Scan Type**: Choose between a ping scan, standard Nmap scan, or other types:
    - Ping Scan Options (e.g., TCP-SYN-PING, UDP-PING).
    - Nmap Scan Types (e.g., TCP-SYN-SCAN, UDP-SCAN).
2. **System Info Checks**: Option to include OS detection, service version detection, and vulnerability script scanning.
3. **Port Selection**: Option to choose top ports to scan (e.g., top 5 ports to all 65,535 ports).
4. **Timing Options**: Choose a timing template ranging from T0 (paranoid) to T5 (insane).
5. **Masking with Decoy IPs**: Option to mask the scan with decoy IP addresses.
6. **Nmap Scripting Engine (NSE)**: Option to include NSE scripts for in-depth scanning.

### Step 4: Saving Scan Results

- **Save Output**: Option to save the scan results in various formats:
    - Normal text file (-oN)
    - XML file (-oX)
    - Grepable file (-oG)
    - All three options (-oA)

### Step 5: Execute the Scan

- The script constructs the final Nmap command based on the options you've chosen.
- Prompts you to confirm running the scan:
    ```
    Would you like to run the nmap command? Y|N
    ```

- If you choose 'Y', the script runs the Nmap scan with the constructed command.
- If you choose 'N', the script exits.

## Code Walkthrough

### Main Workflow

- **Menu Display**: Presents a series of options to the user to guide them through configuring a scan.
- **Ping Scan and Nmap Scan**: Calls functions to set up either a ping sweep or an Nmap scan based on user input.
- **Scan Customization**: Offers a variety of customization options including scan type, ports, timing, decoy IPs, and NSE scripts.
- **Output Management**: Allows saving the results to a file in the desired format.
- **Execution**: Constructs and executes the Nmap command, or exits based on user input.

### Key Points

- **Interactivity**: The script is designed to be highly interactive, with options to customize nearly every aspect of the scan.
- **Output Flexibility**: Supports multiple output formats for saving scan results.
- **Ease of Use**: Provides a straightforward, guided process to perform complex network scans.

## Conclusion

The "IP-Sweeper-Wizard" script serves as a comprehensive tool for performing network scans using Nmap. Its interactive nature and extensive options make it suitable for both beginners and advanced users looking to perform customized scans. The script streamlines the process of running various types of scans, making it easier to identify network vulnerabilities and gather detailed information.
