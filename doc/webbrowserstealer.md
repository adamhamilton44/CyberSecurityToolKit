# Post Exploitation Tool: Browser Info Stealer

This guide explains how to use the `browser_data` bash script to collect browser information from different operating systems. The script supports Windows, macOS, and Linux, with various architecture options for each OS.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Select Operating System

You will be prompted to select the operating system type:

Enter OS type:

1 - windows

2 - Osx

3 - Linux


Enter the corresponding number for the operating system you are using and press Enter.

### Step 3: Select Architecture

#### For Windows

If you select Windows (option `1`), you will be prompted to choose the architecture type:

Enter type:

1 - 32 bit

2 - 64 bit


Enter the corresponding number for your system architecture and press Enter.

- **32 bit**: If you choose `1`, the script will run the command stored in the variable `$win32`.
- **64 bit**: If you choose `2`, the script will run the command stored in the variable `$win64`.
- **Incorrect Option**: If an invalid option is entered, the script will display:

Incorrect Option


#### For macOS

If you select macOS (option `2`), the script will run the command stored in the variable `$osx`.

#### For Linux

If you select Linux (option `3`), you will be prompted to choose the architecture type:

Enter Type:

1 - 386

2 - amd64

3 - arm64


Enter the corresponding number for your system architecture and press Enter.

- **386**: If you choose `1`, the script will run the command stored in the variable `$linux386`.
- **amd64**: If you choose `2`, the script will run the command stored in the variable `$linuxamd`.
- **arm64**: If you choose `3`, the script will run the command stored in the variable `$linuxarm`.
- **Incorrect Option**: If an invalid option is entered, the script will display:

Incorrect Option


### Step 4: Execute the Script

Depending on the options you choose, the script will execute the appropriate command for your operating system and architecture.

### Note

The script relies on several files and external commands that are not provided in this guide. 

The actual data collection and processing are handled by these external scripts and tools. 

The data is received in JSON format, and `jq` is used to parse and extract the needed information.

## Example

1. Run the script.
2. Select the operating system (e.g., `1` for Windows).
3. Select the architecture type (e.g., `2` for 64-bit Windows).
4. The script will execute the corresponding command and perform the browser data collection.

## Conclusion

This script provides a flexible way to collect browser information across different operating systems and architectures. 

Ensure you follow the prompts accurately to gather the necessary data.


