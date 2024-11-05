# Class: ETC - Tool: File Extractor

This guide explains how to use the `extract_archive` bash script to extract various types of archive files. The script supports multiple archive formats and ensures that the necessary extraction tools are installed on the system.

## Prerequisites

Before running the script, ensure that the following extraction tools are installed:

- **tar**
- **bunzip2**
- **unrar**
- **gunzip**
- **unzip**
- **uncompress**
- **dpkg**
- **7z**

The script checks for the presence of these tools and will output an error message if any are missing.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Check Required Commands

The script verifies if the required extraction tools are installed:

- If any of the tools are not installed, an error message specifying the missing tool will be displayed, and the script will exit.

### Step 3: Enter Archive File Path

You will be prompted to enter the full file path of the archive you wish to extract:

Provide the full path to the archive file and press Enter.

### Step 4: Extract the Archive

The script checks if the provided file exists. If it does, it will attempt to extract the archive based on its file extension using the appropriate command:

- **.tar.bz2**: `tar -xjf`
- **.tar.gz**: `tar -xzf`
- **.bz2**: `bunzip2`
- **.rar**: `unrar x`
- **.gz**: `gunzip`
- **.tar**: `tar -xf`
- **.zip**: `unzip`
- **.Z**: `uncompress`
- **.deb**: `dpkg -x`
- **.7z**: `7z x`
- **.tar.wz**: `tar -xf`

If the file does not exist, the script will display:

GPT

markdown

# ETC Tool: File Extractor

This guide explains how to use the `extract_archive` bash script to extract various types of archive files. The script supports multiple archive formats and ensures that the necessary extraction tools are installed on the system.

## Prerequisites

Before running the script, ensure that the following extraction tools are installed:

- **tar**
- **bunzip2**
- **unrar**
- **gunzip**
- **unzip**
- **uncompress**
- **dpkg**
- **7z**

The script checks for the presence of these tools and will output an error message if any are missing.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Check Required Commands

The script verifies if the required extraction tools are installed:

- If any of the tools are not installed, an error message specifying the missing tool will be displayed, and the script will exit.

### Step 3: Enter Archive File Path

You will be prompted to enter the full file path of the archive you wish to extract:

Enter archive full file path:

markdown


Provide the full path to the archive file and press Enter.

### Step 4: Extract the Archive

The script checks if the provided file exists. If it does, it will attempt to extract the archive based on its file extension using the appropriate command:

- **.tar.bz2**: `tar -xjf`
- **.tar.gz**: `tar -xzf`
- **.bz2**: `bunzip2`
- **.rar**: `unrar x`
- **.gz**: `gunzip`
- **.tar**: `tar -xf`
- **.zip**: `unzip`
- **.Z**: `uncompress`
- **.deb**: `dpkg -x`
- **.7z**: `7z x`
- **.tar.wz**: `tar -xf`

If the file does not exist, the script will display:

'$archive' is not a valid file

If the file extension is not recognized, the script will display:

'$archive' cannot be extracted by extract_archive()


## Example

1. Run the script.
2. Enter the full file path of the archive when prompted:
3. The script will extract the archive using the appropriate command and display any relevant messages or errors.

## Conclusion

This script is a versatile tool for extracting various types of archive files. Ensure that the necessary extraction tools are installed and follow the prompts to use the script effectively.
