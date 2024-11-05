# OSINT Tool: Ping Sweeper

This guide explains how to use the `ping_sweeper` bash script to perform an IP sweep across a 255 octet IP range. 

The script fetches and displays all IP addresses that respond to the ping.

## Prerequisites

Before running the script, ensure that the following requirement is met:

- Ping Command

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Script will ask for user input for the ip address range to sweep

The script will ask for a ip address using **ONLY** the first **3** octets

**Correct way**

- 192.168.1           *3 sets of numbers (1-255) 2 dots (.)*

**Incorrect way**

- ~~192.168.1.~~      *No ending dot needed*

- ~~192.168.1.123~~   *Too many octets*

- ~~192.168~~          *Too few octets*

### Step 3: Prompt user on how to save the output

You will be prompted to save the output or print to screen or both:

1. Save information to a file

2. Print to screen only

3. Both save output to a file and print to screen

- Should user save output to a file (option 1 or 3) then file is saved in current working folder

### Step 4: Fetch IP Address Data

The script uses the entered IP address to fetch data using the `ping` command:

### Step 5: Print to file, screen, or both

- If the ping sweep is successful, the script display the following details:

  - **192.168.1.1**

  - **192.168.1.3**

  - **192.168.1.15**

  - **192.168.1.134**

If saving to a file the information will be saved to a file named *pingsweep-`user input`.txt*

- Example: *pingsweep-192.168.1.txt*

- If the script doesn't find any IP addresses the text file is still created and will only include the date

## Conclusion

This script is a simple and effective way to perform an IP address lookup and retrieve relevant detail on a 255 octet ip range.

