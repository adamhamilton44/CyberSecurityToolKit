# ETC Tool: Python Web Server

This guide explains how to use the `Python Webserver` script to open a webserver on the current computer.

## Prerequisites

Before running the script, ensure that the following requirement is met:

- **python3**: A scripting language used heavly in Linux Distro's. The script checks if `python3` is installed. If it's not, the script will output an error message and exit.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Check for python3 Installation

The script verifies if `python3` is installed on the system:

- If `python3` is not installed, an error message `Error: python3 not found.` will be displayed, and the script will exit.
- If `python3` is installed, the script proceeds to the next step.

### Step 3: Prompt for Port number (1-65535)

You will be prompted to provide an Port number for the webserver:

Enter the desired port and press Enter.

### Step 4: Check user input is correct

The script will check that user entered the correct information and will repeat until a number between 1 and 65,535 is entered



### Step 5: Start Python Webserver

The script starts a Webser on given port number

This is a fast and dirty means to transfer information from user's computer to another computer.

## Conclusion

This script is a simple and effective way to start a webserver for transfering files from one computer to another. 

Ensure that `python3` is installed and follow the prompts to get the information you need.


