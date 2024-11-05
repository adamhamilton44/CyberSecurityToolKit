# OSINT Tool: IP Lookup

This guide explains how to use the `find_that_ip` bash script to perform an IP address lookup. The script fetches and displays various details about the provided IP address.

## Prerequisites

Before running the script, ensure that the following requirement is met:

- **jq**: A command-line JSON processor. The script checks if `jq` is installed. If it's not, the script will output an error message and exit.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Check for jq Installation

The script verifies if `jq` is installed on the system:

- If `jq` is not installed, an error message `Error: jq is not installed.` will be displayed, and the script will exit.
- If `jq` is installed, the script proceeds to the next step.

### Step 3: Prompt for IP Address

You will be prompted to provide an IP address for lookup:


Enter the desired IP address and press Enter.

### Step 4: Fetch IP Address Data

The script uses the entered IP address to fetch data from the `ip-api.com` service. It sends a request to:

[website](http://ip-api.com/json)


### Step 5: Process Response

The script checks the status of the response:

- If the status is `"success"`, the script will extract and display the following details:
  - **City**
  - **State**
  - **Country**
  - **Zip Code**
  - **Latitude**
  - **Longitude**
  - **Internet Service Provider (ISP)**

The information will be displayed in the following format:

City: [City]
State: [State]
Country: [Country]
Zip: [Zip Code]
Latitude: [Latitude]
Longitude: [Longitude]
ISP: [ISP]


- If the status is not `"success"`, the script will display the message:

Failed to retrieve information.


## Conclusion

This script is a simple and effective way to perform an IP address lookup and retrieve relevant details. Ensure that `jq` is installed and follow the prompts to get the information you need.