#Class: OSINT - Tool: Pawned Emails

# Breach Data Parsing Tool

This guide explains how to use the `breach_parse` bash script to search through breached data files for specific email domains. The script extracts email-password combinations from a large dataset and saves the results to a specified file. The script includes a progress bar to show the status of the operation, as it can take over 30 minutes to complete.

## Prerequisites

Ensure that you have a directory containing breached data files. The script expects these files to be in a directory specified by the `breached_data` variable.

## Script Overview

The script performs the following steps:

1. Prompts the user for a domain to search and a filename to store the results.
2. Searches through the breached data files for the specified domain.
3. Extracts usernames and passwords associated with the domain.
4. Saves the results to a file in the specified location.
5. Provides a progress bar to indicate the status of the script during execution.

## Usage

### Step 1: Start the Script

Run the `breach_parse` script. You will be greeted with a friendly note indicating that the script will take more than 30 minutes to run.

### Step 2: Confirm or Exit

The script prompts you to press any key to continue or the 'X' key to exit:


Press any key other than 'X' to proceed.

### Step 3: Enter Domain Name

The script prompts you to enter the domain name you wish to search:


Enter the domain name (e.g., `@example.com`) and press Enter.

### Step 4: Enter Output Filename

The script prompts you to enter a filename to store the breached information:


Enter the filename (e.g., `breached_example-accounts.txt`) and press Enter.

### Step 5: Search and Extract Data

The script searches the breached data directory for the specified domain and extracts usernames and passwords. During this process, a progress bar will display the status:


### Step 6: Review Results

After the script finishes running, it extracts the usernames and passwords, then saves the results to the specified file. A summary of the findings is displayed:


The file containing the email-password combinations is saved in the `Loot` directory.

### Step 7: Cleanup

The script removes temporary files used during the extraction process and logs the operation details, including the date, username, domain searched, and the number of results found.

## Conclusion

The `breach_parse` script is an automated tool for extracting specific email-password combinations from breached data files. It provides a simple interface for users to search for specific domains, monitor the progress, and securely store the results.

