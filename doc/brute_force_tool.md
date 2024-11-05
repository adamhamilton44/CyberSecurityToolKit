# Brute Force Tool for Password-Protected Zip and Rar Files

This guide explains how to use a script to brute-force password-protected Zip and Rar files using a wordlist. The script attempts each password from the provided wordlist on the specified archive file until it finds a match or exhausts the wordlist.

## Script Overview

The script performs the following steps:

1. **Prompt for Inputs**: Asks the user to specify the path to a wordlist and the path to the password-protected Zip or Rar file.
2. **Validation**: Checks if the provided wordlist and archive file exist.
3. **Brute Force Attack**: Iterates through each password in the wordlist and attempts to unlock the Zip or Rar file.
4. **Output**: If the correct password is found, it is displayed and saved to a log file. If no password is found, the user is notified.

## Prerequisites

- Ensure you have the `unzip` and `rar` tools installed on your system, as they are required for extracting Zip and Rar files respectively.
- Have a wordlist ready for the brute-force attack, such as `rockyou.txt`.

## Usage

### Step 1: Run the Script

Execute the script with the necessary permissions. The script will prompt you to:

- **Enter the Path to the Wordlist**: 
    ```
    Enter the path and filename of the password word list 
    Example: /usr/share/wordlists/rockyou.txt
    ==> 
    ```

- **Enter the Path to the Zip or Rar File**: 
    ```
    Specify the full path and file name of the zip or rar file to bruteforce
    ==> 
    ```

### Step 2: Validation

The script checks if the specified wordlist and archive file exist:

- If the wordlist is not found:
    ```
    No such dictionary
    ```
- If the archive file is not found:
    ```
    No such file found
    ```

### Step 3: Brute Force Attack

If both files are valid, the script proceeds with the brute-force attack:

- For a **Zip file**:
  - Attempts to unzip the file using each password from the wordlist.
  - If successful, it outputs:
    ```
    Found password: [password]
    ```
  - Logs the found password to `password_bruteforce_zip.txt`.

- For a **Rar file**:
  - Attempts to extract the file using each password from the wordlist.
  - If successful, it outputs:
    ```
    Found password: [password]
    ```
  - Logs the found password to `password_bruteforce_rar.txt`.

### Step 4: Results

- If a password is found, the script stops and displays the password.
- If no password is found after exhausting the wordlist:
    ```
    Password not found. Try another dictionary
    ```

## Code Explanation

- Enter the path and filename of the password word list \nExample: /usr/share/wordlists/rockyou.txt"
- Specify the full path and file name of the zip or rar file to bruteforce"
- Validate files and directories
- Atempts to brute force the password protected zip or rar file

## Conclusion

The script is a easy and fast way to attempt to gain access to a password protected zip or rar file.

