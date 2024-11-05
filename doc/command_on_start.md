# Script to Add Command to Run at Startup

This guide explains how to use a script to add a user-specified command to run at system startup. The script encodes the command using Base64 for basic obfuscation before appending it to the `/etc/rc.local` file.

## Script Overview

The script performs the following steps:

1. **Prompt for Command**: Asks the user to enter a command they want to execute at startup.
2. **Base64 Encoding**: Encodes the user-supplied command using Base64 encoding.
3. **Prepare the Command for Execution**: Constructs a decoding command to be executed at startup.
4. **Modify `/etc/rc.local`**: Appends the encoded command to `/etc/rc.local` so it will run during system startup.

## Prerequisites

- Ensure you have superuser (`sudo`) privileges, as modifying `/etc/rc.local` requires elevated permissions.
- Make sure `/etc/rc.local` is present and executable on your system. If it's not present, you might need to create it and make it executable.

## Usage

### Step 1: Run the Script

Execute the script with the necessary permissions. The script will:

- Prompt you to enter the command you wish to run at startup:
    ```
    Enter command to run at startup
    ==> 
    ```

### Step 2: Enter the Command

Enter the desired command and press Enter.

### Step 3: Script Execution

The script performs the following:

- Encodes the entered command using Base64:
- Prepares the command for execution on startup by creating a decoding command:
- Appends the decoding command to `/etc/rc.local`:

### Step 4: Confirm the Modification

After successfully appending the command, the script will output:

This confirms that the command has been successfully added to run at startup.

## Code Explanation
- Prompt user for the command to run at startup
- Encode the command using Base64
- Create a decoding command to execute at startup
- Append the decoding command to /etc/rc.local
- Confirm the addition
```bash
 	Appended encoded command to /etc/rc.local
```
## Conclusion

The script is a fast and easy way to create persistence in a system using the correct commands.
