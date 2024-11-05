# Secret Message: GPG Look-Alike Encoder/Decoder

This guide explains how to use a script that allows you to create and decode messages that mimic GPG (GNU Privacy Guard) encrypted messages. The script offers encoding and decoding using Base64 and Hex encoding methods.

## Script Overview

The script provides two main functionalities:

1. **GPG Look-Alike Encoding**: Allows you to create a GPG-like message using either Base64 or Hex encoding.
2. **GPG Look-Alike Decoding**: Decodes a GPG-like message that was previously encoded using this script.

### Features

- **User Input**: Prompts for user inputs such as the message and encoding type.
- **Output Management**: Saves the encoded message to a specified file in the "Loot" directory.
- **Validation**: Checks for the existence of input files before attempting to decode.

## Prerequisites

Ensure that you have the following tools available:

- `base64`: For Base64 encoding and decoding.
- `xxd`: For Hex encoding and decoding.

## Usage

### Step 1: Start the Script

Run the script, and it will prompt you to choose between creating or decoding a GPG look-alike message:


Enter `1` to create a message or `2` to decode a message.

### Step 2: Creating a GPG Look-Alike Message (Option 1)

If you choose to create a message:

- **Enter Filename**: You will be prompted to enter the filename for the output.
    ```
    Enter File name for script output Example: key_gpg.key
    ```
- **Enter Message**: Enter the message you want to encode, enclosed in double quotes.
    ```
    Enter Message using double quotes "MESSAGE BODY"
    ```
- **Select Encoding Method**: Choose between Base64 or Hex encoding.
    ```
    Enter number option for encoding process
    1 - Base64 Encoding
    2 - Hex Encoding
    ```
- The script will create a file with a GPG-like format and save it to the "Loot" directory.
    ```
    [filename] complete and saved in the Loot folder
    ```

### Step 3: Decoding a GPG Look-Alike Message (Option 2)

If you choose to decode a message:

- **Enter Path to File**: Provide the full path and filename of the file to decode.
    ```
    Enter path and file name of file to decode
    ```
- **Select Encoding Method**: Choose whether the file is encoded using Base64 or Hex.
    ```
    Enter encoded type for the file:
    1 - Base64 Encoding
    2 - Hex Encoding
    ```
- The script extracts and decodes the message, then displays it on the screen.
    ```
    Decoded message: 
    [Your Decoded Message]
    ```

## Error Handling

- **File Not Found**: If the specified file for decoding does not exist, the script will notify you:
    ```
    File not found!
    ```
- **No Encoded String Found**: If no encoded string is found in the specified format, it will output an error:
    ```
    No base64 string found in the file!
    ```
- **Invalid Option**: If you enter an invalid option at any prompt, the script will terminate with an error message.

## Code Explanation

- **Encoding**: 
  - Adds a GPG-like header and footer to the message.
  - Encodes the message using the chosen encoding method (Base64 or Hex).
  - Saves the encoded message to the specified file in the "Loot" directory.

- **Decoding**: 
  - Extracts the encoded string between the GPG-like header and footer.
  - Decodes the string using the specified method (Base64 or Hex).
  - Displays the decoded message.

## Conclusion

This script provides a convenient way to create and decode messages that resemble GPG encrypted messages using simple encoding methods. It offers basic obfuscation, but it should not be used as a secure method for encrypting sensitive data. Always use proper encryption tools like GPG for secure communication.
