#Class: ETC - Tool: Openssl Helper

This guide explains how to use the `openssl_helper` script. 

## Prerequisites

Before running the script, ensure that the following requirement is met:

- openssl installed

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Script will ask for user input for 8 options 

The script will ask you to enter a number between (1-8)

1. Generate a Random number of bytes (letters, numbers, symbols)
2. Encrypt a single file
3. Decrypt a single file
4. Generate a checksum for a file
5. Verify a file with its checksum
6. Create a public/private key pair
7. Hash a password
8. Exit

### Option 1: Prompt user on what type of bytes to include numbers, uppercase letters, lowercase letters, special caracters

**Example:** 

*Include numbers (y/n):*
- ==> y

*Include uppercase letters (y/n):*
- ==> y

*Include lowercase letters (y/n):*
- ==> y

*Include special characters (y/n):*
- ==> y

The script pulls a random byte one by one from each (Y) Yes option untill length is full

  - 1 number 

  - 1 uppercase letter 

  - 1 lowercase letter 

  - 1 special character 

  - In that order and repeats until lenght is equal to user's final byte length size 

#### Randomize the final bytes length size

  - Script will then randomize the random bytes chosen by the computer.

  - This is to make sure output is as random as possible.

#### Print the random bytes

*Random bytes:* **9<1PvNh0nX;%$5B**

#### Save to file

Finally we ask user if they want there random bytes saved to a file

- If user says (Y): Yes

  - File created as RBG.txt *(Random Bytes Generated) (.txt)*

  - You can continue to save more random bytes of any lenght to the same file. 

  - The script will continue to append the final byte output to the RBG.txt file. 

- If user says (N): No

  - User will be given a option to *press any key to return to main menu* this gives user time to copy the final byte output.

### Option 2: Encrypt a file

User will be asked 3 questions 

1. Path to file to encrypt

2. Path to place encrypted file (include the output file name)

3. Password to use for the ecnryption

  - openssl will encrypt the file with aes-256-cbc salted password encryption

### Option 3: Decrypt a file

User is asked 3 questions (same as above)

1. Path to the encrypted file

2. Path to place the decrypted file (include the output file name)

3. Password to unencrypt file

  -  Password used for the encryption process needs to be the password used for decryption process

### Option 4: Generate a checksum

User is asked 1 question

1. Enter the path and file name to check

  - openssl uses sha-256 checksum

  - this method is used for file integrity (1 single letter in file changes the checksum will not be the same)

  - the checksum is saved to the Parent folder of CyberSecurityToolKit under the etc/keys/file_name.sha256

### Option 5: Verify a checksum

User is asked 2 questions

1. Path and file name of file to verify

2. Path and file name of checksum value (If checksum was created with this program it will be in the etc/keys folder)

  - if file to verify and file with checksum are the same program will print successful

  - if file to verify and file with checksum are different program will print failed

  - this program only uses sha-256 checksum values any other type of checksum value will show a failed attempt

### Option 6: Public/Private key pair

User is asked 3 questions

1. Name for the private key

2. Name for the public key

3. Display the key details on screen

  - keys are made with algorithm RSA and encryption aes-256

  - public key is sent to other person they use the public key to encrypt files when sending to you

  - private key is used for you to decrypt the file

  - this method is military strength encryption

  - generated key are stored in the CyberSecurityToolKit/etc/keys folder

### Option 7: Hash a password

User is asked 1 question

1. Enter password to hash

  - because saving the hashed password to a file would need a gandom name each time in order to not overwrite file...

  - and because using the password to create the file with password as the name is very bad security

  - the hashed password is saved in the keys folder named 'password.sha256_hash.txt'

  - Please move to a different folder or change name between each use. 

## Conclusion

This script is a simple and effective way to work with the openssl program for file integity, password hashing, file encryption/decryption and creating random bytes.

