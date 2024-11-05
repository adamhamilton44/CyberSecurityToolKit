# Post Exploitation Tool: Ransomware Creator

This guide explains how to use the `ransomware_script` bash script to encrypt and decrypt files. The script employs AES-256 encryption for the first layer and RSA encryption for the second layer. 

It also provides instructions for the victim to contact you for the decryption key.

## Prerequisites

Before running the script, ensure that the following requirements are met:

- **OpenSSL**: The script checks if `openssl` is installed. 

If it is not installed, the script will output an error message and exit.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step2: Enter Email Address

You will need to enter a email address for the target to respond back (protonmail) is a very good email

### Step 3: Choose an Password

You will be prompted to enter a password for encrypting the self generated RSA 4096 key

You will be prompted twice to confirm the correct password was used

### Encryption Process

#### Step 4: Create a Linux Encryption Script

The script will create a 3 part encryption script, adding the user information provided from above

The 3 parts are:
1. evasion
  - checks for a vitrual machine if true moves to clean up
  - unset the history file helping ensure no fingerprint is left behind
  - traps the SIGKILL and other kill commands from stoping/killing the script
  - script checks for openssl installed on system
  - checks users sudo access or if running as root
    - if sudo/root
      - downloads openssl if not installed with a message saying checking for updates
      - package managers checked for include
        - apt
	- yum
	- dnf
	- brew
      - if openssl is NOT installed and package manager is NOT found script goes to clean up
    - if NOT sudo/root
      - checks users ability to run with sudo permissions + emulator allows sudo
        - if user can sudo
	  - restarts the script with sudo attempting to get user to enter password 
	- if user can NOT sudo
	  - goes to clean up
2. main script
  - script creates a random RSA 4096 key used as the 'Password' for the encryption
  - script then recursively encrypts all files in an array called 'directories'
    - directories encrypted include all non-functioning directories and child directories
      - root folder /root
      - home folder /home/user
      - opt folder /opt
      - mnt folder /mnt
      - media folder /media
    - script will NOT encrypt needed directory paths for system to run including
      - boot folder /boot
      - dev folder /dev
      - proc folder /proc
      - run folder /run
      - srv folder /srv
      - sys folder /sys
      - usr folder /usr
      - var folder /var
      - tmp folder /tmp
        - tmp folder holds the key needed for encryption
  - encrypted files are given a extension called .GOT_YA
    - all non encrypted files in 'direstories' are removed leaving only the encrypted files
  - script then encrypts the RSA key with users choosen password (Step 3)
    - key name is changed to secret.key.Sucker and a copy is placed in all directories that where encrypted
  - script will then create the ransomware note READ_ME_NOW.txt and place a copy in all parent directories where files where encrypted
  - finally script deletes the non-encrypted RSA key and deletes the temp directory created
3. clean up
  - the most important part cover your tracts
  - script removes the content from 7 different log files /var/log/ helping ensure no fingerprint
  - script removes the content of the history file of commands ran in script (pre-caution) incase the unset command failed in the evasion part 
  - lastly the script deletes itself

#### The Ransom Note

The script creates a file named `READ_ME_NOW.txt` containing the ransom note with instructions for the target:

IMPORTANT PLEASE READ.

Your files are encrypted.

If you wish to receive the decrypt key you need to message [Email]

You have 48 hours for us to receive a message starting at [Current Date].

Once we receive a message, you will be given further instructions.

No response in 48 hours and all your information will be available on the dark web to be used and exploited.

Opening, altering, or modifying your encrypted files will void the ability to decrypt later even with the decryption key; they will be lost forever.


#### Other Tips

Once the Ransomware script is created there will also be a decryption script created with the same user password used to decrypt the files should it be needed.


## Conclusion

This script is a powerful tool for encrypting files with multiple layers of security. 

By ensuring that `openssl` is installed and sudo/root must be used along with multipal clean up functions the chance at success is well above average.

