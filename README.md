![Cyber Security Tool Kit](https://github.com/user-attachments/assets/6ee2e788-b578-4a37-abff-15650fd1af8a)

# CyberSecurityToolKit - A Beginner Friendly Tool Kit for Hackers, Red Teamers, and Penetration testers 

## Author
Adam Hamilton
- [Github](https://www.github.com/adamhamilton44)

- [Email](blacklisthacker@protonmail.com)

## Contributing

Contributions are always welcome!

## Features

There are 4 Classes OSINT, Payloads, Post Exploit, Etc.

### OSINT
- IP address search tool
- Nmap helper script
- ping sweeper tool
- Compromised email/password parsing tool
- Google dorks helper

### Payloads
- Netcat Reverse/Bind Shell Scripts
- Backdoor creation tool
- Ransomware encrypt/decrypt tool
- Multi OS reverse shell creater
- Run in memory payload tool
- Destroy Computer Payload
- DoS zip/Picture attacks

### Post Exploit
- Check if on a VM
- Web browser infomation stealer
- Crypto wallet search tool
- File Permissions exploit tool
- Kernel/Userland Exploit search tool
- Embed a command on startup
- Brute force 7z,zip and rar archives
- Files of Interest search tool
- Kernel/Userland Rootkits

# Etc
- Enumerate users and there shells
- Python web server for easy file transfers
- Multi archive file extracter
- Openssl helper with random byte generator
- Secret message creater
- Turn a bash scrpt into a encrypted executable binary script

## Run Locally
Clone the project
```bash
git clone https://github.com/adamhamilton44/CyberSecurityToolKit.git
```
Go to the project directory
```bash
cd CyberSecurityToolKit
```
Run the main script cstk.sh or chmod +x install.sh and then run install.sh script
```bash
chmod +x install.sh
sudo bash install.sh
```
or
```bash
sudo bash cstk.sh
```
A Script will be added to /usr/local/bin/cstk
Run anywhere
```bash
sudo cstk
```
A wrapper script is also added to /usr/local/bin/cstk_wrapper 

## Tested on
- Kali-Linux 6.11.2

## Install script works for
- apt 
- yum 
- dnf 
- brew

## Important Information

When program is ran most files have there SHA256 hashes checked.

This helps to ensure the security and authenticity of the files.

## Bad Checksum

- If the hashes do not match program goes into self delete mode

- Everything contained within the CyberSecurityToolKit program will delete.

## User Safe Files and Directories

These are the files and/or folders that are safe for the user to move delete etc and there use case

- CyberSecurityToolKit/Bank/Loot --> This is where hidden gems collected during use of program are stored / ip scans, nmap output, Files of interest etc...

- CyberSecurityToolKit/Bank/Malware --> This is where user created executable scripts will be stored / Reverse shells, Malwareware scripts, Rootkits, etc...

- CyberSecurityToolKit/etc/keys --> This is where user created important files are stored / Private-Public keys, hashed passwords, checksums, etc..

- CyberSecurityToolKit/logs --> Detailed logs of most user events are stored here 

## Netural Files and Folders

Other files and folders that can be tampered with that hashes are not checked (But i am not sure why you would).

- CyberSecurityToolKit/data ** --> used during the breached email/password lookup

- CyberSecurityToolKit/doc --> README.md files

** Depending on your available hard disk space or your choosen option when install.sh script is ran you may or may not have this directory

If you have any feedback, please reach out to me at [Email](blacklisthacker@protonmail.com)

## 🚀 About Me

👩‍💻 I'm currently working on more bash scripts

💬 Ask me about anything

⚡️ Fun fact I am actually a Professional dog trainer.
   [My website](https://good-happy-puppy.com) 

# Help Fund My Projects

Bitcoin: 3ENrACvnNY7AYG7HUvcdwJgZjnpoaQ9Lbt
