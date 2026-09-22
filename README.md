# CyberSecurityToolKit - A Beginner Friendly Tool Kit for Hackers, Red Teamers, and Penetration testers

![Cyber Security Tool Kit](https://github.com/user-attachments/assets/bccc925c-d373-4c6a-9ac0-226cde5edd7e)

## Author

Adam Hamilton

- [Github](https://www.github.com/adamhamilton44)

- [Email](blacklisthacker@protonmail.com)

## Contributing

Contributions are always welcome!

## Features

There are 4 Classes in total: OSINT, Payloads, Post Exploit, Etc.

### OSINT

- IP address lookup tool
- Nmap helper script
- ping sweeper tool
- Check a email address on multiple sites
- Breached email/password lookup tool
- Google dorks helper
- Automated enumeration script of a internet facing web site
- Automated vulnerability scanner of a internet facing web site
- Password attack tool for online/offline attacks

### Payloads

- Netcat Reverse/Bind Shell Scripts
- Linux reverse shell creation tool with 30+ shells
- Ransomware encrypt/decrypt tool
- Multi OS reverse shell creater
- Run in memory payload tool
- DoS zip, computer-killer, and fork-bomb payloads
- SSH payload script
- Metasploit & msfvenom helper
- Create a malicious APK file

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
- In memory password dumper

### Etc

- Enumerate users and there shells
- Python web server for easy file transfers
- Multi archive file extracter
- Openssl helper with random byte generator
- Secret message creater
- Turn a bash scrpt into a encrypted executable binary script
- Post exploit zip file with all the needed tools to open and run on remote host
- Create a array encrypted script that can be run on the remote host
- Log cleaner tool to hide your tracks

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

A Script will be added to /usr/local/bin/cstk
Run anywhere

```bash
sudo cstk
```

A wrapper script is also added to /usr/local/bin/cstk_wrapper

## Updates

CSTK does not contact package indexes or source repositories during normal
startup. Check for updates explicitly:

```bash
sudo cstk --check-updates
```

Review the reported scope and run the combined updater when ready:

```bash
sudo cstk --update
```

The updater asks for confirmation and is limited to packages and tools that
the CSTK installer recorded. It updates tracked pipx applications, supported
GitHub or Go tools, and CSTK-installed system packages. It does not perform a
full operating-system upgrade, remove packages, or overwrite a dirty or
diverged Git checkout. CSTK itself is updated only through a clean,
authenticated Git checkout using a fast-forward-only pull. After a CSTK
self-update, the launcher requests the private integrity refresh key, rebuilds
and verifies the checksum manifest, and only then starts the updated code.

## Tested on

- Kali-Linux 6.11.2

## Install script works for

- apt
- yum
- dnf
- brew

## Important Information

- When program is ran most files have there SHA256 hashes checked.

- This helps to ensure the security and authenticity of the files.

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

** Depending on your available hard disk space or your choosen option when install.sh script is ran you may or may not have this directory

If you have any feedback, please reach out to me at [Email](blacklisthacker@protonmail.com)

## 🚀 About Me

👩‍💻 I'm currently working on more bash scripts

💬 Ask me about anything

⚡️ Fun fact I am actually a Professional dog trainer.
[My website](https://good-happy-puppy.com)

## Help Fund My Projects

Bitcoin: 3ENrACvnNY7AYG7HUvcdwJgZjnpoaQ9Lbt
