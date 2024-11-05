# Tools Information File

The Tools used in this program are split into four sections

- OSINT TOOLS

- PAYLOADS TOOLS

- POST EXPLOIT TOOLS

- ETC TOOLS

Lets look at each Tool and get a better idea how we can use this information to aid in out mission.

## Tools Menu Options

1. OSINT TOOLS

  - IP Lookup

    - This tool is a simple program to search a API for the location of a given ip address (city, state, reagon, zip, latatude, longatude).

  - Ping Sweeper

    - This tool uses the ping command to automate running ping against multi ip addresses only relaying information on successful respondes.

  - Nmap

    - This tool is used to help aid a person who may have trouble running a successful nmap command.

  - Pawned Email/Password Combo's

    - This tool searches through millions of pawned email accounts and retreves email/password combos of users given domain name.

2. PAYLOADS TOOLS

  - Netcat Bind/Reverse Shells

    - These tools creates a script that when the victim runs on computer it will connect with your computer giving us access without there knowledge.

      - The **Bind** Payload opens a port on victim computer for us to connect, once we connect there computer will give us a shell session.

      - The **Reverse** Payload once victim runs on there computer will try to reach our computer, if available it will give us a shell session on there computer.

      - It is important to note that if using the *reverse* Payload, you need to have a netcat listener running (not included).

  - Linux Backdoor Creater Tool

    - This tool uses more then 20 different types of payloads to give you access to a victim's computer.

    - This tool checks for many different programs in witch a backdoor shell session can be created on there computer.

  - Ransomware Remote Tool

    - This tool creates a ransomware encryption and decryption script that will need to be ran on target Linux computer.

    - Once ran it will encrypt all files/folders on target computer that are not vital for operation.

    - Some examples of directories that **will be encrypted**

      - home, media, mnt, opt, root

    - Some examples of directories that **will not be encrypted**

      - boot, dev, etc, usr, var, sys, srv, lib*

    - The decryption script will release the files back to the target computer. **IF files have not been changed**

  - Multi Reverse Shell Tool

    - This tool is a multi reverse shell helper script with the ability to run ngrok and/or updog as a proxie server.

    - shells can be encoded in a number of ways and are automatically added to your clipboard.

3. POST EXPLOIT TOOLS

  - Check for VM

    - This is a very simple tool that takes no effort on the users part just run and find out if your shell session is on a VM.

    - Great for checking if you are in a honeypot.

  - Web Browser Password Stealer Tool

    - This tool searches the current computer for web browser files that contain saved passwords, cookies, user sessions and more.

  - Crypto Cash Finder Tool

    - This Tool uses regex patterns to search current computer for known crypto wallet's.

  - File Permission Exploit Tool

    - This tool searches current computer's file permissions and checks with a database for misconfigured permissions that can lead to user becoming a Admin or Root user.

  - Kernal Exploits

    - This tool is fast and takes no effort from user just run and get the CVR number if any available. 

  - Command on Start up

    - Create a script that when ran will download a file online and run in memory.

  - Brute Force Archive files

    - Fast and simple way to brute force a password protected zip or rar archive using a word list.

  - Files of Interest

    - Automated Script to collect files and directory structure of the most usefull files/folders for exploiting a system.

4. ETC TOOLS

  - Users and Shells

    - This tool searches current computer for available users and there default shells (bash,zsh,fish).

  - Python Webserver

    - This tools starts a webserver on current computer used to easily transfer files to a remote computer.

  - Extract files

    - This tool aids in easily extracting many different archive file types (tar, bz2, 7z, rar, gz, zip, deb, wz, Z). 

  - Openssl helper 

    - This is a multi use tool that helps create Public/Private keys, hash passwords, create a checksum of a file, check a checksum of a file, encrypt/decrypt a file using a password, plus a bonus tool that will create a completely random password of choice.

  - gpg secret message

    - A fun little tool for encoding a message to look like a gpg key file.

  - Create a binary executable bash or sh shell script

    - This tool will take a shell script and encrypt it using multipal encryption methods and push out a executable binary file. 

### !! Important Information !! 

**POST EXPLOIT TOOLS - ONLY RUN ON THE CURRENT COMPUTER**

Payloads requiring a **netcat listener** for success are the **Reverse** payloads, This is achived using the below command.

*nc -lvnp port number* 

Where `port number` is the choosen  port you picked when running the program.

Example: say you picked port 3456 when running the *netcat reverse shell tool*. User needs to run the below command.

``` 
nc -lvp 3456
```
nc = program name in this case netcat

l = listen - listen for incoming connection

v = verbose - give more details

p = port - the port number for (l) listener to listen on

If you create a script for victim to run on there computer that says contact my computer on port 3456 and you open any other port except 3456 the connection will fail.

---

Payloads requiring a known victim ip address are **Binding Payloads**

When using a *bind Payload* user must already know the victim's ip address, this is why *reverse payloads* are used more often.

Example: If we want to connect to victim computer and they ran our *netcat bind payload script* then the code below will help us achieve this.

```
nc 192.168.1.1 3456
```
nc = program name in this case netcat

192.168.1.1 = victim computer ip address waiting for us to connect

3456 = port number we told victim computer to open for us and let us connect to when we created the *netcat bind payload script*

#### Conclusion 

As you can see you have a array of tools available in your tool belt. 

To better understand each tool i have provided a help file for every tool available.

