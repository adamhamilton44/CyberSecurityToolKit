# Class: PAYLOADS - Tool: Linux Backdoor Creater

This guide explains how to use the Linux Backdoor Creater script, which automates the process of creating a malicous script 

Once sent to the target and ran there computer will try to connect to your computer and give you remote access. 

The script includes built-in evasion and cleanup mechanisms to help ensure stealth and security.

## Prerequisites

Ensure that `netcat` (`nc` or `ncat` ) is installed on computer.

Must have a netcat listener running on your computer and waiting for a connection. 

## Script Overview

The reverse shell script tells the target machine to make a outgoing connection to your machine. 

When a connection is established, it provides remote access from the target machine. 

The script automates the integration of the remote access along with evasion and cleanup functionalities.

## Usage

### Step 1: Choose your available ip addresses and a port to tell victim computer to reach you at 

The script will ask you what ip address you want to use and port to connect to. (1-65535)

A computer has a minimum of 2 ip addresses one internal and one external, if sending to a computer on the same network you can use the internal ip usually a number like `192.168` or `10.10`

If sending to a target computer outside of your network a external ip address will need to be used. 

A script will be produced for you to use social engineering to get target to run on there computer

### Step 2: Target runs script

Once target runs the script there are 3 parts 

  - Part 1 evasion 
	
     - To aid in the evasion process the script will only run with sudo or root permissions.

     - Stop the saving of any commands in the history file.

     - Trap (avoid) signals that try to kill the script from running. Example  CTRL+X

     - Adds ip address to the allowed list in ip tables

  - Part 2 backdoor 

     - The main part of the script has 25+ reverse shells commands placed in variables

     - Script will loop through each option till it finds a program user has available on there system (Linux only)

     - Some programs the script looks for are:

     - awk
     - python(2) (3)
     - sh bash zsh
     - php
     - openssl plus many more

     - Once a program is matched it calls the corresponding reverse shell variable and tries to hide the process in the background

     - Next the script will reach out to your computer on same ip address and port number picked earlier 

You need to have a netcat listener running to gain access to target computer

Command for the netcat listener is as followes:

```
nc -lvnp [PORT]
```

**nc = netcat command**

**-l = listen**

**-v = verbose**

**-n = numeric-only IP addresses**

**-p = open a port for connection**

**port = port number you choose to open on your computer**

Note: ** ONLY -l and -p are needed ** 

### If all works out as intended you will have root priviledges on target computer

### Step 6: Cleanup

Once you end the connection script goes into cleanup.

  - delete ip address from allowed list in ip tables

  - Clean logs and history 

  - reset the saving of commands to the history file

  - remove (delete) itself to avoiding detection and reverse engineering

## Conclusion

This script will generate an executable file named RevShell which includes all the necessary components for evasion and cleanup.

The Linux reverse shell script provides a powerful and automated way to establish remote access while incorporating evasion and cleanup mechanisms to maintain stealth and security.

Change the name of script before sending.
