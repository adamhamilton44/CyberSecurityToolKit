# PAYLOAD Tool: Netcat Reverse Shell

This guide explains how to use the Netcat reverse shell script, which automates the process of creating a malicous script to send to the target once ran they will try to connect to your machine and then give you remote access. 

The script includes built-in evasion and cleanup mechanisms to help ensure stealth and security.

## Prerequisites

Ensure that `netcat` (or `nc`) is installed on computer.

Must have a netcat listener running on your computer and waiting for a connection. 

## Script Overview

The reverse shell script tells the target machine to make a outgoing connection to your machine. 

When a connection is established, it provides remote access to the target machine. 

The script automates the integration of the remote access along with evasion and cleanup functionalities.

## Usage

### Step 1: Choose your available ip addresses and a port to tell victim computer to reach you at 

The script will ask you what ip address you want to use and port to connect to. (1-65535)

A computer has a minimum of 2 ip addresses one internal and one external, if sending to a computer on the same network you can use the internal ip usually a number like `192.168` or `10.10`

If sending to a target computer outside of your network a external ip address will need to be used. 

A script will be produced for you to use social engineering to get victim to run on there computer

### Step 2: Victim runs script

Once victim runs the script there are 3 parts

- evasion part will stop the saving of commands in the history file.

- script will also trap (avoid) signals that try to kill the netcat connection. Example  CTRL+X

Next if user is not using sudo or is not root, the script will check if user has sudo permissions and tell user it needs sudo priviledges to run if available.

- If user doesn't have sudo or root available script will cleanup and remove itself.

- If user has sudo priviledges script will ask user a yes or no question to use sudo.

If user says no script will fail and exit using the cleanup part to cover it's tracks.

If user says yes to sudo then the script will switch to root and wait for user to enter password.

Once user enters there password script will add your ip address to the allow list in ip tables.

Next the script will try to reach your computer on same ip and port as you choose once connected you will have access to target computer

### Step 3: Victim computer tries to connect to yours

If user has sudo/root and ran script a netcat connection will run in the background hidden from the command line.

### Step 4: Connect to target computer

As long as you have a  netcat listener open and waiting for a connection we can now connect to victim

``` bash
nc -lvnp [PORT]
```

nc = netcat command

-l = listen

-v = verbose

-n = numeric-only IP addresses

-p = open a port for connection

port = port number you choose to open on your computer

Note that **ONLY -l and -p are needed** for a reliable connection

### Step 5: If all works out as intended you will have root priviledges on victim computer

### Step 6: Cleanup

Once user ends the connection or victim doesn't issue root priviledges script goes into cleanup.

- With root

  - delete ip address from allowed list in ip tables

  - Clean logs and history

  - reset the saving of commands to the history file

  - delete itself avoiding detection

- Without root

  - script will not run a netcat command

  - scrpt will empty the history file

  - script will reset the saving of commands to the history file

  - script will delete itself leaving little to no fingerprint


## Conclusion

This script will generate an executable file named NetcatReverseShell which includes all the necessary components for evasion and cleanup.

The Netcat reverse shell script provides a powerful and automated way to establish remote access while incorporating evasion and cleanup mechanisms to maintain stealth and security.

Change the name of script before sending.
