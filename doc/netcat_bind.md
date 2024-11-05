# PAYLOAD Tool: Netcat Bind Shell

This guide explains how to use the Netcat bind shell script, which automates the process of setting up a server on a target machine for remote access.

The script includes built-in evasion and cleanup mechanisms to help ensure stealth and security.

## Prerequisites

Ensure that `netcat` (or `nc`) is installed on computer.

Must have Knowledge of victim's external ip address.

## Script Overview

The bind shell script opens a user chosen port on the target machine and listens for incoming connections.

When a connection is established, it provides remote access to the target machine.

The script automates the integration of the remote access along with evasion and cleanup functionalities.

## Usage

### Step 1: Choose a port to open on victim computer

The script will ask you what port to open on the victim computer. (1-65535)

A port number above 1500 is safer then a port number below.

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

### Step 3: Victim computer open's a port with netcat

If user has sudo/root and ran script a netcat listener will run in the background hidden from the command line.

### Step 4: Connect to target computer

With netcat listener open and waiting for a connection we can now connect to victim

nc [TARGET_IP] [PORT]

nc = netcat command

target_ip = IP address of victim's computer to connect to

port = port you choose to open on victim computer

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

This script will generate an executable file named NetcatBindingShell which includes all the necessary components for evasion and cleanup.

The Netcat bind shell script provides a powerful and automated way to establish remote access while incorporating evasion and cleanup mechanisms to maintain stealth and security.

Change the name of script before sending
