# System Environment Detection Script

This guide explains how to use the script to detect if the system is running in a chroot environment or on a virtual machine. This script uses basic Linux commands to check the system's environment and outputs relevant information.

## Script Overview

The script performs two main checks:

1. **Chroot Environment Check**: Determines if the system is running in a chroot environment.
2. **Virtual Machine Check**: Checks if the system is hosted on a virtual machine.

### Chroot Environment Check

- The script lists the inode number of the root directory `/` using `ls -di`.
- It uses `grep` to filter the output and checks if the inode number starts with `2`. If it doesn't, this indicates the system is likely running in a chroot environment.
- If the system is in a chroot, the script will output:
    ```
    Running in chroot
    ```

### Virtual Machine Check

- The script checks the `cpuinfo` file in `/proc` for a line that includes "hypervisor" in the CPU flags, which indicates a virtualized environment.
- If the script finds "hypervisor" in the CPU flags, it outputs:
    ```
    Host is running on a Virtual Machine
    ```
- If it doesn't find "hypervisor", it outputs:
    ```
    Host is not a Virtual Machine
    ```

## How to Use the Script

1. **Run the Script**: Execute the script from the Post Exploit Class option. The script will automatically perform the checks and display the results.

2. **Review the Output**: The script will print one or both of the following messages based on the system environment:
   - `Running in chroot` if the system is in a chroot environment.
   - `Host is running on a Virtual Machine` if the system is running in a virtual machine.
   - `Host is not a Virtual Machine` if the system is not running on a virtual machine.

### Conclusion

The script is a very fast and automated way to check for chroot is enabled and if running on a Virtual Machine
