# Multi-Language Reverse Shell Generator Script

This guide explains the flow and available options for a script that allows users to generate reverse shells for various programming languages. The script provides encoding options, shell customization, and additional utilities to create shells or payloads tailored to different environments.

## Main Menu

Upon starting the script, the user is presented with the following options:

1. **Powershell**: Generate reverse shell payloads in Powershell.
2. **Netcat**: Generate reverse shells using Netcat.
3. **Bash**: Create Bash-based reverse shells.
4. **Python**: Generate reverse shells using Python (both Python 2 and 3).
5. **Ruby**: Create Ruby-based reverse shells.
6. **Perl**: Generate reverse shells in Perl.
7. **Telnet**: Set up reverse shells using Telnet.
8. **Zsh**: Generate Zsh reverse shells.
9. **PHP**: Create reverse shells using PHP.
10. **Awk**: Generate reverse shells using Awk.
11. **OpenSSL**: Set up OpenSSL-based reverse shells.
12. **Golang**: Create Golang reverse shells.
13. **Files**: Download precompiled tools or scripts for reverse shells (e.g., `nc` binaries, Sharpcat).
14. **Webshells**: Generate web shells in ASP, PHP, and JSP.
15. **Node.js**: Generate reverse shells using Node.js.
16. **Start/Stop Updog**: Manage the Updog web server.
17. **Start/Stop Ngrok**: Manage Ngrok for tunneling.
18. **Exit**: Exit the script.

## IP and Port Configuration

Before generating any reverse shell, the script prompts for the following:

- **Listening IP**: User enters the IP address to receive the reverse shell (default is displayed in brackets).
- **Listening Port**: User specifies the port to listen on (default is displayed in brackets).
  
  Additionally, the user can choose the format of the IP address:

1. **Normal**: Standard IP format (e.g., `192.168.1.1`).
2. **Hexadecimal**: Encodes the IP in hexadecimal.
3. **Long**: Converts the IP address to its long integer form.

## Powershell Reverse Shells

Available for Windows, with encoding options and evasion techniques:

1. Powershell – Windows (No encoding).
2. Powershell – URL-encoded.
3. Powershell – Double URL-encoded.
4. Powershell – Windows Core.
5. VBA Macro (for MS Office).
6. Reflective loading with Sharpcat.

### Powershell Options

- **Block Microsoft Defender** (requires admin privileges).
- **Fill PowerShell Event Log** (EDR evasion).
- **Clear PowerShell Event Logs** (requires admin).
- **Include upload/download functions**.
- **Download/Run AMSI bypass**.
- **Protocol** (default `tcp`).
- **Initialize with command** (default `cmd`).

## Netcat Reverse Shells

Provides reverse shells with various encoding options:

1. No encoding.
2. Base64 encoding.
3. URL-safe Base64 encoding.
4. URL encoding.
5. Double URL encoding.
6. Looping variations for all encoding methods.

### Netcat Options

- **Shell**: Default shell is `/bin/bash`. Can be customized by the user.

## Bash Reverse Shells

Similar to Netcat, but for Bash:

1. No encoding (TCP).
2. Base64 encoding (TCP).
3. URL encoding (TCP).
4. UDP variants.

## Python Reverse Shells

Supports both Python 2 and Python 3, with Windows-specific payloads:

1. Python 3 – No encoding.
2. Python 3 – URL-encoded.
3. Python 2 variations (no encoding, URL-encoded, double URL-encoded).
4. Windows-specific payloads for both Python 2 and 3.

### Python Options

- **Shell**: Customizable shell (default is `/bin/bash`).

## Ruby, Perl, Telnet, Zsh, PHP, Awk, OpenSSL, Golang

All these languages have similar reverse shell options:

1. No encoding.
2. Base64 encoding.
3. URL-safe Base64 encoding.
4. URL encoding.
5. Double URL encoding.

### Shell Options

- **Shell**: Allows customization of the shell used (default is `/bin/bash`).

## Files

This section provides precompiled binaries for different architectures:

1. `nc` for Linux 64-bit, 32-bit, ARM, and MacOS.
2. `nc` for Windows 32-bit and 64-bit.
3. C++ Powershell scripts for Windows.
4. Sharpcat 64-bit.
5. AMSI bypass scripts (e.g., Rastamouse).

## Webshells

Generates various web-based shells:

1. ASPX – Insomnia.
2. ASPX – Insomnia impersonate reverse shell.
3. ASPX – Simple reverse shell.
4. ASP – Simple reverse shell.
5. PHP – p0wnyshell.
6. PHP – Simple reverse shell.
7. JSP webshell.

## Node.js Reverse Shells

For Node.js-based reverse shells, users can choose from different encoding options and specialized XSS variants:

1. No encoding.
2. Base64 encoding.
3. URL-safe Base64 encoding.
4. URL encoding.
5. XSS variants.

### Node.js Options

- **Shell**: Customizable shell (default is `/bin/bash`).

## Additional Options

- **Updog**: Start or stop the Updog web server.
- **Ngrok**: Start or stop Ngrok for tunneling.

## Conclusion

This script provides a versatile and user-friendly interface to generate reverse shells in various languages, with customizable encoding, shell options, and additional utilities for evasion and file handling. 

It supports both Linux and Windows environments, offering flexibility in generating the payloads needed for different scenarios.
