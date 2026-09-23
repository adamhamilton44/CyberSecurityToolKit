# CyberSecurityToolKit (CSTK)

![CyberSecurityToolKit logo](Other/cstk.png)

CyberSecurityToolKit is a menu-driven collection of security assessment,
payload-development, post-exploitation, and support utilities. CSTK is designed
primarily for Kali Linux and Kali under WSL2.

> [!CAUTION]
> Use CSTK only on systems, accounts, applications, and networks that you own
> or are explicitly authorized to test. Several tools can change files,
> credentials, services, or system availability.

## At a glance

| Class | Purpose | Examples |
| --- | --- | --- |
| OSINT | Reconnaissance and vulnerability discovery | IP lookup, Nmap, host sweeps, web enumeration, account checks, SSH enumeration, and WAF detection |
| Payloads | Controlled payload creation for authorized labs | Reverse-shell, encryption, DoS lab, SSH, Metasploit, APK, and command-and-control helpers |
| Post Exploit | Assessment after authorized access | VM detection, browser-data collection, crypto searches, permission and kernel checks, and archive auditing |
| Etc | Supporting utilities | Users, web servers, archives, OpenSSL, hashes, Bash packaging, Zip2Go, and Arsenal help |

## Requirements

- Kali Linux is the primary supported and tested environment.
- Root access through `sudo` is required.
- Git and Git LFS are required to clone the complete private repository.
- Network access is required during installation and update checks.
- The owner-provided CSTK library key is required to use protected resources.
  The key is installed locally with root-only permissions and is never stored
  in this repository.

The installer contains package mappings for APT, DNF, YUM, and Homebrew, but
Kali Linux receives the most testing.

## Installation

### 1. Enable Git LFS

```bash
git lfs install
```

### 2. Clone the private repository

Use a GitHub account and SSH key that have access to the repository:

```bash
git clone git@github.com:adamhamilton44/CyberSecurityToolKit.git
cd CyberSecurityToolKit
```

### 3. Run the installer

```bash
sudo bash install.sh
```

The installer adds the `cstk` launcher and its restricted wrapper under
`/usr/local/bin/`, installs the manual page and tab completion, records the
packages it installs, and prepares protected local state.

### 4. Start CSTK

```bash
sudo cstk
```

## Main menu

| Choice | Action |
| --- | --- |
| `1` | Open the OSINT tools |
| `2` | Open the payload-development tools |
| `3` | Open the post-exploitation tools |
| `4` | Open the supporting utilities |
| `5` | Turn CSTK launcher authentication on or off |
| `6` | Turn animated headers on or off |
| `U` | Check for and install approved CSTK-managed updates |
| `T` | Display the full TTY shell-upgrade guide |
| `X` | Exit |

Authentication and animated-header preferences are stored locally and are not
committed to Git.

## Command-line help

```bash
sudo cstk -H                 # Short help and examples
sudo cstk --help             # Full option and tool list
sudo cstk -V                 # Version
sudo cstk --tty              # TTY shell-upgrade guide
sudo cstk --check-updates    # Report available managed updates
sudo cstk --update           # Review and install approved managed updates
man cstk                     # Installed manual page
```

Class and tool options can be combined:

```bash
sudo cstk -On
sudo cstk --osint --nmap
```

The first example uses compact short options. The second uses the equivalent
long options.

## Updates

CSTK does not contact package indexes or source repositories during normal
startup. Update checks are always user initiated.

To check without installing:

```bash
sudo cstk --check-updates
```

To review and install approved updates:

```bash
sudo cstk --update
```

The combined updater:

- works only with system packages, pipx applications, Go tools, and GitHub
  repositories recorded or recognized by CSTK;
- shows its scope and asks for confirmation before installing;
- does not perform a full operating-system upgrade;
- does not run `autoremove`;
- refuses to overwrite a dirty or diverged CSTK checkout; and
- updates CSTK itself only through an authenticated, fast-forward-only Git
  pull.

After a CSTK self-update, the already-running trusted launcher privately
requests maintenance authorization, refreshes installed interfaces, rebuilds
and verifies the local checksum manifest, and only then starts the updated
launcher. There is no public integrity-refresh command, and private keys should
never be placed on a command line.

Update logs are written beneath `log/updates/`.

## Integrity protection

CSTK verifies protected program files before opening its menus or dispatching
tools. The protected set includes the launcher, uninstaller, runtime binaries,
library files, checksum verifier, and installed wrapper when present.

The checksum manifest is generated locally at:

```text
Other/SecurityChecks/sha256.checksum
```

It is deliberately excluded from Git and stored with restrictive permissions.

### What happens when verification fails

CSTK does **not** automatically delete itself.

1. CSTK refuses to run the requested tool.
2. The user may quit without changing anything.
3. The user may explicitly choose deletion and must type a second confirmation.
4. The integrity-screen deletion removes CSTK launchers and core program files
   while preserving local data, collected results, logs, wordlists, and
   installed system packages.
5. Authorized maintenance has a private recovery path for rebuilding the
   manifest; it is intentionally not exposed as a normal command-line option.

An unexpected integrity warning should be treated seriously. Quit, review the
changed files, and restore them from a trusted signed commit unless the change
was intentional.

## Local data and generated output

These paths are intentionally excluded from Git:

| Path | Purpose |
| --- | --- |
| `Bank/Loot/` | Scan output, reports, and collected assessment results |
| `Bank/Malware/` | User-generated payloads and executable test artifacts |
| `data/` | Optional breached-account datasets |
| `etc/keys/` | Locally generated keys and other sensitive configuration |
| `log/` | Installer, updater, and runtime logs |
| `Other/Downloads/` | Third-party repositories installed at runtime |
| `Other/SecurityChecks/` | Local authentication settings, installation records, and integrity state; only the verifier is committed |

Back up any local material you need before manually removing the CSTK folder.
Never place credentials, private keys, collected browser data, breached-account
records, or generated payloads in a commit or issue.

## Troubleshooting

- Run `git status --short` before updating. CSTK self-update requires a clean
  checkout.
- Run `git lfs pull` if either ZIP asset is unexpectedly represented by a
  small text pointer.
- Review `log/package_manager/` for installation failures.
- Review `log/updates/` for update-check and update failures.
- Use `sudo cstk --tty` for help stabilizing a limited authorized shell.
- Use `man cstk` for the complete installed command reference.

## Project information

- Version: `3.0.5`
- Primary tested platform: Kali Linux
- License: [Other/LICENSE.txt](Other/LICENSE.txt)
- Author: Adam Hamilton
- GitHub: [adamhamilton44](https://github.com/adamhamilton44)
- Contact: [blacklisthacker@protonmail.com](mailto:blacklisthacker@protonmail.com)

Feedback and carefully scoped contributions are welcome. Do not include secrets
or collected assessment data in reports or pull requests.

## About the author

Adam also works as a professional dog trainer:
[Good Happy Puppy](https://good-happy-puppy.com).

## Support the project

Bitcoin: `3ENrACvnNY7AYG7HUvcdwJgZjnpoaQ9Lbt`
