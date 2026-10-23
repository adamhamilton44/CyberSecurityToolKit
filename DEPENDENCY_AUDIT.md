# CSTK dependency audit

System install entries: 111 → 95. Removed system defaults: 16.

This is a static use audit, not execution of security tools. Installer/updater declarations, password wordlists, old archives, vendor enumeration data and examples alone are not evidence that a tool is needed. Package aliases are checked explicitly. Catalogue-only references do not justify mandatory installation.

Reference sources are read-only files outside this checkout. A matching source filename does not prove equivalence with an opaque compiled executable. References may include optional checks, hints and descriptions rather than an actual invocation. Unverified dependencies are retained for review rather than removed on absence of a text match.

## Decisions

| Dependency | Kind | Decision | Reason / evidence |
| --- | --- | --- | --- |
| `7zip` | system | Retain; source references | cstk.sh:92, cstk.sh:99, cstk.sh:409 (+16 more; see JSON) |
| `amass` | system | Retain; source references | reference/Osint_enum.sh:196, reference/Osint_enum.sh:198, reference/Osint_enum.sh:199 (+4 more; see JSON) |
| `apache-users` | system | Retain; source references | reference/Osint_enum.sh:776, reference/Osint_enum.sh:777, reference/Osint_enum.sh:778 |
| `apktool` | system | Retain; source references | reference/Payload_apk_builder.sh:114, reference/Payload_apk_builder.sh:239, reference/Payload_apk_builder.sh:241 (+4 more; see JSON) |
| `argon2` | system | Remove automatic install | No executable reference found in the launcher or available maintained tool sources. |
| `aria2` | system | Retain prerequisite | Optional dataset download in install.sh invokes aria2c; retain until that workflow is separately changed. |
| `arjun` | system | Retain; source references | reference/Osint_enum.sh:580, reference/Osint_enum.sh:581, reference/Osint_enum.sh:582 |
| `arp-scan` | system | Retain; source references | reference/Osint_enum.sh:899, reference/Osint_enum.sh:903 |
| `arsenal-ng` | system | Retain; source references | cstk.sh:108, cstk.sh:1268, cstk.sh:2380 (+2 more; see JSON) |
| `assetfinder` | system | Retain; source references | reference/Osint_enum.sh:270, reference/Osint_enum.sh:271, reference/Osint_enum.sh:272 (+1 more; see JSON) |
| `autoconf` | system | Retain prerequisite | autoreconf for shc source build |
| `basez` | system | Remove automatic install | Only executable/example catalogue references found in matching shipped-tool sources. |
| `bc` | system | Remove automatic install | Only executable/example catalogue references found in matching shipped-tool sources. |
| `bloodhound` | system | Remove automatic install | No BloodHound application launch found; enumeration only prints a collector hint. |
| `braa` | system | Retain; source references | reference/Osint_enum.sh:416, reference/Osint_enum.sh:417, reference/Osint_enum.sh:418 |
| `build-essential` | system | Retain prerequisite | C/C++ compilation and make |
| `bzip2` | system | Retain; source references | reference/Etc_extract_archive.sh:23, reference/Etc_extract_archive.sh:36 |
| `cargo` | system | Remove automatic install | No Rust/Cargo build or runtime invocation found; Katana was a Go build. |
| `cewl` | system | Retain; source references | reference/Osint_password_attack.sh:1054, reference/Osint_password_attack.sh:1071, reference/Osint_password_attack.sh:1078 (+2 more; see JSON) |
| `commix` | system | Retain; source references | reference/Osint_enum.sh:705, reference/Osint_enum.sh:707, reference/Osint_enum.sh:708 (+1 more; see JSON) |
| `coreutils` | system | Retain prerequisite | installation/report core commands |
| `crackmapexec` | system | Retain; source references | reference/Osint_enum.sh:372, reference/Osint_enum.sh:373, reference/Osint_enum.sh:374 (+16 more; see JSON) |
| `curl` | system | Retain; source references | cstk.sh:1396, cstk.sh:1397, cstk.sh:1474 (+17 more; see JSON) |
| `dirb` | system | Retain; source references | reference/Osint_enum.sh:547, reference/Osint_enum.sh:548, reference/Osint_enum.sh:549 |
| `dirsearch` | system | Retain; source references | reference/Osint_enum.sh:543, reference/Osint_enum.sh:544, reference/Osint_enum.sh:545 |
| `dmitry` | system | Retain; source references | reference/Osint_enum.sh:204, reference/Osint_enum.sh:206, reference/Osint_enum.sh:207 (+2 more; see JSON) |
| `dnsrecon` | system | Retain; source references | reference/Osint_enum.sh:181, reference/Osint_enum.sh:182, reference/Osint_enum.sh:183 (+2 more; see JSON) |
| `dpkg` | system | Retain; source references | cstk.sh:1261, reference/Etc_extract_archive.sh:23, reference/Etc_extract_archive.sh:42 (+1 more; see JSON) |
| `enum4linux` | system | Retain; source references | reference/Osint_enum.sh:364, reference/Osint_enum.sh:365, reference/Osint_enum.sh:366 |
| `exploitdb` | system | Retain; source references | cstk.sh:1218, reference/Osint_auto_vuln_finder.sh:23, reference/Osint_auto_vuln_finder.sh:95 |
| `feroxbuster` | system | Retain; source references | reference/Osint_enum.sh:535, reference/Osint_enum.sh:536, reference/Osint_enum.sh:537 |
| `ffuf` | system | Retain; source references | reference/Osint_enum.sh:539, reference/Osint_enum.sh:540, reference/Osint_enum.sh:541 |
| `fierce` | system | Retain; source references | reference/Osint_enum.sh:309, reference/Osint_enum.sh:310, reference/Osint_enum.sh:311 |
| `fping` | system | Retain; source references | reference/Osint_enum.sh:313, reference/Osint_enum.sh:316, reference/Osint_enum.sh:317 |
| `fzf` | system | Retain; source references | cstk.sh:60, cstk.sh:1595, cstk.sh:1623 (+4 more; see JSON) |
| `gcc` | system | Retain prerequisite | C compilation |
| `git` | system | Retain; source references | reference/Etc_log_cleaner.sh:23, reference/Etc_log_cleaner.sh:40, reference/Etc_log_cleaner.sh:42 |
| `git-lfs` | system | Retain prerequisite | Git LFS release archive checkout |
| `sed` | system | Retain; source references | cstk.sh:1104, scripts/bin/web_tls_security_assessment:235, scripts/bin/web_tls_security_assessment:238 (+23 more; see JSON) |
| `gobuster` | system | Retain; source references | cstk.sh:1213, reference/Osint_enum.sh:280, reference/Osint_enum.sh:282 (+3 more; see JSON) |
| `golang` | system | Retain; source references | cstk.sh:1623, cstk.sh:1877, cstk.sh:1889 (+8 more; see JSON) |
| `golang-any` | system | Remove automatic install | Duplicate Go toolchain requirement; retain golang. |
| `gospider` | system | Retain; source references | reference/Osint_enum.sh:590, reference/Osint_enum.sh:591, reference/Osint_enum.sh:592 |
| `grep` | system | Retain; source references | cstk.sh:1024, cstk.sh:1067, cstk.sh:1078 (+108 more; see JSON) |
| `gzip` | system | Retain; source references | reference/Payload_CommandAndControl.py:4817, reference/Payload_CommandAndControl.py:4819 |
| `hashcat` | system | Retain; source references | reference/Osint_password_attack.sh:762, reference/Osint_password_attack.sh:767, reference/Osint_password_attack.sh:769 (+7 more; see JSON) |
| `hping3` | system | Retain; source references | reference/Osint_enum.sh:319, reference/Osint_enum.sh:320, reference/Osint_enum.sh:321 |
| `httpx-toolkit` | system | Retain; source references | reference/Osint_enum.sh:350, reference/Osint_enum.sh:351, reference/Osint_enum.sh:352 |
| `hydra` | system | Retain; source references | reference/Osint_enum.sh:728, reference/Osint_enum.sh:729, reference/Osint_enum.sh:730 (+15 more; see JSON) |
| `impacket-scripts` | system | Retain; source references | reference/Osint_enum.sh:873, reference/Osint_enum.sh:875, reference/Osint_enum.sh:879 (+2 more; see JSON) |
| `john` | system | Retain; source references | cstk.sh:1684, reference/Etc_make_binary.sh:24, reference/Osint_password_attack.sh:175 (+23 more; see JSON) |
| `joomscan` | system | Retain; source references | reference/Osint_enum.sh:565, reference/Osint_enum.sh:566, reference/Osint_enum.sh:567 |
| `jq` | system | Retain; source references | cstk.sh:1476, cstk.sh:1477, cstk.sh:1478 (+26 more; see JSON) |
| `libc6-dev` | system | Retain prerequisite | C build headers |
| `lynis` | system | Retain; source references | reference/PostEx_linux_exploit_checker.sh:54, reference/PostEx_linux_exploit_checker.sh:56, reference/PostEx_linux_exploit_checker.sh:65 (+1 more; see JSON) |
| `make` | system | Retain prerequisite | source compilation |
| `masscan` | system | Remove automatic install | No invocation found in available tool sources; enumeration uses Nmap. |
| `medusa` | system | Retain; source references | reference/Osint_password_attack.sh:681, reference/Osint_password_attack.sh:687, reference/Osint_password_attack.sh:690 (+5 more; see JSON) |
| `metasploit-framework` | system | Retain; source references | cstk.sh:78, cstk.sh:1235, cstk.sh:2004 (+26 more; see JSON) |
| `mongodb-server-core` | system | Remove automatic install | Reviewed enumeration uses mongosh client, not a local MongoDB server. |
| `mxcheck` | system | Retain; source references | reference/Osint_enum.sh:394, reference/Osint_enum.sh:396 |
| `mysql-common` | system | Remove automatic install | Common configuration is a client dependency; retain default-mysql-client. |
| `nasm` | system | Retain; source references | cstk.sh:1830, cstk.sh:1831, cstk.sh:1839 |
| `ncrack` | system | Retain; source references | reference/Osint_password_attack.sh:687, reference/Osint_password_attack.sh:724, reference/Osint_password_attack.sh:729 (+5 more; see JSON) |
| `ncat` | system | Retain; source references | reference/Payload_CommandAndControl.py:3904, reference/Payload_CommandAndControl.py:3908, reference/Payload_CommandAndControl.py:3910 (+2 more; see JSON) |
| `nikto` | system | Retain; source references | cstk.sh:1213, reference/Osint_enum.sh:525, reference/Osint_enum.sh:526 (+1 more; see JSON) |
| `nmap` | system | Retain; source references | cstk.sh:55, cstk.sh:116, cstk.sh:1212 (+66 more; see JSON) |
| `npm` | system | Remove automatic install | Only executable/example catalogue references found; no maintained Node build workflow found. |
| `nuclei` | system | Retain; source references | reference/Osint_enum.sh:625, reference/Osint_enum.sh:627, reference/Osint_enum.sh:628 (+4 more; see JSON) |
| `onesixtyone` | system | Retain; source references | reference/Osint_enum.sh:408, reference/Osint_enum.sh:409, reference/Osint_enum.sh:410 |
| `openssh-client` | system | Retain; source references | cstk.sh:65, cstk.sh:77, cstk.sh:1220 (+58 more; see JSON) |
| `openssh-server` | system | Remove automatic install | No local sshd setup/start workflow found; retain openssh-client. |
| `openssl` | system | Retain; source references | cstk.sh:102, cstk.sh:525, cstk.sh:1050 (+33 more; see JSON) |
| `p7zip-full` | system | Remove automatic install | Duplicate archive requirement; retain 7zip with legacy-name fallback. |
| `pyenv-runtime` | system | Remove automatic install | No pyenv invocation; installer uses isolated pipx environments. |
| `python3` | system | Retain; source references | cstk.sh:1689, cstk.sh:1705, cstk.sh:2193 (+42 more; see JSON) |
| `python3-pip` | system | Retain prerequisite | Python packaging/bootstrap |
| `pipx` | system | Retain prerequisite | isolated Python application installation |
| `automake` | system | Retain prerequisite | shc autoreconf/Automake build |
| `libtool` | system | Retain prerequisite | source build support |
| `pkg-config` | system | Retain prerequisite | source build support |
| `wget` | system | Retain; source references | reference/Payload_CommandAndControl.py:2452, reference/Payload_CommandAndControl.py:5402, reference/PostEx_filesofinterest.sh:292 (+1 more; see JSON) |
| `redis` | system | Remove automatic install | Reviewed enumeration uses redis-cli; retain redis-tools instead of a server package. |
| `rlwrap` | system | Remove automatic install | Only executable/example catalogue references found in matching shipped-tool sources. |
| `seclists` | system | Retain; source references | reference/Osint_enum.sh:801, reference/Osint_enum.sh:812, reference/Osint_password_attack.sh:25 (+1 more; see JSON) |
| `sherlock` | system | Retain; source references | reference/Osint_enum.sh:215, reference/Osint_enum.sh:218, reference/Osint_enum.sh:219 |
| `skipfish` | system | Retain; source references | reference/Osint_enum.sh:644, reference/Osint_enum.sh:646, reference/Osint_enum.sh:647 (+1 more; see JSON) |
| `smbclient` | system | Retain; source references | reference/Osint_enum.sh:368, reference/Osint_enum.sh:370, reference/Osint_enum.sh:883 (+1 more; see JSON) |
| `smtp-user-enum` | system | Retain; source references | reference/Osint_enum.sh:386, reference/Osint_enum.sh:388, reference/Osint_enum.sh:390 (+1 more; see JSON) |
| `snmpcheck` | system | Retain; source references | reference/Osint_enum.sh:412, reference/Osint_enum.sh:413, reference/Osint_enum.sh:414 |
| `sqlmap` | system | Retain; source references | reference/Osint_enum.sh:687, reference/Osint_enum.sh:689, reference/Osint_enum.sh:690 (+7 more; see JSON) |
| `sslscan` | system | Retain; source references | reference/Osint_enum.sh:653, reference/Osint_enum.sh:654, reference/Osint_enum.sh:655 |
| `subfinder` | system | Retain; source references | reference/Osint_enum.sh:265, reference/Osint_enum.sh:266, reference/Osint_enum.sh:267 (+1 more; see JSON) |
| `subjack` | system | Retain; source references | reference/Osint_enum.sh:289, reference/Osint_enum.sh:291 |
| `sublist3r` | system | Retain; source references | cstk.sh:1213, reference/Osint_enum.sh:260, reference/Osint_enum.sh:261 (+2 more; see JSON) |
| `tar` | system | Retain; source references | cstk.sh:99, cstk.sh:401, cstk.sh:402 (+37 more; see JSON) |
| `testssl.sh` | system | Retain; source references | reference/Osint_enum.sh:657, reference/Osint_enum.sh:658, reference/Osint_enum.sh:659 |
| `theharvester` | system | Retain; source references | reference/Osint_enum.sh:188, reference/Osint_enum.sh:190, reference/Osint_enum.sh:191 (+2 more; see JSON) |
| `unrar` | system | Retain; source references | reference/Etc_extract_archive.sh:23, reference/Etc_extract_archive.sh:37, reference/Osint_password_attack.sh:1096 (+3 more; see JSON) |
| `unzip` | system | Retain; source references | reference/Etc_extract_archive.sh:23, reference/Etc_extract_archive.sh:40, reference/Osint_password_attack.sh:1095 (+9 more; see JSON) |
| `wafw00f` | system | Retain; source references | reference/Osint_enum.sh:513, reference/Osint_enum.sh:515 |
| `wapiti` | system | Retain; source references | reference/Osint_enum.sh:637, reference/Osint_enum.sh:639, reference/Osint_enum.sh:640 (+1 more; see JSON) |
| `whatweb` | system | Retain; source references | reference/Osint_enum.sh:346, reference/Osint_enum.sh:347, reference/Osint_enum.sh:348 (+3 more; see JSON) |
| `whiptail` | system | Remove automatic install | Only executable/example catalogue references found; launcher uses shell prompts. |
| `whois` | system | Retain; source references | reference/Osint_enum.sh:147, reference/Osint_enum.sh:149, reference/Osint_enum.sh:150 (+1 more; see JSON) |
| `wpscan` | system | Retain; source references | cstk.sh:1213, reference/Osint_enum.sh:557, reference/Osint_enum.sh:558 (+1 more; see JSON) |
| `xxd` | system | Retain; source references | reference/Etc_gpg_enc_dec.sh:50, reference/Etc_gpg_enc_dec.sh:82 |
| `ldap-utils` | system | Retain; source references | reference/Osint_enum.sh:480, reference/Osint_enum.sh:481, reference/Osint_enum.sh:482 |
| `postgresql-client` | system | Retain; source references | reference/Osint_enum.sh:735, reference/Osint_enum.sh:737 |
| `default-mysql-client` | system | Retain; source references | cstk.sh:1213, reference/Etc_hash_idenify.py:32, reference/Etc_hash_idenify.py:82 (+16 more; see JSON) |
| `redis-tools` | system | Retain; source references | reference/Osint_enum.sh:752, reference/Osint_enum.sh:754 |
| `droopescan` | pipx | Retain; source references | reference/Osint_enum.sh:573, reference/Osint_enum.sh:574, reference/Osint_enum.sh:575 |
| `naminter` | pipx | Remove automatic install | No executable use found; username generation uses CSTK/Python directly. |
| `holehe` | pipx | Retain; source references | cstk.sh:1634, cstk.sh:1644, cstk.sh:1646 |
| `bloodhound-ce` | pipx | Remove automatic install | Collector only appears as optional guidance in the available enumeration source, not an invoked workflow. |
| `mongosh` | download-or-package | Retain; source references | reference/Osint_enum.sh:743, reference/Osint_enum.sh:745 |
| `nrich` | download-or-package | Retain; source references | cstk.sh:1218, reference/Osint_auto_vuln_finder.sh:23, reference/Osint_auto_vuln_finder.sh:32 (+2 more; see JSON) |
| `mimipenguin` | source | Retain; source references | cstk.sh:2183, cstk.sh:2184, cstk.sh:2192 (+4 more; see JSON) |
| `shc` | source-build | Retain; source references | cstk.sh:1789, cstk.sh:1813, cstk.sh:1861 (+29 more; see JSON) |
| `vulscan` | source | Remove automatic install | No runtime invocation found in reviewed CSTK launcher/tool sources; only installer/updater/cleanup references existed. |
| `katana` | Go-build | Remove automatic install | One optional depth-3 crawl beside GoSpider; automatic build/update already retired. |

## Known limitations and remaining checks

- `httpx-toolkit` installs `/usr/bin/httpx-toolkit` in the inspected Kali package, while available enumeration source checks `httpx`. Retained pending a separate runtime/source reconciliation; no compatibility wrapper is added here.
- Available enumeration source offers a `bloodhound-python` availability hint; that is not a justification for automatically installing the BloodHound server/app or a separate collector. Existing optional checks remain.
- Existing installations are not purged or modified. Older package and pipx ledgers remain readable for conservative uninstall; affected journals need reviewed baseline recovery before package removal.
- Build tools may also be dependencies of other retained packages. Removing a default does not guarantee the package will be absent from the final dependency closure.
- Downloaded source helpers shc, nrich, mongosh and MimiPenguin retain installer/runtime references; they were not executed by this audit.
- Package aliases, versions and dependency resolution remain distribution-specific.

## Compiled entries without an exact-name external source match

`Etc_cstk_ai`, `linux-386`, `linux-amd64`, `linux-arm64`, `mac-amd64`, `mac-arm64`, `msf_binary_weather`, `web_tls_security_assessment`, `windows-amd64.exe`, `windows-arm64.exe`

Reproduce with `python3 tools/audit_dependencies.py --reference /path/to/CSTK_bin_files`. Full reference locations and catalogue matches are in the companion JSON.
