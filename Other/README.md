
# SecurityChecks
This folder has 2 checksum files. sha256.checksum and sha256.checksum2
the main script cstk.sh will check the authenticity of the other files in the CyberSecurityToolKit/folders.
It will then compare file hashes with the checksums in the SecurityChecks/Other/SecurityChecks folder.

If the hashes do not match the script will tell you that some files may have been compromised.
If when running the main script 'cstk' should the hashes not align the script will delete this entire program.
