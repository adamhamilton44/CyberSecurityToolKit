
# SecurityChecks
This folder has 2 checksum files.
the main cstk.sh bash script checks the authenticity of the other files in the CyberSecurityToolKit/folders.
It will then compare file checksums with the checksums in the SecurityChecks/Other/SecurityChecks folder.

If the hashes do not align the script will tell you that some files may have been compromised.
If when running the main script 'cstk' should the hashes not align the script will delete this entire program.
