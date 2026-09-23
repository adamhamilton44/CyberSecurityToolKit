# Denial-of-Service Lab Assets

This directory contains resource-exhaustion test assets used by CSTK's payload
menu.

> [!CAUTION]
> These assets can exhaust memory, storage, CPU, or application resources. Use
> them only in a disposable, isolated lab that you own or are explicitly
> authorized to test. Never use them on production, shared, or third-party
> systems.

## Files

| File | Purpose |
| --- | --- |
| `PicBomb` | Encrypted image-bomb resource consumed by the CSTK workflow |
| `ZipBomb.zip` | Git LFS-managed archive used by the CSTK Zip Bomb workflow |

The assets are not intended for manual extraction or direct execution. Start
the relevant workflow through `sudo cstk` so CSTK can apply its normal prompts,
output paths, and integrity checks.

## Lab preparation

- Use a disposable virtual machine with a recent snapshot.
- Keep the test network isolated.
- Set strict storage, memory, and CPU limits.
- Keep important data and mounted host directories outside the test machine.
- Monitor resource use and be prepared to stop or revert the virtual machine.
- Confirm written authorization before testing any service or system.

Git LFS must be installed before cloning or pulling this repository; otherwise,
`ZipBomb.zip` may appear as a small pointer file instead of the required
archive.
