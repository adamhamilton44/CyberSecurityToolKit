#!/usr/bin/env python3
"""Maintainer-only build: python3 tools/build_provisioner.py PRIVATE_KEY_FILE.

The distributed binaries contain recoverable key material. Masking deters casual
inspection; it does not provide confidentiality against the machine's owner.
Generated sources live only in a private temporary directory.
"""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = r'''
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
static volatile unsigned char a[] = {MASK};
static volatile unsigned char b[] = {DATA};
int main(int argc, char **argv) {
    struct stat st;
    if (argc != 2) return 1;
    umask(077);
    int dir = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 2;
    if (fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 077)) {
        close(dir); return 3;
    }
    int fd = openat(dir, "lib_decryption.key", O_WRONLY | O_CREAT | O_EXCL |
                    O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { close(dir); return 4; }
    int failed = 0;
    for (size_t i = 0; i < sizeof(a); i++) {
        unsigned char c = a[i] ^ b[i];
        ssize_t n;
        do { n = write(fd, &c, 1); } while (n < 0 && errno == EINTR);
        c = 0;
        if (n != 1) { failed = 1; break; }
    }
    if (fsync(fd)) failed = 1;
    if (close(fd)) failed = 1;
    if (failed) unlinkat(dir, "lib_decryption.key", 0);
    close(dir);
    return failed ? 5 : 0;
}
'''

def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: build_provisioner.py PRIVATE_KEY_FILE')
    key_path = Path(sys.argv[1])
    if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
        raise SystemExit('Key must be a private regular file (mode 600).')
    key = key_path.read_bytes()
    if not key or b'\x00' in key:
        raise SystemExit('Invalid key file.')
    for probe in (ROOT / 'scripts/lib').glob('*.enc'):
        result = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-salt',
                                 '-pbkdf2', '-in', str(probe), '-out', os.devnull,
                                 '-pass', 'file:' + str(key_path)], capture_output=True)
        if result.returncode:
            raise SystemExit('Key verification failed; no binaries built.')
    mask = secrets.token_bytes(len(key))
    source = TEMPLATE.replace('MASK', ','.join(map(str, mask))).replace(
        'DATA', ','.join(str(x ^ y) for x, y in zip(key, mask)))
    output = ROOT / 'scripts/provision'
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cstk-build-') as tmp:
        src = Path(tmp) / 'provision.c'
        src.write_text(source)
        src.chmod(0o600)
        for arch, compiler in [('x86_64', 'musl-gcc'), ('aarch64', 'aarch64-linux-gnu-gcc')]:
            target = Path(tmp) / arch
            subprocess.run([compiler, '-static', '-Os', '-s', '-Wall', '-Wextra',
                            '-Werror', '-Wl,-z,noexecstack', str(src), '-o', str(target)], check=True)
            if key.rstrip(b'\n') in target.read_bytes():
                raise SystemExit('Unexpected plaintext key in binary.')
            destination = output / ('cstk-provision-' + arch)
            destination.write_bytes(target.read_bytes())
            destination.chmod(0o700)
    print('Built Linux x86_64 and aarch64 provisioners; all encrypted resources verified.')

if __name__ == '__main__':
    main()
