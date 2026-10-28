#!/usr/bin/env python3
"""Explicit assessment utilities; no automatic execution or access installation."""
import argparse
import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

LIMIT = 1024 * 1024


def write_new(path, content):
    # Never truncate an existing file or follow a final output symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def read_input(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Input must be a regular file within the size limit')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Input exceeds the size limit')
        return data


def vm_info():
    signals = []
    for name in ('product_name', 'sys_vendor'):
        try:
            value = (Path('/sys/class/dmi/id') / name).read_text().strip()[:256]
            signals.append({'source': name, 'value': value})
        except OSError:
            signals.append({'source': name, 'status': 'unavailable'})
    try:
        cpu = Path('/proc/cpuinfo').read_text()[:2 * LIMIT]
        signals.append({'source': 'cpu_hypervisor_flag', 'present': any(
            line.startswith(('flags', 'Features')) and 'hypervisor' in line.split() for line in cpu.splitlines())})
    except OSError:
        pass
    command = shutil.which('systemd-detect-virt')
    if command:
        try:
            result = subprocess.run([command], capture_output=True, text=True, timeout=3)
            signals.append({'source': 'systemd-detect-virt', 'value': result.stdout.strip()[:256], 'status': result.returncode})
        except (OSError, subprocess.TimeoutExpired):
            signals.append({'source': 'systemd-detect-virt', 'status': 'unavailable'})
    print(json.dumps({'observations': signals, 'interpretation': 'Informational signals, not proof of physical hardware or a sandbox. No action changes based on the result.'}))


def wordlist(args):
    words = read_input(args.input).decode('utf-8').splitlines()
    if len(words) > 1000 or any(len(word) > 128 for word in words):
        raise ValueError('Use at most 1000 lines of at most 128 characters')
    result = set()
    for word in words:
        if not word:
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in word):
            raise ValueError('Control characters are unsupported')
        for variant in (word, word.lower(), word.upper(), word.capitalize()):
            result.add(variant)
            result.add(variant.translate(str.maketrans({'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'})))
            for suffix in args.suffix:
                if len(suffix) > 16 or '\n' in suffix or '\r' in suffix:
                    raise ValueError('Suffixes must be single-line strings of at most 16 characters')
                result.add(variant + suffix)
                if len(result) > 50000:
                    raise ValueError('Output exceeds 50000 variants; reduce input or suffixes')
    write_new(args.output, ('\n'.join(sorted(result)) + '\n').encode())
    print(json.dumps({'output': str(Path(args.output).absolute()), 'lines': len(result)}))


def encode(args):
    data = read_input(args.input, LIMIT if args.action == 'encode' else 2 * LIMIT + 1)
    if args.action == 'encode':
        output = base64.b64encode(data) if args.format == 'base64' else binascii.hexlify(data)
        output += b'\n'
    else:
        data = data.strip()
        output = base64.b64decode(data, validate=True) if args.format == 'base64' else binascii.unhexlify(data)
    if args.action == 'decode' and len(output) > LIMIT:
        raise ValueError('Decoded data exceeds 1 MiB')
    write_new(args.output, output)
    print('Wrote ' + str(Path(args.output).absolute()) + '; encoding is not encryption.')


def keys(args):
    command = shutil.which('ssh-keygen')
    if not command:
        raise ValueError('ssh-keygen is required')
    parent = Path(args.directory).absolute()
    parent.mkdir(mode=0o700)  # Requires a new private directory.
    try:
        key = parent / 'id_ed25519'
        # No passphrase appears in argv/environment: ssh-keygen prompts directly.
        result = subprocess.run([command, '-t', 'ed25519', '-f', str(key), '-C', 'CSTK assessment key'], timeout=120)
        if result.returncode:
            raise ValueError('ssh-keygen failed or was cancelled')
        key.chmod(0o600)
        (parent / 'id_ed25519.pub').chmod(0o644)
    except BaseException:
        shutil.rmtree(parent)
        raise
    print('Key pair: ' + str(key) + ' (no authorized_keys file was modified)')


def sweep(args):
    if '/' not in args.network:
        raise ValueError('Supply an explicit IPv4 CIDR')
    network = ipaddress.ip_network(args.network, strict=True)
    if network.version != 4 or network.num_addresses > 256 or network.is_multicast or network.is_unspecified or network.network_address.is_reserved:
        raise ValueError('Use a unicast IPv4 CIDR of /24 or smaller')
    ping = shutil.which('ping')
    if not ping:
        raise ValueError('ping is required; its local capabilities determine whether ICMP is permitted')
    output = None
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        output = os.fdopen(fd, 'w')
    try:
        for host in network.hosts():
            try:
                result = subprocess.run([ping, '-n', '-c', '1', '-W', '1', str(host)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=2)
                state = 'reply' if result.returncode == 0 else 'no-reply' if result.returncode == 1 else 'error'
            except subprocess.TimeoutExpired:
                state = 'timeout'
            line = json.dumps({'address': str(host), 'status': state})
            print(line, flush=True)
            if output:
                output.write(line + '\n'); output.flush()
    finally:
        if output:
            output.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('vm')
    words = commands.add_parser('wordlist')
    words.add_argument('--input', required=True); words.add_argument('--output', required=True)
    words.add_argument('--suffix', action='append', default=[])
    coding = commands.add_parser('encoding')
    coding.add_argument('action', choices=['encode', 'decode'])
    coding.add_argument('--format', choices=['base64', 'hex'], required=True)
    coding.add_argument('--input', required=True); coding.add_argument('--output', required=True)
    keygen = commands.add_parser('keys'); keygen.add_argument('--directory', required=True)
    ping = commands.add_parser('sweep'); ping.add_argument('--network', required=True); ping.add_argument('--output')
    args = parser.parse_args()
    try:
        if args.command == 'vm': vm_info()
        elif args.command == 'wordlist': wordlist(args)
        elif args.command == 'encoding': encode(args)
        elif args.command == 'keys': keys(args)
        elif args.command == 'sweep': sweep(args)
    except (OSError, ValueError, binascii.Error, UnicodeError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, str(exc) + '\n')
    except KeyboardInterrupt:
        parser.exit(130, 'Interrupted.\n')


if __name__ == '__main__':
    main()
