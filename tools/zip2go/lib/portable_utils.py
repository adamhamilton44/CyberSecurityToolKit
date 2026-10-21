#!/usr/bin/env python3
"""Local example user agents and constrained archive inspection/extraction."""
import argparse
import contextlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import signal
import stat
import tarfile
import tempfile
import zipfile
import zlib

MAX_FILES = 1000
MAX_BYTES = 100 * 1024 * 1024
AGENTS = (
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'CSTK-Zip2Go/1.0 (assessment; Linux)',
)


def validate(name):
    parts = PurePosixPath(name)
    if not name or '\\' in name or parts.is_absolute() or '..' in parts.parts or ':' in name:
        raise ValueError('Unsafe archive member path')
    if any(ord(c) < 32 or ord(c) == 127 for c in name) or not parts.parts or len(parts.parts) > 20:
        raise ValueError('Unsupported archive member path')
    return parts


@contextlib.contextmanager
def archive_members(filename):
    with contextlib.ExitStack() as stack:
        if zipfile.is_zipfile(filename):
            archive = stack.enter_context(zipfile.ZipFile(filename))
            entries = archive.infolist()
            def info(entry):
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or entry.flag_bits & 1:
                    raise ValueError('Links and encrypted members are unsupported')
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('Special files are unsupported')
                return entry.filename, entry.file_size, entry.is_dir(), lambda: archive.open(entry)
        else:
            archive = stack.enter_context(tarfile.open(filename, 'r:*'))
            entries = []
            for entry in archive:
                entries.append(entry)
                if len(entries) > MAX_FILES:
                    raise ValueError('Archive exceeds 1000 members')
            def info(entry):
                if not (entry.isfile() or entry.isdir()):
                    raise ValueError('Links and special files are unsupported')
                return entry.name, entry.size, entry.isdir(), lambda: archive.extractfile(entry)
        if len(entries) > MAX_FILES:
            raise ValueError('Archive exceeds 1000 members')
        total = 0
        names = set()
        members = []
        for entry in entries:
            name, size, directory, opener = info(entry)
            if directory and name in (".", "./"):
                continue
            relative = validate(name)
            normalized = relative.as_posix()
            if normalized in names:
                raise ValueError('Duplicate archive paths are unsupported')
            names.add(normalized)
            if size < 0:
                raise ValueError('Invalid member size')
            total += size
            if total > MAX_BYTES:
                raise ValueError('Archive exceeds 100 MiB uncompressed')
            members.append((relative, size, directory, opener))
        yield members


def unpack(source, destination):
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination must not exist; no overwrites are allowed')
    if not destination.parent.is_dir():
        raise ValueError('Destination parent directory must exist')
    # Validate the entire archive before creating output. Work in a private sibling.
    with archive_members(source) as members:
        staging = Path(tempfile.mkdtemp(prefix='cstk-extract-', dir=destination.parent))
        try:
            total = 0
            for relative, expected, directory, opener in members:
                output = staging.joinpath(*relative.parts)
                if directory:
                    output.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                size = 0
                with opener() as reader, output.open('xb') as writer:
                    while True:
                        chunk = reader.read(65536)
                        if not chunk:
                            break
                        total += len(chunk); size += len(chunk)
                        if total > MAX_BYTES or size > expected:
                            raise ValueError('Decompressed data exceeds declared limits')
                        writer.write(chunk)
                if size != expected:
                    raise ValueError('Truncated archive member')
                output.chmod(0o600)
            # Create a destination only after successful validation/extraction.
            # Reserve a fresh destination without replacing existing content.
            destination.mkdir(mode=0o700)
            try:
                for child in staging.iterdir():
                    child.rename(destination / child.name)
            except BaseException:
                shutil.rmtree(destination)
                raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    print('Extracted to ' + str(destination))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    agents = commands.add_parser('user-agent')
    agents.add_argument('--count', type=int, default=1)
    archives = commands.add_parser('archive')
    actions = archives.add_subparsers(dest='action', required=True)
    listing = actions.add_parser('list'); listing.add_argument('source')
    extracting = actions.add_parser('extract'); extracting.add_argument('source'); extracting.add_argument('destination')
    args = parser.parse_args()
    if args.command == 'user-agent':
        if not 1 <= args.count <= 20:
            parser.error('--count must be in 1..20')
        for _ in range(args.count):
            print(secrets.choice(AGENTS))
        return
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if Path(args.source).stat().st_size > MAX_BYTES:
            raise ValueError('Input archive exceeds 100 MiB')
        if args.action == 'list':
            with archive_members(args.source) as members:
                for name, size, directory, _ in members:
                    print(json.dumps({'path': name.as_posix(), 'bytes': size, 'directory': directory}))
        else:
            unpack(args.source, args.destination)
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, zlib.error, EOFError) as exc:
        parser.exit(1, 'Archive operation failed: ' + str(exc) + '\n')
    except KeyboardInterrupt:
        parser.exit(130, 'Archive operation interrupted.\n')


if __name__ == '__main__':
    main()
