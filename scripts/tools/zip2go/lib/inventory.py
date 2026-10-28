#!/usr/bin/env python3
"""Bounded metadata inventory of one explicitly chosen directory."""
import json
import os
from pathlib import Path
import stat
import sys

if len(sys.argv) not in (2, 3) or len(sys.argv) == 3 and sys.argv[2] != '--interesting':
    raise SystemExit('Supply one directory and optional --interesting.')
interesting = len(sys.argv) == 3
selected = 0
root = Path(sys.argv[1]).absolute()
try:
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError:
    raise SystemExit('Select a readable real directory, not a symlink.')
queue = [(fd, '', 0)]
count = 0
try:
    while queue and count < 200:
        directory, relative, depth = queue.pop(0)
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if count >= 200:
                        break
                    count += 1
                    name = relative + entry.name
                    try:
                        info = entry.stat(follow_symlinks=False)
                        include = (not interesting or stat.S_ISDIR(info.st_mode) or
                            Path(entry.name).suffix.lower() in ('.conf', '.cfg', '.ini', '.service', '.timer', '.sh', '.py', '.yaml', '.yml', '.json'))
                        if include:
                            selected += 1
                            print(json.dumps({'path': name, 'mode': stat.filemode(info.st_mode),
                                'uid': info.st_uid, 'gid': info.st_gid, 'bytes': info.st_size}, ensure_ascii=True))
                        if depth < 1 and stat.S_ISDIR(info.st_mode):
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                            queue.append((child, name + '/', depth + 1))
                    except OSError as exc:
                        print(json.dumps({'path': name, 'error': exc.strerror}))
        except OSError as exc:
            print(json.dumps({'directory': relative, 'error': exc.strerror}))
        finally:
            os.close(directory)
    print(json.dumps({'entries': count, 'selected': selected, 'limit': 200, 'depth': 2,
                      'truncated': bool(queue) or count >= 200}))
finally:
    for fd, _, _ in queue:
        os.close(fd)
