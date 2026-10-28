#!/usr/bin/env python3
"""Explicit, bounded HTTP downloads of individually selected regular files."""
import argparse
import ipaddress
import os
from pathlib import Path
import stat
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote, unquote, urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', action='append', required=True, help='One approved regular file; repeat to add files.')
    parser.add_argument('--bind', default='127.0.0.1', help='Numeric local IPv4 address (default: loopback).')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--duration', type=int, default=300, help='Lifetime in seconds, maximum 3600.')
    parser.add_argument('--max-downloads', type=int, default=20, help='Successful GET/HEAD requests before exit, maximum 100.')
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.bind)
    except ValueError:
        parser.error('--bind must be a numeric local IPv4 address')
    if address.version != 4 or not 1024 <= args.port <= 65535:
        parser.error('Use IPv4 and an unprivileged port in 1024..65535')
    if not 1 <= args.duration <= 3600 or not 1 <= args.max_downloads <= 100 or len(args.file) > 20:
        parser.error('Use duration 1..3600, max-downloads 1..100, and no more than 20 files')
    files = {}
    server = None
    lifetime_timer = None
    active_connection = None
    expired = threading.Event()
    try:
        for value in args.file:
            path = Path(value).absolute()
            if any(ord(character) < 32 or ord(character) == 127 for character in path.name):
                parser.error('Selected basenames must not contain control characters')
            if path.name in files:
                parser.error('Selected files must have unique basenames')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 100 * 1024 * 1024:
                os.close(fd)
                parser.error('Only regular files up to 100 MiB each may be selected')
            files[path.name] = (fd, info.st_size)
        completed = 0

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'
            server_version = 'CSTK-FileTransfer/1'
            sys_version = ''

            def setup(self):
                nonlocal active_connection
                super().setup()
                active_connection = self.connection
                self.connection.settimeout(5)
                if expired.is_set():
                    self.connection.shutdown(socket.SHUT_RDWR)

            def finish(self):
                nonlocal active_connection
                try:
                    super().finish()
                finally:
                    if active_connection is self.connection:
                        active_connection = None

            def log_message(self, format, *arguments):
                # Do not log arbitrary peer-supplied paths or header values.
                print('HTTP request handled', flush=True)

            def do_HEAD(self):
                self.download(head=True)

            def do_GET(self):
                self.download(head=False)

            def download(self, head=False):
                nonlocal completed
                try:
                    url = urlsplit(self.path)
                    name = unquote(url.path, errors='strict')
                except (ValueError, UnicodeError):
                    self.send_error(400); return
                if url.query or url.fragment or url.netloc or not name.startswith('/') or '/' in name[1:]:
                    self.send_error(404); return
                name = name[1:]
                if name not in files:
                    self.send_error(404); return
                fd, size = files[name]
                completed += 1
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(size))
                self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(name, safe=''))
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                if not head:
                    offset = 0
                    try:
                        while offset < size:
                            data = os.pread(fd, min(65536, size - offset), offset)
                            if not data:
                                break
                            self.wfile.write(data)
                            offset += len(data)
                    except (OSError, TimeoutError):
                        pass

        server = HTTPServer((str(address), args.port), Handler)
        server.timeout = 0.5
        print('Plaintext HTTP; no authentication or encryption. Only selected files are exposed.', flush=True)
        print(f'Listening on {address}:{args.port}; duration={args.duration}s, request limit={args.max_downloads}', flush=True)
        for name in files:
            print(f'Download: http://{address}:{args.port}/{quote(name, safe="")}', flush=True)
        def expire():
            expired.set()
            connection = active_connection
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        lifetime_timer = threading.Timer(args.duration, expire)
        lifetime_timer.daemon = True
        lifetime_timer.start()
        while not expired.is_set() and completed < args.max_downloads:
            server.handle_request()
    except KeyboardInterrupt:
        print('Stopped.', flush=True)
    except OSError as exc:
        parser.exit(1, f'File service failed: {exc.strerror}\n')
    finally:
        if lifetime_timer is not None:
            lifetime_timer.cancel()
        if server is not None:
            server.server_close()
        for fd, _ in files.values():
            os.close(fd)


if __name__ == '__main__':
    main()
