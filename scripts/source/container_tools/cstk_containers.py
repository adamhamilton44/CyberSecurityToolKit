#!/usr/bin/env python3
"""CSTK's local Web Check lifecycle and read-only Trivy project adapter."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import urllib.request

WEB_IMAGE = 'lissy93/web-check:latest'
TRIVY_IMAGE = 'aquasec/trivy:latest'
NAME = 'cstk-web-check'
LABEL = 'io.cstk.component=web-check'
URL = 'http://127.0.0.1:3000'


def docker(*args, capture=False, check=True):
    return subprocess.run(['docker', *args], check=check, text=True,
                          capture_output=capture)


def require_docker():
    if not shutil.which('docker'):
        raise RuntimeError('Docker is missing. Install docker.io, then start Docker (sudo systemctl start docker).')
    if docker('info', capture=True, check=False).returncode:
        raise RuntimeError('Docker is unavailable. Start its daemon and run CSTK with sudo or Docker access.')


def invoking_user():
    name = os.environ.get('SUDO_USER') if os.geteuid() == 0 else None
    return pwd.getpwnam(name) if name and name != 'root' else pwd.getpwuid(os.getuid())


def open_browser():
    account = invoking_user()
    if account.pw_uid == 0:
        print(f'Open {URL} in your desktop user browser (no non-root invoking user found).')
        return
    if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        print(f'No desktop session detected. Open {URL} manually.')
        return
    browser = next((shutil.which(x) for x in ('xdg-open', 'firefox', 'google-chrome', 'chromium') if shutil.which(x)), None)
    if not browser:
        print(f'No browser launcher found. Open {URL} manually.')
        return
    env = {k: v for k, v in os.environ.items() if k in
           ('PATH', 'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS', 'LANG')}
    env.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name,
               XDG_RUNTIME_DIR=f'/run/user/{account.pw_uid}')
    command = [browser, URL]
    if os.geteuid() == 0:
        command = ['runuser', '-u', account.pw_name, '--', 'env', *[f'{k}={v}' for k,v in env.items()], *command]
    # Browser launch must not hold the CLI open or inherit its privileged descriptors.
    subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    print(f'Opening {URL} as {account.pw_name}. If no window appears, open the URL manually.')


def inspect_web():
    result = docker('container', 'inspect', NAME, capture=True, check=False)
    if result.returncode:
        # Distinguish an absent container from daemon/permission errors.
        ids = docker('container', 'ls', '-a', '--filter', f'name=^/{NAME}$', '-q', capture=True)
        if ids.stdout.strip():
            raise RuntimeError('Unable to inspect the existing Web Check container.')
        return None
    item = json.loads(result.stdout)[0]
    labels = item['Config'].get('Labels') or {}
    ports = item['HostConfig'].get('PortBindings') or {}
    if (labels.get('io.cstk.component') != 'web-check' or
        ports != {'3000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '3000'}]}):
        raise RuntimeError(f'{NAME} already exists with a different owner/configuration; choose another name or remove it manually.')
    return item


def web_check(action):
    item = inspect_web()
    if action == 'status':
        print(f'{NAME}: ' + (item['State']['Status'] if item else 'not created'))
        return 0
    if action == 'stop':
        if item and item['State']['Running']:
            docker('stop', NAME)
        else:
            print('Web Check is already stopped.')
        return 0
    if item is None:
        docker('run', '-d', '--name', NAME, '--label', LABEL, '--restart', 'no',
               '-p', '127.0.0.1:3000:3000', WEB_IMAGE)
    elif not item['State']['Running']:
        docker('start', NAME)
    # Do not open a browser before the service is reachable. Ignore proxy env.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(45):
        try:
            with opener.open(URL, timeout=2) as response:
                if response.status < 400:
                    open_browser()
                    print('Stop later with: cstk -Dc stop (standalone lab session).')
                    return 0
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise RuntimeError(f'Web Check did not become ready. Inspect: docker logs {NAME}. Container left available for diagnosis.')


def project_audit(directory):
    account = invoking_user()
    target = Path(directory).expanduser().resolve(strict=True)
    if not target.is_dir() or ',' in str(target):
        raise ValueError('Select a project directory without commas (Docker mount syntax).')
    # Check access as the operator, not the privileged CSTK launcher.
    if os.geteuid() == 0 and account.pw_uid != 0:
        subprocess.run(['runuser', '-u', account.pw_name, '--', 'test', '-r', str(target)], check=True)
        subprocess.run(['runuser', '-u', account.pw_name, '--', 'test', '-x', str(target)], check=True)
    print('Scanning dependencies, secrets, IaC, and licenses; target mounted read-only. Database downloads require internet.')
    # Never mount the Docker socket, user HOME, or host root implicitly.
    # Config/ignore files from an untrusted project must not suppress findings.
    command = ['run', '--rm', '--user', f'{account.pw_uid}:{account.pw_gid}',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--env', 'TRIVY_CACHE_DIR=/tmp/trivy', '--workdir', '/tmp',
               '--mount', f'type=bind,src={target},dst=/project,readonly', TRIVY_IMAGE,
               'fs', '--config', '/dev/null', '--ignorefile', '/dev/null',
               '--scanners', 'vuln,secret,misconfig,license', '--exit-code', '1', '/project']
    return docker(*command, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='tool', required=True)
    web = commands.add_parser('web-check')
    web.add_argument('action', choices=('start', 'stop', 'status'), default='start', nargs='?')
    project = commands.add_parser('project')
    project.add_argument('directory')
    commands.add_parser('prefetch', help='Download optional images without starting containers')
    args = parser.parse_args()
    try:
        require_docker()
        if args.tool == 'prefetch':
            docker('pull', WEB_IMAGE)
            docker('pull', TRIVY_IMAGE)
            return 0
        return web_check(args.action) if args.tool == 'web-check' else project_audit(args.directory)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'CSTK container tool: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
