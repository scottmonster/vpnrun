#!/usr/bin/python3
"""Install a SHA-pinned snapshot from the fixed upstream repository."""
import argparse
import io
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REPOSITORY = 'scottmonster/vpnrun'
BRANCH = 'master'
MAX_ARCHIVE = 8 * 1024 * 1024
FILES = ('runtime.py', 'protocol.py', 'service.py', 'launch.py', 'client.py', 'installer.py',
         'install', 'uninstall', 'vpnctl', 'vpnrun', 'README.md', 'LICENSE', 'TESTING.md', 'CHANGELOG.md',
         'updater.py', 'probe.py', 'watchdog.py')
UNITS = ('inverse-split-tunnel.socket', 'inverse-split-tunnel@.service', 'inverse-split-tunnel-watchdog.service')
REQUIRED = set(FILES) | {'systemd/' + name for name in UNITS}


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'vpnrun-updater', 'Accept': 'application/vnd.github+json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=30) as response:
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError('download exceeds size limit')
    return data


def unpack(data, destination):
    """Extract allowlisted regular files only; reject links, duplicates, traversal."""
    found = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        total = 0
        for count, member in enumerate(archive, 1):
            total += member.size
            if count > 1000 or total > MAX_ARCHIVE:
                raise ValueError('archive exceeds unpacking limits')
            parts = member.name.split('/')
            if any(part in {'.', '..'} for part in parts) or member.name.startswith('/'):
                raise ValueError('unsafe archive path')
            relative = '/'.join(parts[1:])
            if relative not in REQUIRED:
                continue
            if not member.isfile() or member.size > 1024 * 1024 or relative in found:
                raise ValueError('unsafe or duplicate package file')
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
            path.chmod(0o600)
            found.add(relative)
    if found != REQUIRED:
        raise ValueError('upstream package incomplete; code may not have been published yet')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true', help='bootstrap a new installation')
    args = parser.parse_args(argv)
    os.umask(0o077)
    installation = Path('/var/lib/inverse-split-tunnel/installation.json')
    user = None
    current = None
    if not args.install:
        if os.geteuid() != 0:
            sys.exit('use vpnrun update (requests sudo)')
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import runtime as r
        info = r.read_json(installation)
        user = info['user']
        if pwd.getpwnam(user).pw_uid != info['uid']:
            sys.exit('installed user identity changed; reinstall explicitly')
        current = r.read_json(r.CODE / 'manifest.json').get('revision')
    elif os.geteuid() != 0:
        user = pwd.getpwuid(os.getuid()).pw_name
    else:
        uid = int(os.environ.get('SUDO_UID', '0'))
        if uid:
            user = pwd.getpwuid(uid).pw_name
    try:
        commit = json.loads(download(f'https://api.github.com/repos/{REPOSITORY}/commits/{BRANCH}'))['sha']
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('invalid upstream revision')
        if current == commit:
            print('vpnrun is already up to date (' + commit[:12] + ').')
            return 0
        with tempfile.TemporaryDirectory(prefix='vpnrun-update-') as directory:
            source = Path(directory)
            unpack(download(f'https://codeload.github.com/{REPOSITORY}/tar.gz/{commit}'), source)
            (source / 'revision.json').write_text(json.dumps({'revision': commit}))
            command = ['/bin/sh', str(source / 'install')]
            if user:
                command += ['--user', user]
            print('Installing vpnrun revision ' + commit[:12], flush=True)
            return subprocess.run(command, check=False).returncode
    except Exception:
        # Never dump HTTP bodies or credentials. Failure leaves installation intact.
        print('vpnrun update failed: could not fetch/validate/install the upstream package; '
              'check connectivity and that the code is published on master.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
