#!/usr/bin/python3
"""Executed only after namespace entry and setpriv have dropped root."""
import json
import datetime
import os
from pathlib import Path
import pwd
import shutil
import sys


def resolve_command(command, path):
    """Keep PATH precedence; treat an unknown bare name as a local path."""
    if '/' not in command[0] and shutil.which(command[0], path=path) is None:
        return ['./' + command[0], *command[1:]]
    return command


def sandbox(user, cwd, command, dns=None):
    dns = dns or Path('/etc/netns/ist-managed')
    resolver = Path('/etc/resolv.conf').resolve()
    nsswitch = Path('/etc/nsswitch.conf').resolve()
    return ['/usr/bin/bwrap', '--unshare-user', '--disable-userns', '--unshare-pid',
            '--unshare-ipc', '--unshare-uts', '--die-with-parent', '--cap-drop', 'ALL',
            '--ro-bind', '/', '/', '--bind', user.pw_dir, user.pw_dir,
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/run', '--tmpfs', '/tmp',
            '--dir', f'/run/user/{user.pw_uid}', '--dir', str(resolver.parent),
            '--ro-bind', str(dns / 'resolv.conf'), str(resolver),
            '--ro-bind', str(dns / 'nsswitch.conf'), str(nsswitch),
            '--chdir', cwd, '--', *command]


def main():
    if os.geteuid() == 0:
        raise RuntimeError('launch.py: root payload launch refused')
    request_fd, ready_fd = map(int, sys.argv[1:])
    with os.fdopen(request_fd) as source:
        request = json.load(source)
    user = pwd.getpwuid(os.getuid())
    env = request['env']
    for key in list(env):
        if key.lower().endswith('_proxy') or key.startswith('SUDO_') or key in {
            'DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS', 'SSH_AUTH_SOCK',
            'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR'}:
            del env[key]
    env.update(VPNRUN='1', HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name,
               XDG_RUNTIME_DIR=f'/run/user/{user.pw_uid}')
    env.setdefault('PATH', '/usr/local/bin:/usr/bin:/bin')
    os.chdir(request['cwd'])
    command = resolve_command(request['command'], env['PATH'])
    os.write(ready_fd, b'1')
    os.close(ready_fd)
    os.execve('/usr/bin/bwrap', sandbox(user, request['cwd'], command), env)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(f'{datetime.datetime.now(datetime.timezone.utc).isoformat()} ERROR namespace ist-managed: payload launcher failed after privilege drop; check the terminal and service journal', file=sys.stderr)
        sys.exit(126)
