#!/usr/bin/python3
"""One root-owned systemd socket service instance per authenticated request."""
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol
import runtime as r


def authorize(connection):
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    config = r.read_json(r.DATA / 'installation.json')
    if uid == 0 or uid != config['uid']:
        raise r.Failure(f'control socket {r.SOCKET}: UID {uid} is not the installed user')
    user = pwd.getpwuid(uid)
    if user.pw_gid != config['gid'] or user.pw_name != config['user']:
        raise r.Failure(f'control socket {r.SOCKET}: installed user identity changed; reinstall for UID {uid}')
    return user


def validate_launch(request, fds):
    command, cwd, env = request.get('command'), request.get('cwd'), request.get('env')
    if len(fds) != 3:
        raise r.Failure(f'control socket {r.SOCKET}: launch requires exactly three stdio descriptors')
    if not isinstance(command, list) or not command or not all(isinstance(v, str) and '\0' not in v for v in command):
        raise r.Failure(f'control socket {r.SOCKET}: invalid application command; arguments excluded')
    if not isinstance(cwd, str) or not cwd.startswith('/') or '\0' in cwd:
        raise r.Failure(f'control socket {r.SOCKET}: expected an absolute application directory; contents excluded')
    if not isinstance(env, dict) or not all(isinstance(k, str) and k and '=' not in k and '\0' not in k and isinstance(v, str) and '\0' not in v for k, v in env.items()):
        raise r.Failure(f'control socket {r.SOCKET}: invalid application environment; contents excluded')


def terminate(process, number=signal.SIGTERM):
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass


def run_program(connection, request, fds, user):
    validate_launch(request, fds)
    with r.launch_ready():
        request_file = tempfile.TemporaryFile(dir=r.RUN, prefix='launch-')
        payload = request_file.fileno()
        read_ready, write_ready = os.pipe2(os.O_CLOEXEC)
        process = None
        try:
            os.write(payload, json.dumps({k: request[k] for k in ('command', 'cwd', 'env')}).encode())
            os.lseek(payload, 0, os.SEEK_SET)
            args = ['ip', 'netns', 'exec', r.NS, 'setpriv', f'--reuid={user.pw_uid}',
                    f'--regid={user.pw_gid}', '--clear-groups', '--no-new-privs',
                    '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    '/usr/bin/python3', '-I', str(r.CODE / 'launch.py'), str(payload), str(write_ready)]
            process = subprocess.Popen(args, stdin=fds[0], stdout=fds[1], stderr=fds[2],
                env={'PATH': r.PATH, 'LANG': 'C.UTF-8'}, pass_fds=(payload, write_ready), start_new_session=True)
            os.close(write_ready)
            write_ready = None
            readable, _, _ = select.select([read_ready], [], [], 12)
            if not readable or os.read(read_ready, 1) != b'1':
                terminate(process, signal.SIGKILL)
                process.wait()
                raise r.Failure(f'namespace {r.NS}: payload failed to enter namespace and drop privileges; launch refused')
        except BaseException:
            if process is not None and process.poll() is None:
                terminate(process, signal.SIGKILL)
                process.wait()
            raise
        finally:
            request_file.close()
            os.close(read_ready)
            if write_ready is not None:
                os.close(write_ready)
    try:
        protocol.send(connection, {'ok': True, 'started': True})
        connection.settimeout(10)
        while process.poll() is None:
            readable, _, _ = select.select([connection], [], [], 0.2)
            if readable:
                message, extra = protocol.receive(connection)
                for fd in extra:
                    os.close(fd)
                if message.get('signal') not in ('INT', 'TERM', 'HUP'):
                    raise r.Failure(f'control socket {r.SOCKET}: invalid payload signal')
                terminate(process, getattr(signal, 'SIG' + message['signal']))
        code = process.wait()
        if code:
            name = Path(request['command'][0]).name
            resource = name if re.fullmatch(r'[a-zA-Z0-9_.+-]{1,128}', name) else '(nonstandard executable name excluded)'
            diagnostic = r.error_message('application', r.Failure(f'application {resource} in namespace {r.NS} exited with status {code}; arguments and stderr excluded'))
            print(diagnostic, file=sys.stderr, flush=True)
            protocol.send(connection, {'ok': True, 'exit_code': code, 'diagnostic': diagnostic})
        else:
            protocol.send(connection, {'ok': True, 'exit_code': 0})
    finally:
        if process.poll() is None:
            terminate(process)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                terminate(process, signal.SIGKILL)
                process.wait()


def serve(connection):
    fds = []
    operation = 'request'
    try:
        connection.settimeout(10)
        user = authorize(connection)
        request, fds = protocol.receive(connection)
        if not isinstance(request, dict):
            raise r.Failure(f'control socket {r.SOCKET}: expected request object')
        action = request.get('action')
        if action not in {'run', 'status', 'servers', 'switch', 'stop'}:
            raise r.Failure(f'control socket {r.SOCKET}: unsupported action')
        operation = action
        if action == 'run':
            return run_program(connection, request, fds, user)
        if fds:
            raise r.Failure(f'control socket {r.SOCKET}: descriptors only accepted for application launch')
        if action == 'status':
            result = r.status()
        elif action == 'switch':
            result = r.switch(request.get('server'))
        elif action == 'stop':
            result = r.stop()
        else:
            prefix = request.get('prefix', '')
            if not isinstance(prefix, str) or len(prefix) > 100:
                raise r.Failure('command vpnctl servers: invalid prefix')
            result = {'servers': [row['hostname'] for row in r.Mullvad().relays() if row['hostname'].startswith(prefix)]}
        protocol.send(connection, {'ok': True, 'result': result})
    except Exception as exc:
        diagnostic = r.error_message(operation, exc)
        print(diagnostic, file=sys.stderr, flush=True)
        try:
            protocol.send(connection, {'ok': False, 'error': diagnostic})
        except OSError:
            pass
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('service.py must be started by its root systemd socket service')
    os.umask(0o077)
    with socket.socket(fileno=os.dup(0)) as connection:
        serve(connection)
