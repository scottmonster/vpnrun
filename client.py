"""Unprivileged CLI; credentials never enter the client protocol."""
import argparse
import datetime
import json
import os
import signal
import socket
import sys

import protocol

SOCKET = '/run/inverse-split-tunnel/control.sock'


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


ACTIONS = {'run', 'status', 'servers', 'switch', 'stop', 'uninstall', 'update', 'upgrade'}


def parse_args(argv=None, control=False):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog='vpnctl' if control else 'vpnrun',
        description='Run CLI programs through Mullvad. Use -- COMMAND to disambiguate reserved command names.')
    if not control and argv and argv[0] not in ACTIONS and argv[0] not in {'-h', '--help', '--version'}:
        argv.insert(0, 'run')
    if argv and argv[0] == '--':
        argv.insert(0, 'run')
    parser.add_argument('--version', action='version', version='vpnrun 0.2.0')
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('status', help='show local configuration and background connectivity status')
    servers = commands.add_parser('servers', help='list active server hostnames')
    servers.add_argument('prefix', nargs='?', default='')
    switch = commands.add_parser('switch', help='select the shared tunnel server')
    switch.add_argument('server')
    commands.add_parser('stop', help='stop after all tunnel programs exit')
    run = commands.add_parser('run', help='launch a program inside the tunnel')
    run.add_argument('command', nargs=argparse.REMAINDER)
    commands.add_parser('uninstall', help='uninstall interactively (asks for sudo)')
    commands.add_parser('update', aliases=['upgrade'], help='install the latest GitHub master revision (asks for sudo)')
    args = parser.parse_args(argv)
    if args.action == 'run':
        args.command = args.command[1:] if args.command[:1] == ['--'] else args.command
        if not args.command:
            parser.error('an application command is required after --')
    return args


def main(run_only=False):
    args = parse_args(control=not run_only)
    code = '/usr/local/lib/inverse-split-tunnel'
    if args.action in {'update', 'upgrade'}:
        if os.environ.get('VPNRUN') == '1':
            sys.exit('run vpnrun update outside the protected tunnel')
        os.execv('/usr/bin/sudo', ['sudo', '--', '/usr/bin/python3', '-I', '-B', code + '/updater.py'])
    if args.action == 'uninstall':
        os.execv('/usr/bin/sudo', ['sudo', '--', '/bin/sh', code + '/uninstall'])
    request = {'action': args.action}
    fds = ()
    if args.action == 'run':
        command = args.command
        request.update(command=command, cwd=os.getcwd(), env=dict(os.environ))
        fds = (0, 1, 2)
    elif args.action == 'switch':
        request['server'] = args.server
    elif args.action == 'servers':
        request['prefix'] = args.prefix
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(180)
            connection.connect(SOCKET)
            protocol.send(connection, request, fds)
            response, extra = protocol.receive(connection)
            for fd in extra:
                os.close(fd)
            if not response['ok']:
                print(response['error'], file=sys.stderr)
                return 1
            if args.action == 'run':
                connection.settimeout(None)
                def forward(number, _):
                    try:
                        protocol.send(connection, {'signal': signal.Signals(number).name[3:]})
                    except OSError:
                        pass
                previous = {number: signal.signal(number, forward) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
                try:
                    response, extra = protocol.receive(connection)
                    for fd in extra:
                        os.close(fd)
                finally:
                    for number, handler in previous.items():
                        signal.signal(number, handler)
                if not response['ok']:
                    print(response['error'], file=sys.stderr)
                    return 1
                if response.get('diagnostic'):
                    print(response['diagnostic'], file=sys.stderr)
                code = response['exit_code']
                return code if code >= 0 else 128 - code
            result = response['result']
            if args.action == 'servers':
                print('\n'.join(result['servers']))
            else:
                print(json.dumps(result, indent=2))
            return 0
    except (OSError, EOFError, ValueError, KeyError) as exc:
        print(f'{timestamp()} ERROR control socket {SOCKET}: {type(exc).__name__}; check installation and service', file=sys.stderr)
        return 1
