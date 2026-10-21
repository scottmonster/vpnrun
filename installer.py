#!/usr/bin/python3
"""Interactive machine-local installation. Never imports prototype credentials."""
import argparse
import datetime
import contextlib
import ctypes
import fcntl
import hashlib
import getpass
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sys
sys.dont_write_bytecode = True
import tempfile
import urllib.parse
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime as r

SOURCE = Path(__file__).resolve().parent
from updater import FILES, UNITS
VERSION = 2


def note(message):
    print(f'{r.stamp()} {message}', flush=True)


def ask(prompt, default=False):
    # Buffered update mode (r+) requires seeking, which terminals cannot do.
    try:
        with open('/dev/tty', 'r') as reader, open('/dev/tty', 'w') as writer:
            writer.write(prompt + (' [Y/n]: ' if default else ' [y/N]: '))
            writer.flush()
            line = reader.readline()
    except OSError:
        raise r.Failure('terminal /dev/tty: cannot read confirmation; run install/uninstall in an interactive terminal') from None
    if not line:
        raise r.Failure('terminal /dev/tty: closed before confirmation; operation cancelled')
    answer = line.strip().lower()
    return answer in {'y', 'yes'} if answer else default


def prompt_account():
    try:
        with open('/dev/tty', 'w') as writer, warnings.catch_warnings():
            # Refuse getpass's echoed-input fallback instead of risking exposure.
            warnings.simplefilter('error', getpass.GetPassWarning)
            account = getpass.getpass('Mullvad account number (stored privately for this installation): ', stream=writer)
    except (OSError, EOFError, getpass.GetPassWarning):
        raise r.Failure('terminal /dev/tty: cannot read hidden account input; run install in an interactive terminal') from None
    account = account.replace(' ', '').strip()
    if not re.fullmatch(r'[0-9]{16}', account):
        raise r.Failure('installer account prompt at /dev/tty: expected 16 digits; input excluded')
    return account


def dependencies():
    if not Path('/run/systemd/system').is_dir():
        raise r.Failure('systemd at /run/systemd/system: a Linux host booted with systemd is required')
    required = ('ip', 'wg', 'nft', 'setpriv', 'bwrap', 'systemctl')
    if all(shutil.which(name, path=r.PATH) for name in required):
        return
    if shutil.which('apt-get', path=r.PATH):
        note('Installing OS packages with apt-get: iproute2 wireguard-tools nftables util-linux bubblewrap')
        r.command(['apt-get', 'update'], timeout=900)
        args = ['apt-get', 'install', '-y', 'iproute2', 'wireguard-tools', 'nftables', 'util-linux', 'bubblewrap']
    elif shutil.which('dnf', path=r.PATH):
        args = ['dnf', 'install', '-y', 'iproute', 'wireguard-tools', 'nftables', 'util-linux', 'bubblewrap']
    elif shutil.which('pacman', path=r.PATH):
        args = ['pacman', '-S', '--needed', '--noconfirm', 'iproute2', 'wireguard-tools', 'nftables', 'util-linux', 'bubblewrap']
    else:
        raise r.Failure('dependency installation: supported package manager not found (apt-get, dnf, pacman); required commands: ' + ', '.join(required))
    r.command(args, timeout=900)
    for name in required:
        if not shutil.which(name, path=r.PATH):
            raise r.Failure(f'command {name}: still unavailable after dependency installation')


def selected_user(name):
    try:
        user = pwd.getpwnam(name) if name else pwd.getpwuid(int(os.environ.get('SUDO_UID', '0') or '0'))
    except (KeyError, ValueError):
        raise r.Failure('installation user: unknown; invoke ./install as your normal user or supply --user USER') from None
    if user.pw_uid == 0 or not re.fullmatch(r'[a-zA-Z0-9_.-]+', user.pw_name):
        raise r.Failure('installation user: select a non-root login using --user USER')
    if not Path(user.pw_dir).is_dir():
        raise r.Failure(f'home directory {user.pw_dir} for user {user.pw_name}: absent')
    return user


def preflight(user):
    # Run real Bubblewrap after dropping root, without accessing any credentials.
    r.command(['setpriv', f'--reuid={user.pw_uid}', f'--regid={user.pw_gid}',
               '--clear-groups', '--no-new-privs', '--bounding-set=-all',
               '--inh-caps=-all', '--ambient-caps=-all',
               'bwrap', '--unshare-user', '--disable-userns', '--unshare-pid',
               '--unshare-ipc', '--unshare-uts', '--ro-bind', '/', '/', '--proc', '/proc',
               '--dev', '/dev', '--', '/bin/true'])


def owned_installation():
    if r.CODE.exists():
        manifest = r.read_json(r.CODE / 'manifest.json')
        if manifest.get('application') != r.APP:
            raise r.Failure(f'installation directory {r.CODE}: not owned by this application')
    for name in ('vpnctl', 'vpnrun', 'vpn-run'):
        path = r.BIN / name
        if os.path.lexists(path) and (not path.is_symlink() or path.readlink() != r.CODE / name):
            raise r.Failure(f'command path {path}: already occupied by another installation; refusing to overwrite')
    if not r.CODE.exists():
        for unit in UNITS:
            path = r.UNIT_DIR / unit
            if os.path.lexists(path):
                raise r.Failure(f'systemd unit {path}: already exists without this application manifest')


def provision():
    path = r.DATA / 'identity.json'
    if path.exists():
        note(f'Reusing this installation\'s dedicated key from {path}')
        value = r.identity()
    else:
        account = prompt_account()
        key = r.valid_key(r.command(['wg', 'genkey']))
        value = {'account': account, 'private_key': key,
                 'public_key': r.valid_key(r.command(['wg', 'pubkey'], key + '\n'))}
        # Save before registration so an interrupted API response can be recovered
        # on reinstall without creating another key or orphan device.
        r.atomic_json(path, value)
    value = r.register_device(value)
    note(f'Dedicated Mullvad device ready: {value["device_name"]}; key stays on this machine')


def package_digest(source):
    result = hashlib.sha256()
    for name in sorted((*FILES, *('systemd/' + name for name in UNITS))):
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise r.Failure(f'package source {path}: expected a regular file')
        result.update(name.encode() + b'\0' + path.read_bytes() + b'\0')
    return result.hexdigest()


def revision(source):
    path = source / 'revision.json'
    if path.exists():
        value = json.loads(path.read_text()).get('revision')
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
            raise r.Failure('package revision: invalid SHA')
        return value
    try:
        if r.command(['git', '-C', str(source), 'status', '--porcelain']):
            return None
        value = r.command(['git', '-C', str(source), 'rev-parse', 'HEAD'])
        return value if re.fullmatch(r'[0-9a-f]{40}', value) else None
    except r.Failure:
        return None


def copy_code(digest):
    r.CODE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + r.APP + '-', dir=r.CODE.parent))
    for name in FILES:
        shutil.copyfile(SOURCE / name, staging / name)
        (staging / name).chmod(0o755 if name in {'install', 'uninstall', 'vpnctl', 'vpnrun'} else 0o644)
    (staging / 'systemd').mkdir(mode=0o755)
    for name in UNITS:
        shutil.copyfile(SOURCE / 'systemd' / name, staging / 'systemd' / name)
        (staging / 'systemd' / name).chmod(0o644)
    if package_digest(staging) != digest:
        raise r.Failure('installer source changed during copy; installation refused')
    r.atomic_json(staging / 'manifest.json', {'application': r.APP, 'version': VERSION,
                  'package_digest': digest, 'revision': revision(SOURCE)})
    staging.chmod(0o755)
    if r.CODE.exists():
        # Linux atomic exchange avoids the old rename-away / missing-code window.
        libc = ctypes.CDLL(None, use_errno=True)
        exchange = getattr(libc, 'renameat2', None)
        if exchange is None or exchange(-100, os.fsencode(staging), -100, os.fsencode(r.CODE), 2) != 0:
            raise r.Failure('atomic installation exchange unavailable; old installation retained')
        retained = r.DATA / 'retained-code' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        retained.parent.mkdir(mode=0o700, exist_ok=True)
        staging.rename(retained)
    else:
        staging.rename(r.CODE)
    descriptor = os.open(r.CODE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def maintenance_lock():
    r.secure_dir(r.RUN, 0o711)
    with (r.RUN / 'maintenance.lock').open('a') as descriptor:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def user_record(user):
    return {'uid': user.pw_uid, 'gid': user.pw_gid, 'user': user.pw_name, 'version': VERSION}


def begin_maintenance(operation, user=None, digest=None):
    with r.locked(maintenance=True, wait=r.management_wait()):
        if r.NS in r.namespaces() and r.command(['ip', 'netns', 'pids', r.NS]):
            raise r.Failure(f'namespace {r.NS}: stop tunnel programs before installing/updating/uninstalling')
        marker = {'operation': operation, 'pid': os.getpid(), 'timestamp': r.stamp(), 'package_digest': digest}
        if user:
            marker['installation'] = user_record(user)
        r.atomic_json(r.DATA / 'maintenance', marker)


def finalize(info):
    user = pwd.getpwnam(info['user'])
    if user_record(user) != {**info, 'version': VERSION}:
        raise r.Failure('installation user identity changed; reinstall explicitly')
    r.atomic_json(r.DATA / 'installation.json', user_record(user))
    if not (r.DATA / 'settings.json').exists():
        r.atomic_json(r.DATA / 'settings.json', r.DEFAULTS)
    r.settings()
    for name in UNITS:
        content = (r.CODE / 'systemd' / name).read_text().replace('@USER@', user.pw_name)
        path = r.UNIT_DIR / name
        # Unit text is public; replace it atomically and apply standard mode.
        fd, temporary = tempfile.mkstemp(prefix='.' + name, dir=r.UNIT_DIR)
        with os.fdopen(fd, 'w') as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        Path(temporary).chmod(0o644)
        os.replace(temporary, path)
    r.BIN.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name in ('vpnctl', 'vpnrun'):
        path = r.BIN / name
        if os.path.lexists(path) and (not path.is_symlink() or path.readlink() != r.CODE / name):
            raise r.Failure(f'command path {path}: occupied by another installation')
        if not path.is_symlink():
            path.symlink_to(r.CODE / name)
    old = r.BIN / 'vpn-run'
    if old.is_symlink() and old.readlink() == r.CODE / 'vpn-run':
        old.unlink()
    r.command(['systemctl', 'daemon-reload'])
    r.command(['systemctl', 'enable', '--now', 'inverse-split-tunnel.socket', 'inverse-split-tunnel-watchdog.service'])


def recover_maintenance():
    """An abandoned marker is cleared only after verifying and finishing install."""
    try:
        with maintenance_lock():
            if not (r.DATA / 'maintenance').exists():
                return True
            try:
                marker = r.read_json(r.DATA / 'maintenance')
            except r.Failure:
                # Legacy installs used an empty marker. Verify the entire code
                # package and installed user before recovering that older form.
                if (r.DATA / 'maintenance').stat().st_size != 0:
                    raise
                marker = {'operation': 'install'}
            if marker.get('operation') != 'install':
                raise r.Failure('abandoned uninstall: rerun uninstall or install from a trusted source directory')
            manifest = r.read_json(r.CODE / 'manifest.json')
            digest = package_digest(r.CODE)
            if manifest.get('version') != VERSION or manifest.get('package_digest') != digest:
                raise r.Failure('interrupted installation: installed package incomplete; rerun sh install')
            expected = marker.get('package_digest')
            if expected is not None and expected != digest:
                # An update died before the atomic exchange. The old verified
                # installation remains authoritative; restore it, then retry update.
                info = r.read_json(r.DATA / 'installation.json')
            else:
                info = marker.get('installation') or r.read_json(r.DATA / 'installation.json')
            with r.locked(maintenance=True):
                finalize(info)
                (r.DATA / 'maintenance').unlink()
            note('Recovered abandoned maintenance using the verified installed package')
            return True
    except BlockingIOError:
        return False


def install(user_name=None):
    user = selected_user(user_name)
    owned_installation()
    dependencies()
    preflight(user)
    r.secure_dir(r.DATA)
    r.secure_dir(r.DATA / 'history')
    digest = package_digest(SOURCE)
    with maintenance_lock():
        begin_maintenance('install', user, digest)
        # Retain the marker on failure: the watchdog validates the installed
        # package before finishing/reverting an interrupted installation.
        provision()
        copy_code(digest)
        with r.locked(maintenance=True, wait=r.management_wait()):
            finalize(user_record(user))
            (r.DATA / 'maintenance').unlink()
    r.command(['systemctl', 'restart', 'inverse-split-tunnel-watchdog.service'])
    note(f'Installed vpnrun for {user.pw_name}; the source directory can be moved or removed.')
    print('Next: vpnrun servers us-; vpnrun switch EXACT-SERVER; vpnrun -- COMMAND\n'
          'Updates: vpnrun update (or upgrade). Uninstall: vpnrun uninstall')


def revoke_device():
    value = r.identity()
    api = r.Mullvad(value['account'])
    device_id = value.get('device_id')
    devices = api.request('/accounts/v1/devices')
    matched = next((row for row in devices if row['id'] == device_id), None)
    if matched is None:
        note('Dedicated Mullvad device is already absent; no remote device deleted')
        return
    if matched['pubkey'] != value['public_key']:
        raise r.Failure('dedicated remote device key differs; deletion refused')
    api.request('/accounts/v1/devices/' + urllib.parse.quote(device_id, safe=''), method='DELETE')
    note('Revoked only this installation\'s dedicated Mullvad device')


def uninstall():
    owned_installation()
    if not (r.CODE / 'manifest.json').exists():
        raise r.Failure(f'installation {r.CODE}: not installed')
    if not ask('Uninstall vpnrun from this machine?'):
        return
    revoke = (r.DATA / 'identity.json').exists() and ask('Also revoke this installation\'s dedicated Mullvad device?', default=True)
    erase = (r.DATA / 'identity.json').exists() and ask('Remove the saved account number and WireGuard private key?')
    with maintenance_lock():
        begin_maintenance('uninstall')
        if revoke:
            revoke_device()
        r.command(['systemctl', 'disable', '--now', 'inverse-split-tunnel-watchdog.service', 'inverse-split-tunnel.socket'])
        r.command(['systemctl', 'stop', 'inverse-split-tunnel@*.service'])
        r.stop(maintenance=True)
        for name in ('vpnctl', 'vpnrun', 'vpn-run'):
            path = r.BIN / name
            if path.is_symlink() and path.readlink() == r.CODE / name:
                path.unlink()
        for name in UNITS:
            (r.UNIT_DIR / name).unlink(missing_ok=True)
        r.command(['systemctl', 'daemon-reload'])
        shutil.rmtree(r.CODE)
        if erase:
            (r.DATA / 'identity.json').unlink(missing_ok=True)
        (r.DATA / 'maintenance').unlink(missing_ok=True)
    note(f'Uninstalled; shared packages and non-secret history remain at {r.DATA}')
    if not erase:
        note(f'Saved credentials remain root-only at {r.DATA / "identity.json"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('install', 'uninstall'))
    parser.add_argument('--user', help='non-root login authorized to use this installation')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run sh install or sh uninstall; the wrapper requests sudo')
    os.umask(0o077)
    try:
        if args.operation == 'install':
            install(args.user)
        else:
            uninstall()
    except (Exception, KeyboardInterrupt) as exc:
        print(r.error_message(args.operation, exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
