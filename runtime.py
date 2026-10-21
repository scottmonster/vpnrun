"""Installed service primitives. No desktop Mullvad or checkout dependencies."""
import base64
import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import traceback
import urllib.error
import urllib.request
import uuid

APP = 'inverse-split-tunnel'
CODE = Path('/usr/local/lib') / APP
BIN = Path('/usr/local/bin')
UNIT_DIR = Path('/etc/systemd/system')
DATA = Path('/var/lib') / APP
RUN = Path('/run') / APP
SOCKET = RUN / 'control.sock'
NS = 'ist-managed'
IFACE = 'wg-vpn'
DNS = Path('/etc/netns') / NS
PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
FIREWALL = '''table inet vpn_guard {
 chain output { type filter hook output priority 0; policy drop; oifname "wg-vpn" accept; }
 chain input { type filter hook input priority 0; policy drop; iifname "wg-vpn" ct state established,related accept; }
 chain forward { type filter hook forward priority 0; policy drop; }
}
'''
RESOLVER = 'nameserver 10.64.0.1\noptions timeout:2 attempts:2\n'
NSSWITCH = 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n'
DEFAULTS = {'launch_wait_ms': 0, 'check_interval': 15, 'probe_timeout': 3,
            'failure_threshold': 3, 'max_backoff': 120}


class Failure(Exception):
    """Only explicitly sanitized messages may cross the privileged boundary."""


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def secure_dir(path, mode=0o700):
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise Failure(f'directory {path}: unexpected owner, type, or symlink')
    path.chmod(mode)


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump(value, target)
            target.write('\n')
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_json(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise Failure(f'file {path}: expected owner-only regular file')
            return json.load(source)
    except Failure:
        raise
    except (OSError, ValueError):
        raise Failure(f'file {path}: cannot read valid private JSON; contents excluded') from None


def command(args, data=None, timeout=30):
    try:
        result = subprocess.run(args, input=data, text=True, capture_output=True,
                                env={'PATH': PATH, 'LANG': 'C.UTF-8'}, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(f'command {args[0]} for namespace {NS}: unavailable or timed out') from None
    if result.returncode:
        # Never retain stdout/stderr: commands may process key material.
        raise Failure(f'command {args[0]} for namespace {NS}: exit {result.returncode}; output excluded')
    return result.stdout.strip()


def inside(args, **kwargs):
    return command(['ip', 'netns', 'exec', NS, *args], **kwargs)


def settings():
    value = dict(DEFAULTS)
    path = DATA / 'settings.json'
    if path.exists():
        saved = read_json(path)
        if not isinstance(saved, dict) or set(saved) - set(DEFAULTS):
            raise Failure(f'configuration {path}: unknown setting')
        value.update(saved)
    limits = {'launch_wait_ms': (0, 30000), 'check_interval': (1, 3600),
              'probe_timeout': (1, 10), 'failure_threshold': (1, 20), 'max_backoff': (1, 3600)}
    for key, (low, high) in limits.items():
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise Failure(f'configuration {path}: {key} must be an integer between {low} and {high}')
    return value


def management_wait():
    # Explicit stop/switch/install may wait for a bounded background probe.
    # Healthy launches use shared locks and never wait for that probe.
    return max(5, settings()['probe_timeout'] * 2 + 2)


@contextlib.contextmanager
def locked(maintenance=False, wait=0, shared=False):
    secure_dir(RUN, 0o711)
    with (RUN / 'control.lock').open('a') as target:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(target, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Failure('tunnel control busy; retry shortly or configure launch_wait_ms') from None
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        if not maintenance and (DATA / 'maintenance').exists():
            raise Failure(f'installation {DATA}: maintenance in progress; retry after install/uninstall finishes')
        yield


def error_message(operation, error):
    """Format a compact terminal/journal error without creating diagnostic files."""
    # Arbitrary exception text/locals may contain credentials or API bodies.
    cause = str(error) if isinstance(error, Failure) else type(error).__name__
    frames = traceback.extract_tb(error.__traceback__)
    location = f'{frames[-1].filename}:{frames[-1].lineno}' if frames else str(DATA)
    return f'{stamp()} ERROR {operation} (namespace {NS}): {cause}; at {location}'


def valid_key(value):
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise Failure('WireGuard key validation: invalid 32-byte key; contents excluded') from None


class Mullvad:
    host = 'https://api.mullvad.net'

    def __init__(self, account=None):
        self.account = account
        self.token = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, body=None, method=None, authenticated=True):
        if authenticated and self.token is None:
            self.token = self.request('/auth/v1/webtoken', {'account_number': self.account}, authenticated=False)['access_token']
        url = self.host + path
        request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method)
        request.add_header('Content-Type', 'application/json')
        if authenticated:
            request.add_header('Authorization', 'Bearer ' + self.token)
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise Failure(f'URL {url}: response size limit exceeded')
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise Failure(f'URL {url}: HTTP {exc.code}; response body excluded') from None
        except (OSError, ValueError, urllib.error.URLError):
            raise Failure(f'URL {url}: request failed or invalid JSON; contents excluded') from None

    def relays(self):
        values = self.request('/www/relays/all', authenticated=False)
        if not isinstance(values, list):
            raise Failure(f'URL {self.host}/www/relays/all: expected relay list')
        if not all(isinstance(row, dict) for row in values):
            raise Failure(f'URL {self.host}/www/relays/all: expected relay objects')
        return [validate_relay(row) for row in values if row.get('type') == 'wireguard' and row.get('active') is True]


def validate_relay(row):
    try:
        name = row['hostname']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)+', name) or len(name) > 100:
            raise ValueError
        address = str(ipaddress.IPv4Address(row['ipv4_addr_in']))
        return {'hostname': name, 'endpoint': address + ':51820', 'public_key': valid_key(row['pubkey'])}
    except (KeyError, TypeError, ValueError, Failure):
        raise Failure('URL https://api.mullvad.net/www/relays/all: invalid relay hostname, address, or key; row excluded') from None


def identity():
    path = DATA / 'identity.json'
    value = read_json(path)
    try:
        valid_key(value['private_key'])
        valid_key(value['public_key'])
        if command(['wg', 'pubkey'], value['private_key'] + '\n') != value['public_key']:
            raise ValueError
        if not re.fullmatch(r'[0-9]{16}', value['account']):
            raise ValueError
    except (KeyError, TypeError, ValueError, Failure):
        raise Failure(f'identity file {path}: invalid credential structure; contents excluded') from None
    return value


def register_device(value):
    """Recover an interrupted registration by key; never rotate keys on failure."""
    api = Mullvad(value['account'])
    devices = api.request('/accounts/v1/devices')
    device = next((row for row in devices if row['pubkey'] == value['public_key']), None)
    if device is None:
        device = api.request('/accounts/v1/devices', {'pubkey': value['public_key'], 'hijack_dns': False})
    try:
        if device['pubkey'] != value['public_key']:
            raise ValueError
        value.update(device_id=device['id'], device_name=device['name'],
                     addresses=[str(ipaddress.IPv4Interface(device['ipv4_address'])),
                                str(ipaddress.IPv6Interface(device['ipv6_address']))])
    except (KeyError, ValueError, TypeError):
        raise Failure('URL https://api.mullvad.net/accounts/v1/devices: invalid dedicated device response; body excluded') from None
    atomic_json(DATA / 'identity.json', value)
    return value


def ensure_device():
    value = identity()
    devices = Mullvad(value['account']).request('/accounts/v1/devices')
    if not any(row['id'] == value.get('device_id') and row['pubkey'] == value['public_key'] for row in devices):
        raise Failure(f'dedicated device for {DATA / "identity.json"}: no longer registered; rerun install to repair (no automatic key replacement)')
    return value


def namespaces():
    return {line.split()[0] for line in command(['ip', 'netns', 'list']).splitlines()}


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items() if k not in {'handle', 'metainfo'}}
    if isinstance(value, list):
        return [normalize(v) for v in value if not (isinstance(v, dict) and 'metainfo' in v)]
    return value


def target():
    """One durable intent; legacy desired.json wins over a stale selection."""
    if (DATA / 'state.json').exists():
        value = read_json(DATA / 'state.json')
        if (not isinstance(value, dict) or type(value.get('enabled')) is not bool or
                not isinstance(value.get('generation'), str)):
            raise Failure('saved tunnel intent: invalid state; rerun vpnrun switch SERVER')
        relay = saved_relay(value.get('relay'))
        return {**value, 'relay': relay}
    for name in ('desired.json', 'selection.json'):
        if (DATA / name).exists():
            relay = saved_relay(read_json(DATA / name))
            generation = hashlib.sha256(json.dumps(relay, sort_keys=True).encode()).hexdigest()
            return {'enabled': True, 'relay': relay, 'generation': generation}
    return None


def saved_relay(value):
    try:
        host, port = value['endpoint'].rsplit(':', 1)
        if port != '51820':
            raise ValueError
        return validate_relay({'hostname': value['hostname'], 'ipv4_addr_in': host,
                               'pubkey': value['public_key']})
    except (KeyError, TypeError, ValueError):
        raise Failure('saved server: invalid configuration; rerun vpnrun switch SERVER') from None


def snapshot():
    # Five local commands; never a network operation or handshake wait.
    links = json.loads(inside(['ip', '-j', 'address', 'show'], timeout=2))
    rules = json.loads(inside(['nft', '-j', 'list', 'table', 'inet', 'vpn_guard'], timeout=2))
    routes4 = json.loads(inside(['ip', '-j', 'route', 'show', 'table', 'all'], timeout=2))
    routes6 = json.loads(inside(['ip', '-j', '-6', 'route', 'show', 'table', 'all'], timeout=2))
    # wg dump includes private material: parse here, never expose/retain the dump.
    rows = inside(['wg', 'show', IFACE, 'dump'], timeout=2).splitlines()
    interface = rows[0].split('\t')
    peers = [row.split('\t') for row in rows[1:]]
    if len(interface) != 4 or any(len(row) != 8 for row in peers):
        raise Failure('WireGuard interface: invalid local inspection output')
    return {'links': links, 'rules': rules, 'routes4': routes4, 'routes6': routes6,
            'public_key': interface[1],
            'peers': [{'public_key': row[0], 'endpoint': row[2], 'allowed_ips': row[3],
                       'handshake': int(row[4]), 'rx': int(row[5]), 'tx': int(row[6]),
                       'keepalive': row[7]} for row in peers]}


def guard(wanted=None, value=None):
    wanted = wanted or target()
    if not wanted:
        raise Failure('select a server first with vpnrun switch SERVER')
    value = value or read_json(DATA / 'identity.json')
    view = snapshot()
    links = {row['ifname']: row for row in view['links']}
    if set(links) != {'lo', IFACE}:
        raise Failure(f'namespace {NS}: missing or extra interface; launch refused')
    if any('UP' not in row.get('flags', []) for row in links.values()):
        raise Failure(f'namespace {NS}: interface down; recovery required')
    addresses = {str(ipaddress.ip_interface(row['local'] + '/' + str(row['prefixlen'])))
                 for row in links[IFACE].get('addr_info', []) if row.get('scope') == 'global'}
    if addresses != {str(ipaddress.ip_interface(address)) for address in value['addresses']}:
        raise Failure(f'namespace {NS}: tunnel addresses incomplete; recovery required')
    if normalize(view['rules']) != normalize(read_json(DATA / 'firewall.json')):
        raise Failure(f'namespace {NS}: firewall differs; launch refused')
    for routes in (view['routes4'], view['routes6']):
        if any(row.get('dev') not in {None, IFACE, 'lo'} for row in routes):
            raise Failure(f'namespace {NS}: unexpected route device; launch refused')
        if not any(row.get('dst') == 'default' and row.get('dev') == IFACE and
                   row.get('table', 'main') in ('main', 254) and 'gateway' not in row and
                   row.get('type', 'unicast') == 'unicast' for row in routes):
            raise Failure(f'namespace {NS}: default route missing; recovery required')
    relay = wanted['relay']
    if view['public_key'] != value['public_key'] or len(view['peers']) != 1:
        raise Failure(f'namespace {NS}: unexpected WireGuard identity/peer; recovery required')
    peer = view['peers'][0]
    if (peer['public_key'] != relay['public_key'] or peer['endpoint'] != relay['endpoint'] or
            set(peer['allowed_ips'].split(',')) != {'0.0.0.0/0', '::/0'} or peer['keepalive'] != '25'):
        raise Failure(f'namespace {NS}: peer differs from requested server; recovery required')
    if {p.name for p in DNS.iterdir()} != {'resolv.conf', 'nsswitch.conf'}:
        raise Failure(f'namespace override directory {DNS}: unexpected contents')
    for name, expected in (('resolv.conf', RESOLVER), ('nsswitch.conf', NSSWITCH)):
        path = DNS / name
        if not stat.S_ISREG(path.lstat().st_mode) or path.read_text() != expected:
            raise Failure(f'namespace resolver {path}: unexpected contents')
    return view


def wire_config(value, relay):
    return (f'[Interface]\nPrivateKey = {value["private_key"]}\n'
            f'[Peer]\nPublicKey = {relay["public_key"]}\n'
            f'Endpoint = {relay["endpoint"]}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')


def configure(value, relay):
    inside(['wg', 'setconf', IFACE, '/dev/stdin'], data=wire_config(value, relay))


def write_dns():
    if DNS.exists():
        retain_dns()
    if not DNS.parent.exists():
        DNS.parent.mkdir(mode=0o755)
        DNS.parent.chmod(0o755)
    secure_dir(DNS, 0o755)
    for name, content in (('resolv.conf', RESOLVER), ('nsswitch.conf', NSSWITCH)):
        (DNS / name).write_text(content)
        (DNS / name).chmod(0o644)


def install_firewall(replace=False):
    prefix = ''
    if replace:
        try:
            inside(['nft', 'list', 'table', 'inet', 'vpn_guard'])
            prefix = 'delete table inet vpn_guard\n'
        except Failure:
            pass
    # nft applies the entire replacement atomically.
    inside(['nft', '-f', '-'], data=prefix + FIREWALL)
    atomic_json(DATA / 'firewall.json', json.loads(inside(['nft', '-j', 'list', 'table', 'inet', 'vpn_guard'])))


def set_addresses_routes(value):
    inside(['ip', 'address', 'flush', 'dev', IFACE, 'scope', 'global'])
    for address in value['addresses']:
        inside(['ip', 'address', 'add', address, 'dev', IFACE])
    inside(['ip', 'link', 'set', IFACE, 'mtu', '1280', 'up'])
    inside(['ip', 'link', 'set', 'lo', 'up'])
    inside(['ip', 'route', 'replace', 'default', 'dev', IFACE])
    inside(['ip', '-6', 'route', 'replace', 'default', 'dev', IFACE])


def create_namespace(value, relay):
    write_dns()
    command(['ip', 'netns', 'add', NS])
    transport = 'ist' + str(os.getpid())
    try:
        command(['ip', 'link', 'add', transport, 'type', 'wireguard'])
        command(['ip', 'link', 'set', transport, 'netns', NS])
        inside(['ip', 'link', 'set', transport, 'name', IFACE])
        install_firewall()
        configure(value, relay)
        set_addresses_routes(value)
        guard({'relay': relay}, value)
    except Exception:
        try:
            command(['ip', 'link', 'del', transport])
        except Failure:
            pass
        raise


def record_applied(wanted):
    atomic_json(DATA / 'applied.json', {'generation': wanted['generation'],
                'server': wanted['relay']['hostname'], 'timestamp': stamp()})


def recover_locked(wanted):
    """Caller holds control lock; no API traffic, no process termination."""
    value = identity()
    if NS not in namespaces():
        create_namespace(value, wanted['relay'])
    else:
        try:
            guard(wanted, value)
        except (Failure, OSError, ValueError, KeyError):
            pids = command(['ip', 'netns', 'pids', NS]).split()
            if not pids:
                command(['ip', 'netns', 'del', NS])
                create_namespace(value, wanted['relay'])
            else:
                # Never delete a namespace that applications still occupy.
                install_firewall(replace=True)
                links = json.loads(inside(['ip', '-j', 'link', 'show']))
                if {row['ifname'] for row in links} != {'lo', IFACE}:
                    raise Failure(f'namespace {NS}: cannot repair interfaces with active programs; stop them and retry')
                inside(['ip', 'link', 'set', IFACE, 'down'])
                write_dns()
                configure(value, wanted['relay'])
                set_addresses_routes(value)
                guard(wanted, value)
    record_applied(wanted)


def prepare_launch():
    """Called while locked: hot path checks only; repairs run in watchdog."""
    wanted = target()
    if not wanted:
        raise Failure('select a server first with vpnrun switch SERVER')
    if not wanted['enabled']:
        wanted = {**wanted, 'enabled': True}
        atomic_json(DATA / 'state.json', wanted)
    if NS not in namespaces():
        # Cold starts need local setup, never API access or a handshake wait.
        recover_locked(wanted)
        return
    try:
        guard(wanted)
    except (Failure, OSError, ValueError, KeyError):
        (RUN / 'recover-needed').touch(mode=0o600)
        raise Failure('tunnel needs recovery; watchdog will repair it; retry shortly (vpnrun status)') from None


@contextlib.contextmanager
def launch_ready():
    deadline = time.monotonic() + settings()['launch_wait_ms'] / 1000
    while True:
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(locked(shared=True))
                wanted = target()
                if wanted and wanted['enabled'] and (Path('/run/netns') / NS).exists():
                    try:
                        guard(wanted)
                    except (Failure, OSError, ValueError, KeyError):
                        (RUN / 'recover-needed').touch(mode=0o600)
                        raise Failure('tunnel needs recovery; watchdog will repair it; retry shortly (vpnrun status)') from None
                else:
                    stack.close()
                    stack.enter_context(locked())
                    prepare_launch()
            except Failure:
                if time.monotonic() >= deadline:
                    raise
            else:
                # Keep the lock until payload namespace entry/privilege drop.
                # Errors in the application launcher must never retry execution.
                yield
                return
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))


def switch(server):
    if not isinstance(server, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)+', server) or len(server) > 100:
        raise Failure('vpnrun switch: expected an exact relay hostname')
    # Slow API validation is outside the control lock.
    relay = next((row for row in Mullvad().relays() if row['hostname'] == server), None)
    if relay is None:
        raise Failure(f'relay {server}: not active or not found')
    ensure_device()
    with locked(wait=management_wait()):
        previous = target()
        wanted = {'enabled': True, 'relay': relay, 'generation': uuid.uuid4().hex}
        if NS in namespaces():
            links = json.loads(inside(['ip', '-j', 'link', 'show']))
            if any(row['ifname'] == IFACE for row in links):
                # Block the old peer BEFORE committing a new authoritative intent.
                inside(['ip', 'link', 'set', IFACE, 'down'])
        atomic_json(DATA / 'state.json', wanted)
        # Intent survives SIGKILL even if applying it or recording completion fails.
        recover_locked(wanted)
        atomic_json(DATA / 'history' / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json'),
                    {'timestamp': stamp(), 'previous': previous, 'selected': relay})
    return {'server': server, 'message': 'Server applied; existing connections may need to reconnect.'}


def status():
    with locked(wait=0.1, shared=True):
        wanted = target()
        result = {'state': 'stopped', 'server': wanted['relay']['hostname'] if wanted else None,
                  'enabled': wanted['enabled'] if wanted else False, 'settings': settings()}
        if NS in namespaces():
            try:
                view = guard(wanted)
                result.update(state='configured', peers=view['peers'])
            except (Failure, OSError, ValueError, KeyError) as exc:
                result.update(state='degraded', error=error_message('status', exc))
        if (RUN / 'health.json').exists():
            health = read_json(RUN / 'health.json')
            if wanted and health.get('generation') == wanted['generation']:
                try:
                    checked = datetime.datetime.fromisoformat(health['timestamp'])
                    age = (datetime.datetime.now(datetime.timezone.utc) - checked).total_seconds()
                    health['age_seconds'] = max(0, round(age, 1))
                    health['stale'] = age > max(30, health.get('retry_in_seconds', 15) * 2 + 10)
                except (KeyError, TypeError, ValueError):
                    health['stale'] = True
                result['health'] = health
                if result['state'] == 'configured' and not health['stale'] and health.get('state') in {'connected', 'degraded'}:
                    result['state'] = health['state']
        return result


def retain_dns():
    if DNS.exists():
        retained = DATA / 'retained-netns' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        retained.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.move(str(DNS), str(retained))


def stop(maintenance=False):
    with locked(maintenance=maintenance, wait=management_wait()):
        if NS in namespaces() and command(['ip', 'netns', 'pids', NS]).split():
            raise Failure(f'namespace {NS}: stop its programs before shutdown')
        wanted = target()
        if wanted:
            atomic_json(DATA / 'state.json', {**wanted, 'enabled': False})
        if NS in namespaces():
            command(['ip', 'netns', 'del', NS])
        retain_dns()
        (RUN / 'health.json').unlink(missing_ok=True)
        (RUN / 'recover-needed').unlink(missing_ok=True)
    return {'state': 'stopped'}
