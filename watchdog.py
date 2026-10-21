#!/usr/bin/python3
"""Background repair and connectivity monitoring; systemd supervises this daemon."""
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import uuid
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime as r


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0' + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
            connection.sendto(message.encode(), address)


def tick(previous, now=None):
    now = time.monotonic() if now is None else now
    config = r.settings()
    # The maintenance flock, not an untrusted PID or age, determines liveness.
    if (r.DATA / 'maintenance').exists():
        import installer
        if not installer.recover_maintenance():
            return {'next_check': now + 1}
    needs_repair = False
    with r.locked(shared=True):
        wanted = r.target()
        if not wanted or not wanted['enabled']:
            r.atomic_json(r.RUN / 'health.json', {'state': 'stopped', 'timestamp': r.stamp()})
            return {'next_check': now + config['check_interval']}
        generation = wanted['generation']
        failures = previous.get('failures', 0) if previous.get('generation') == generation else 0
        if now < previous.get('next_check', 0) and previous.get('generation') == generation and not (r.RUN / 'recover-needed').exists():
            return previous
        try:
            r.guard(wanted)
            applied = r.read_json(r.DATA / 'applied.json') if (r.DATA / 'applied.json').exists() else {}
            needs_repair = applied.get('generation') != generation
        except (r.Failure, OSError, ValueError, KeyError):
            needs_repair = True
    if needs_repair:
        with r.locked():
            current = r.target()
            if not current or not current['enabled'] or current['generation'] != generation:
                return {'next_check': now}
            r.recover_locked(current)
    (r.RUN / 'recover-needed').unlink(missing_ok=True)
    # A shared probe lock allows healthy launches and status concurrently.
    # Stop/install/switch wait for the bounded probe to exit, so its PID is not
    # mistaken for an application and its namespace cannot be deleted mid-probe.
    try:
        with r.locked(shared=True):
            current = r.target()
            if not current or not current['enabled'] or current['generation'] != generation:
                return {'next_check': now}
            probe = json.loads(r.inside(['/usr/bin/python3', '-I', '-B', str(r.CODE / 'probe.py'),
                                         str(config['probe_timeout'])], timeout=config['probe_timeout'] * 2 + 1))
    except (r.Failure, ValueError):
        probe = {'dns_ok': False, 'vpn_ok': False}
    failures = 0 if probe.get('vpn_ok') else failures + 1
    backoff = min(config['max_backoff'], config['check_interval'] * 2 ** min(max(0, failures - config['failure_threshold']), 10))
    health = {'generation': generation, 'server': wanted['relay']['hostname'],
              'state': 'connected' if probe.get('vpn_ok') else 'degraded',
              'dns_ok': bool(probe.get('dns_ok')), 'vpn_ok': bool(probe.get('vpn_ok')),
              'failures': failures, 'timestamp': r.stamp(), 'retry_in_seconds': backoff}
    with r.locked(shared=True):
        current = r.target()
        if not current or not current['enabled'] or current['generation'] != generation:
            return {'next_check': now}
        r.atomic_json(r.RUN / 'health.json', health)
    if previous.get('health_state') != health['state']:
        print(f'{r.stamp()} tunnel {health["server"]}: {health["state"]} '
              f'(DNS={health["dns_ok"]}, VPN={health["vpn_ok"]})', flush=True)
    if failures >= config['failure_threshold']:
        # Refresh ONLY the selected server. API outages retain the cached peer.
        try:
            relay = next((row for row in r.Mullvad().relays() if row['hostname'] == wanted['relay']['hostname']), None)
            if relay and relay != wanted['relay']:
                with r.locked():
                    current = r.target()
                    if current and current['enabled'] and current['generation'] == generation:
                        current['relay'] = relay
                        current['generation'] = uuid.uuid4().hex
                        r.atomic_json(r.DATA / 'state.json', current)
                        r.recover_locked(current)
        except (r.Failure, OSError, ValueError):
            pass
    return {'generation': generation, 'failures': failures, 'health_state': health['state'], 'next_check': now + backoff}


def ensure_socket():
    state = r.command(['systemctl', 'show', 'inverse-split-tunnel.socket', '--property=ActiveState', '--value'], timeout=2)
    if state in {'failed', 'inactive'}:
        r.command(['systemctl', 'reset-failed', 'inverse-split-tunnel.socket'], timeout=2)
        r.command(['systemctl', 'start', 'inverse-split-tunnel.socket'], timeout=5)


def main():
    if os.geteuid() != 0:
        sys.exit('watchdog must run as root via systemd')
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    state, errors, next_retry = {}, 0, 0
    notify('READY=1')
    while True:
        notify('WATCHDOG=1')
        try:
            if not (r.DATA / 'maintenance').exists():
                ensure_socket()
            if time.monotonic() >= next_retry:
                state = tick(state)
                errors, next_retry = 0, 0
        except Exception as exc:
            print(r.error_message('watchdog', exc), file=sys.stderr, flush=True)
            errors += 1
            try:
                limit = r.settings()['max_backoff']
            except Exception:
                limit = r.DEFAULTS['max_backoff']
            next_retry = time.monotonic() + min(limit, 2 ** min(errors, 12))
        notify('WATCHDOG=1')
        time.sleep(1)


if __name__ == '__main__':
    main()
