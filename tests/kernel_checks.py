"""Real WireGuard/nftables tests, strictly inside disposable Linux namespaces."""
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import runtime as r
import watchdog


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def check(condition, description):
    if not condition:
        raise AssertionError(description)
    print('PASS:', description, flush=True)


def main():
    for kind, key in (('net', 'VPNRUN_TEST_PARENT_NET'), ('mnt', 'VPNRUN_TEST_PARENT_MNT')):
        parent = os.environ.get(key)
        if not parent or str(os.stat('/proc/self/ns/' + kind).st_ino) == parent:
            sys.exit('Refusing kernel tests without isolated network AND mount namespaces; use sh tests/kernel.sh')
    run('mount', '--make-rprivate', '/')
    with tempfile.TemporaryDirectory(prefix='vpnrun-kernel-') as temporary:
        root = Path(temporary)
        run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
        etc = root / 'etc'
        etc.mkdir()
        for name in ('ld.so.cache', 'nsswitch.conf', 'passwd', 'group', 'hosts', 'protocols', 'services'):
            path = Path('/etc') / name
            if path.is_file():
                (etc / name).write_bytes(path.read_bytes())
        (etc / 'resolv.conf').write_text('nameserver 127.0.0.1\n')
        (etc / 'netns').mkdir()
        # Overlay /etc too: never create test directories in the host filesystem.
        run('mount', '--bind', str(etc), '/etc')
        r.DATA, r.RUN, r.CODE = root / 'state', Path('/run/vpnrun-test'), ROOT
        r.DATA.mkdir(mode=0o700)
        (r.DATA / 'history').mkdir(mode=0o700)
        r.NS = 'vpnrun-kernel-test'
        r.DNS = Path('/etc/netns') / r.NS
        private = r.command(['wg', 'genkey'])
        public = r.command(['wg', 'pubkey'], data=private + '\n')
        peer_private = r.command(['wg', 'genkey'])
        peer_public = r.command(['wg', 'pubkey'], data=peer_private + '\n')
        identity = {'account': '0' * 16, 'private_key': private, 'public_key': public,
                    'addresses': ['10.77.0.2/32', 'fd42::2/128']}
        relay = {'hostname': 'us-test-wg-001', 'endpoint': '192.0.2.1:51820', 'public_key': peer_public}
        wanted = {'enabled': True, 'generation': 'first', 'relay': relay}
        r.atomic_json(r.DATA / 'identity.json', identity)
        r.atomic_json(r.DATA / 'state.json', wanted)
        # Any unexpected API access is a test failure. No real account is used.
        with patch.object(r.Mullvad, 'request', side_effect=AssertionError('unexpected API call')):
            with r.launch_ready():
                pass
            check(bool(r.guard()), 'cold launch builds real WireGuard, IPv4/IPv6 routes and nftables')
            check(r.inside(['cat', '/etc/resolv.conf']) == r.RESOLVER.strip(),
                  'namespace processes receive the private Mullvad resolver')
            timings = []
            for _ in range(30):
                start = time.perf_counter()
                with r.launch_ready():
                    pass
                timings.append((time.perf_counter() - start) * 1000)
            print('Healthy launch preparation: median %.2f ms; p95 %.2f ms (30 samples, no payload startup)' %
                  (statistics.median(timings), sorted(timings)[28]), flush=True)
            baseline_file = os.environ.get('VPNRUN_TEST_BASELINE')
            if baseline_file:
                spec = importlib.util.spec_from_file_location('legacy_runtime', baseline_file)
                baseline = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(baseline)
                for name in ('DATA', 'RUN', 'DNS', 'NS', 'CODE'):
                    setattr(baseline, name, getattr(r, name))
                old = []
                for _ in range(30):
                    start = time.perf_counter()
                    with baseline.locked():
                        if baseline.NS not in baseline.namespaces():
                            raise AssertionError('baseline namespace missing')
                        baseline.guard()
                    old.append((time.perf_counter() - start) * 1000)
                print('Previous launch preparation: median %.2f ms; p95 %.2f ms (30 samples)' %
                      (statistics.median(old), sorted(old)[28]), flush=True)
            process = subprocess.Popen(['ip', 'netns', 'exec', r.NS, '/bin/sleep', '60'])
            try:
                time.sleep(0.05)
                inode = os.stat('/run/netns/' + r.NS).st_ino
                r.inside(['ip', 'route', 'del', 'default'])
                r.inside(['ip', 'link', 'set', r.IFACE, 'down'])
                start = time.perf_counter()
                try:
                    with r.launch_ready():
                        raise AssertionError('damaged tunnel launched')
                except r.Failure:
                    pass
                check(time.perf_counter() - start < 0.2, 'damaged setup fails promptly without repair sleeps')
                with r.locked():
                    r.recover_locked(wanted)
                r.guard()
                check(process.poll() is None and os.stat('/run/netns/' + r.NS).st_ino == inode,
                      'repair preserves active program and namespace')
                wanted = {**wanted, 'generation': 'second', 'relay': {**relay, 'endpoint': '192.0.2.2:51820'}}
                r.atomic_json(r.DATA / 'state.json', wanted)
                try:
                    with r.launch_ready():
                        raise AssertionError('old peer accepted')
                except r.Failure:
                    pass
                with r.locked():
                    r.recover_locked(r.target())
                check(r.guard()['peers'][0]['endpoint'] == '192.0.2.2:51820',
                      'interrupted switch restores authoritative requested peer')
                check(process.poll() is None, 'peer recovery leaves active program alive')
            finally:
                process.terminate()
                process.wait()
            # Direct-route positive control and fail-closed negative control.
            r.command(['ip', 'link', 'add', 'outside', 'type', 'veth', 'peer', 'name', 'direct'])
            r.command(['ip', 'link', 'set', 'direct', 'netns', r.NS])
            r.command(['ip', 'address', 'add', '198.18.0.1/30', 'dev', 'outside'])
            r.command(['ip', 'link', 'set', 'outside', 'up'])
            r.inside(['ip', 'address', 'add', '198.18.0.2/30', 'dev', 'direct'])
            r.inside(['ip', 'link', 'set', 'direct', 'up'])
            r.inside(['nft', 'flush', 'ruleset'])
            r.inside(['ping', '-c', '1', '-W', '1', '198.18.0.1'])
            check(True, 'direct network route works in disposable positive control')
            r.install_firewall()
            r.inside(['ip', 'link', 'set', r.IFACE, 'down'])
            try:
                r.inside(['ping', '-c', '1', '-W', '1', '198.18.0.1'])
            except r.Failure:
                check(True, 'down tunnel cannot use reachable direct route')
            else:
                raise AssertionError('direct traffic escaped firewall')
            r.command(['ip', 'link', 'del', 'outside'])
            with r.locked():
                r.recover_locked(wanted)
            # Simulate lost volatile kernel namespace after boot, retain disk intent/DNS.
            r.command(['ip', 'netns', 'del', r.NS])
            actual_inside = r.inside
            def offline_probe(args, **kwargs):
                if str(r.CODE / 'probe.py') in args:
                    return '{"dns_ok": true, "vpn_ok": true}'
                return actual_inside(args, **kwargs)
            with patch.object(r, 'inside', side_effect=offline_probe):
                watchdog.tick({}, now=0)
            check(bool(r.guard()), 'watchdog restores lost namespace from durable intent after simulated reboot')
            r.stop()
            with patch.object(r, 'inside', side_effect=AssertionError('stopped tunnel probed')):
                watchdog.tick({}, now=0)
            check(r.NS not in r.namespaces() and not r.target()['enabled'], 'intentional stop survives watchdog tick')
        print('No host networking, credentials, installed services or external endpoints were used.', flush=True)


if __name__ == '__main__':
    main()
