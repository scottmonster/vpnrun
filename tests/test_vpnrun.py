"""Offline regression tests: no root, systemd changes, network or real credentials."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import client
import installer
import launch
import protocol
import runtime as r
import updater
import watchdog

KEY = base64.b64encode(b'a' * 32).decode()
OTHER_KEY = base64.b64encode(b'b' * 32).decode()
RELAY = {'hostname': 'us-test-wg-001', 'endpoint': '192.0.2.1:51820', 'public_key': KEY}
IDENTITY = {'public_key': OTHER_KEY, 'private_key': KEY, 'account': '0' * 16,
            'addresses': ['10.77.0.2/32', 'fd42::2/128']}
WANTED = {'enabled': True, 'relay': RELAY, 'generation': 'one'}


class TemporaryState(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.patches = []
        for name in ('DATA', 'RUN', 'DNS'):
            path = self.base / name.lower()
            path.mkdir(mode=0o700)
            item = patch.object(r, name, path)
            item.start()
            self.patches.append(item)
        r.atomic_json(r.DATA / 'state.json', WANTED)
        r.atomic_json(r.DATA / 'identity.json', IDENTITY)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.directory.cleanup()


class CommandTests(unittest.TestCase):
    def test_optional_separator_preserves_all_arguments(self):
        args = ['./script.sh', 'two words', '', '--flag', '*']
        self.assertEqual(client.parse_args(args).command, args)
        self.assertEqual(client.parse_args(['--', *args]).command, args)
        self.assertEqual(client.parse_args(['run', '--', *args]).command, args)

    def test_reserved_name_requires_separator(self):
        self.assertEqual(client.parse_args(['update']).action, 'update')
        self.assertEqual(client.parse_args(['upgrade']).action, 'upgrade')
        self.assertEqual(client.parse_args(['--', 'update']).command, ['update'])

    def test_control_alias(self):
        self.assertEqual(client.parse_args(['switch', RELAY['hostname']], control=True).server, RELAY['hostname'])

    def test_marker_is_overwritten_after_privilege_drop(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = tempfile.TemporaryFile()
            payload.write(json.dumps({'command': ['/bin/true'], 'cwd': directory,
                                      'env': {'VPNRUN': '0', 'HTTP_PROXY': 'hidden', 'DISPLAY': ':0'}}).encode())
            payload.seek(0)
            read_ready, write_ready = os.pipe()
            try:
                with patch.object(sys, 'argv', ['launch.py', str(os.dup(payload.fileno())), str(write_ready)]), \
                     patch.object(os, 'geteuid', return_value=1000), patch.object(os, 'chdir'), \
                     patch.object(os, 'execve') as execute:
                    launch.main()
                env = execute.call_args.args[2]
                self.assertEqual(env['VPNRUN'], '1')
                self.assertNotIn('HTTP_PROXY', env)
                self.assertNotIn('DISPLAY', env)
                self.assertEqual(os.read(read_ready, 1), b'1')
            finally:
                os.close(read_ready)
                payload.close()

    def test_protocol_transfers_real_descriptors(self):
        left, right = socket.socketpair()
        try:
            with open('/dev/null') as source:
                protocol.send(left, {'hello': 'world'}, [source.fileno()])
                value, descriptors = protocol.receive(right)
                self.assertEqual(value, {'hello': 'world'})
                self.assertEqual(len(descriptors), 1)
                self.assertEqual(os.read(descriptors[0], 1), b'')
                os.close(descriptors[0])
        finally:
            left.close()
            right.close()


class StateTests(TemporaryState):
    def test_legacy_desired_wins_over_old_selection(self):
        (r.DATA / 'state.json').unlink()
        other = {**RELAY, 'hostname': 'se-test-wg-002'}
        r.atomic_json(r.DATA / 'desired.json', other)
        r.atomic_json(r.DATA / 'selection.json', RELAY)
        self.assertEqual(r.target()['relay'], other)

    def test_saved_intent_is_authoritative(self):
        r.atomic_json(r.DATA / 'desired.json', {**RELAY, 'hostname': 'old-test-wg-001'})
        self.assertEqual(r.target(), WANTED)

    def test_invalid_intent_rejected(self):
        r.atomic_json(r.DATA / 'state.json', {**WANTED, 'relay': {'endpoint': '../../bad'}})
        with self.assertRaises(r.Failure):
            r.target()

    def test_default_no_wait(self):
        self.assertEqual(r.settings()['launch_wait_ms'], 0)

    def test_settings_validation(self):
        for value in ({'launch_wait_ms': -1}, {'launch_wait_ms': True}, {'unknown': 1}):
            r.atomic_json(r.DATA / 'settings.json', value)
            with self.assertRaises(r.Failure):
                r.settings()

    def test_exclusive_contention_is_immediate(self):
        with r.locked():
            before = time.monotonic()
            with self.assertRaises(r.Failure):
                with r.locked():
                    self.fail('lock was acquired')
            self.assertLess(time.monotonic() - before, 0.05)

    def test_shared_checks_can_overlap(self):
        with r.locked(shared=True):
            with r.locked(shared=True):
                pass
            with self.assertRaises(r.Failure):
                with r.locked():
                    self.fail('writer acquired shared lock')

    def test_configured_lock_wait_is_bounded(self):
        with r.locked():
            start = time.monotonic()
            with self.assertRaises(r.Failure):
                with r.locked(wait=0.03):
                    pass
            elapsed = time.monotonic() - start
            self.assertGreaterEqual(elapsed, 0.025)
            self.assertLess(elapsed, 0.15)

    def test_failed_application_launch_is_not_retried(self):
        r.atomic_json(r.DATA / 'settings.json', {'launch_wait_ms': 50})
        with patch.object(r, 'prepare_launch'), patch.object(r, 'guard'), patch.object(Path, 'exists', return_value=False):
            count = 0
            with self.assertRaisesRegex(r.Failure, 'payload'):
                with r.launch_ready():
                    count += 1
                    raise r.Failure('payload')
            self.assertEqual(count, 1)

    def test_hot_launch_never_uses_api_or_recovery(self):
        with patch.object(r, 'namespaces', return_value={r.NS}), patch.object(r, 'guard') as guard, \
             patch.object(r, 'recover_locked', side_effect=AssertionError('repair')), \
             patch.object(r.Mullvad, 'request', side_effect=AssertionError('network')):
            r.prepare_launch()
            guard.assert_called_once()

    def test_corrupt_hot_tunnel_requests_background_repair(self):
        with patch.object(r, 'namespaces', return_value={r.NS}), patch.object(r, 'guard', side_effect=r.Failure('bad')):
            with self.assertRaises(r.Failure):
                r.prepare_launch()
            self.assertTrue((r.RUN / 'recover-needed').exists())

    def test_stop_refuses_active_programs(self):
        with patch.object(r, 'namespaces', return_value={r.NS}), patch.object(r, 'command', return_value='123'):
            with self.assertRaises(r.Failure):
                r.stop()
        self.assertTrue(r.target()['enabled'])

    def test_stop_saves_intent_before_kernel_delete(self):
        def command(args, **kwargs):
            if args[:3] == ['ip', 'netns', 'pids']:
                return ''
            self.assertFalse(r.target()['enabled'])
            return ''
        with patch.object(r, 'namespaces', return_value={r.NS}), patch.object(r, 'command', side_effect=command):
            r.stop()
        self.assertFalse(r.target()['enabled'])

    def test_explicit_launch_resumes_stopped_tunnel(self):
        r.atomic_json(r.DATA / 'state.json', {**WANTED, 'enabled': False})
        with patch.object(r, 'namespaces', return_value=set()), patch.object(r, 'recover_locked') as recover:
            r.prepare_launch()
        self.assertTrue(r.target()['enabled'])
        self.assertTrue(recover.call_args.args[0]['enabled'])


class GuardTests(TemporaryState):
    def setUp(self):
        super().setUp()
        (r.DNS / 'resolv.conf').write_text(r.RESOLVER)
        (r.DNS / 'nsswitch.conf').write_text(r.NSSWITCH)
        r.atomic_json(r.DATA / 'firewall.json', {'nftables': []})
        self.view = {'links': [{'ifname': 'lo', 'flags': ['UP']},
                              {'ifname': r.IFACE, 'flags': ['UP'], 'addr_info': [
                                  {'local': '10.77.0.2', 'prefixlen': 32, 'scope': 'global'},
                                  {'local': 'fd42::2', 'prefixlen': 128, 'scope': 'global'}]}],
                     'rules': {'nftables': []}, 'routes4': [{'dst': 'default', 'dev': r.IFACE}],
                     'routes6': [{'dst': 'default', 'dev': r.IFACE}], 'public_key': OTHER_KEY,
                     'peers': [{'public_key': KEY, 'endpoint': RELAY['endpoint'],
                                'allowed_ips': '0.0.0.0/0,::/0', 'keepalive': '25'}]}

    def check(self):
        with patch.object(r, 'snapshot', return_value=self.view):
            return r.guard()

    def test_complete_local_config_passes(self):
        self.check()

    def test_missing_ipv4_and_ipv6_defaults_rejected(self):
        for key in ('routes4', 'routes6'):
            with self.subTest(key=key):
                before = self.view[key]
                self.view[key] = []
                with self.assertRaises(r.Failure):
                    self.check()
                self.view[key] = before

    def test_down_interface_rejected(self):
        self.view['links'][1]['flags'] = []
        with self.assertRaises(r.Failure): self.check()

    def test_wrong_server_key_or_endpoint_rejected(self):
        for key in ('public_key', 'endpoint'):
            before = self.view['peers'][0][key]
            self.view['peers'][0][key] = 'wrong'
            with self.assertRaises(r.Failure): self.check()
            self.view['peers'][0][key] = before

    def test_missing_address_rejected(self):
        self.view['links'][1]['addr_info'].pop()
        with self.assertRaises(r.Failure): self.check()

    def test_changed_firewall_rejected(self):
        self.view['rules'] = {'nftables': ['changed']}
        with self.assertRaises(r.Failure): self.check()

    def test_extra_interface_rejected(self):
        self.view['links'].append({'ifname': 'eth0', 'flags': ['UP']})
        with self.assertRaises(r.Failure): self.check()


class WatchdogTests(TemporaryState):
    def setUp(self):
        super().setUp()
        r.atomic_json(r.DATA / 'applied.json', {'generation': WANTED['generation']})

    def test_stopped_tunnel_is_not_resurrected(self):
        r.atomic_json(r.DATA / 'state.json', {**WANTED, 'enabled': False})
        with patch.object(r, 'recover_locked', side_effect=AssertionError('resurrected')), \
             patch.object(r, 'inside', side_effect=AssertionError('network')):
            watchdog.tick({}, now=0)

    def test_healthy_tunnel_not_reconfigured_or_restarted(self):
        with patch.object(r, 'guard'), patch.object(r, 'recover_locked', side_effect=AssertionError('reconfigure')), \
             patch.object(r, 'inside', return_value='{"dns_ok": true, "vpn_ok": true}'):
            state = watchdog.tick({}, now=0)
        self.assertEqual(state['failures'], 0)
        self.assertEqual(r.read_json(r.RUN / 'health.json')['state'], 'connected')

    def test_failed_probe_has_bounded_backoff(self):
        with patch.object(r, 'guard'), patch.object(r, 'inside', return_value='{}'), \
             patch.object(r.Mullvad, 'relays', side_effect=r.Failure('offline')):
            state = {}
            for _ in range(12):
                now = state.get('next_check', 0)
                state = watchdog.tick(state, now=now)
                self.assertLessEqual(state['next_check'] - now, r.DEFAULTS['max_backoff'])
        self.assertEqual(r.read_json(r.RUN / 'health.json')['state'], 'degraded')

    def test_late_probe_does_not_overwrite_new_server(self):
        def probe(*args, **kwargs):
            r.atomic_json(r.DATA / 'state.json', {**WANTED, 'generation': 'new'})
            return '{"vpn_ok": true}'
        with patch.object(r, 'guard'), patch.object(r, 'inside', side_effect=probe):
            watchdog.tick({}, now=0)
        self.assertFalse((r.RUN / 'health.json').exists())

    def test_damaged_tunnel_is_repaired_before_probe(self):
        events = []
        with patch.object(r, 'guard', side_effect=r.Failure('broken')), \
             patch.object(r, 'recover_locked', side_effect=lambda *_: events.append('repair')), \
             patch.object(r, 'inside', side_effect=lambda *_ , **kw: events.append('probe') or '{"vpn_ok": true}'):
            watchdog.tick({}, now=0)
        self.assertEqual(events, ['repair', 'probe'])

    def test_probe_allows_readers_but_defers_destructive_changes(self):
        def probe(*args, **kwargs):
            with r.locked(shared=True):
                pass
            with self.assertRaises(r.Failure):
                with r.locked():
                    self.fail('writer raced live probe')
            return '{"dns_ok": true, "vpn_ok": true}'
        with patch.object(r, 'guard'), patch.object(r, 'inside', side_effect=probe):
            watchdog.tick({}, now=0)

    def test_stale_connected_status_is_not_reported_as_connected(self):
        r.atomic_json(r.RUN / 'health.json', {'generation': WANTED['generation'], 'state': 'connected',
                                             'timestamp': '2000-01-01T00:00:00+00:00'})
        with patch.object(r, 'namespaces', return_value={r.NS}), patch.object(r, 'guard', return_value={'peers': []}):
            result = r.status()
        self.assertEqual(result['state'], 'configured')
        self.assertTrue(result['health']['stale'])

    def test_background_refresh_keeps_selected_hostname_and_invalidates_old_health(self):
        changed = {**RELAY, 'endpoint': '192.0.2.9:51820'}
        other = {**RELAY, 'hostname': 'se-other-wg-002'}
        with patch.object(r, 'guard'), patch.object(r, 'inside', return_value='{}'), \
             patch.object(r.Mullvad, 'relays', return_value=[other, changed]), patch.object(r, 'recover_locked') as repair:
            watchdog.tick({'generation': WANTED['generation'], 'failures': 2}, now=0)
        current = r.target()
        self.assertEqual(current['relay'], changed)
        self.assertNotEqual(current['generation'], WANTED['generation'])
        repair.assert_called_once()


class MaintenanceTests(TemporaryState):
    def manifest(self, expected=None):
        code = self.base / 'code'
        code.mkdir()
        item = patch.object(r, 'CODE', code)
        item.start()
        self.patches.append(item)
        digest = installer.package_digest(ROOT)
        for name in (*installer.FILES, *('systemd/' + name for name in installer.UNITS)):
            target = code / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        r.atomic_json(code / 'manifest.json', {'version': installer.VERSION, 'package_digest': digest})
        info = installer.user_record(pwd.getpwuid(os.getuid()))
        r.atomic_json(r.DATA / 'installation.json', info)
        r.atomic_json(r.DATA / 'maintenance', {'operation': 'install', 'package_digest': expected or digest, 'installation': info})
        return code

    def test_active_maintenance_marker_is_never_cleared(self):
        r.atomic_json(r.DATA / 'maintenance', {'operation': 'install'})
        with installer.maintenance_lock():
            self.assertFalse(installer.recover_maintenance())
        self.assertTrue((r.DATA / 'maintenance').exists())

    def test_complete_abandoned_install_is_finalized(self):
        self.manifest()
        with patch.object(installer, 'finalize') as finish:
            self.assertTrue(installer.recover_maintenance())
        finish.assert_called_once()
        self.assertFalse((r.DATA / 'maintenance').exists())

    def test_incomplete_install_stays_blocked(self):
        code = self.manifest()
        (code / 'launch.py').write_text('damaged')
        with patch.object(installer, 'finalize') as finish, self.assertRaises(r.Failure):
            installer.recover_maintenance()
        finish.assert_not_called()
        self.assertTrue((r.DATA / 'maintenance').exists())

    def test_pre_exchange_crash_preserves_previous_verified_install(self):
        self.manifest(expected='new-not-yet-installed')
        with patch.object(installer, 'finalize'):
            self.assertTrue(installer.recover_maintenance())

    def test_abandoned_uninstall_is_not_silently_reversed(self):
        r.atomic_json(r.DATA / 'maintenance', {'operation': 'uninstall'})
        with self.assertRaises(r.Failure):
            installer.recover_maintenance()
        self.assertTrue((r.DATA / 'maintenance').exists())

    def test_atomic_code_exchange_keeps_previous_code(self):
        code = self.base / 'installed'
        code.mkdir()
        (code / 'old').write_text('previous package')
        with patch.object(r, 'CODE', code), patch.object(installer, 'SOURCE', ROOT):
            installer.copy_code(installer.package_digest(ROOT))
            self.assertEqual(installer.package_digest(code), installer.package_digest(ROOT))
        self.assertFalse((code / 'old').exists())
        self.assertEqual(len(list((r.DATA / 'retained-code').glob('*/old'))), 1)


class UpdateTests(unittest.TestCase):
    def archive(self, extra=None, omit=None):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name in updater.REQUIRED:
                if name == omit: continue
                info = tarfile.TarInfo('vpnrun-SHA/' + name)
                content = (ROOT / name).read_bytes()
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            if extra:
                archive.addfile(extra, io.BytesIO(b''))
        return stream.getvalue()

    def test_complete_package_extracts(self):
        with tempfile.TemporaryDirectory() as directory:
            updater.unpack(self.archive(), Path(directory))
            self.assertEqual((Path(directory) / 'vpnrun').read_bytes(), (ROOT / 'vpnrun').read_bytes())

    def test_license_only_upstream_cannot_replace_install(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                updater.unpack(self.archive(omit='runtime.py'), Path(directory))

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                updater.unpack(self.archive(extra=tarfile.TarInfo('vpnrun-SHA/../../outside')), Path(directory))

    def test_symlink_package_file_is_rejected(self):
        info = tarfile.TarInfo('vpnrun-SHA/runtime.py')
        info.type = tarfile.SYMTYPE
        info.linkname = '/etc/shadow'
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                updater.unpack(self.archive(extra=info, omit='runtime.py'), Path(directory))

    def test_duplicate_package_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                updater.unpack(self.archive(extra=tarfile.TarInfo('vpnrun-SHA/runtime.py')), Path(directory))

    def test_update_downloads_pinned_sha_and_preserves_installed_login(self):
        commit = 'a' * 40
        user = pwd.getpwuid(os.getuid())
        def read(path):
            return {'user': user.pw_name, 'uid': user.pw_uid} if path.name == 'installation.json' else {'revision': None}
        def install(command, **kwargs):
            self.assertEqual(command[0], '/bin/sh')
            self.assertEqual(command[-2:], ['--user', user.pw_name])
            stage = Path(command[1]).parent
            self.assertEqual(json.loads((stage / 'revision.json').read_text())['revision'], commit)
            self.assertEqual((stage / 'vpnrun').read_bytes(), (ROOT / 'vpnrun').read_bytes())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(os, 'geteuid', return_value=0), patch.object(r, 'read_json', side_effect=read), \
             patch.object(updater, 'download', side_effect=[json.dumps({'sha': commit}).encode(), self.archive()]) as download, \
             patch.object(subprocess, 'run', side_effect=install):
            self.assertEqual(updater.main([]), 0)
        self.assertEqual(download.call_args_list[1].args[0], 'https://codeload.github.com/scottmonster/vpnrun/tar.gz/' + commit)

    def test_current_revision_is_noop(self):
        commit = 'b' * 40
        user = pwd.getpwuid(os.getuid())
        def read(path):
            return {'user': user.pw_name, 'uid': user.pw_uid} if path.name == 'installation.json' else {'revision': commit}
        with patch.object(os, 'geteuid', return_value=0), patch.object(r, 'read_json', side_effect=read), \
             patch.object(updater, 'download', return_value=json.dumps({'sha': commit}).encode()) as download, \
             patch.object(subprocess, 'run') as install:
            self.assertEqual(updater.main([]), 0)
        download.assert_called_once()
        install.assert_not_called()

    def test_failed_download_never_invokes_installer(self):
        with patch.object(updater, 'download', side_effect=ValueError('offline')), patch.object(subprocess, 'run') as install:
            self.assertEqual(updater.main(['--install']), 1)
        install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
