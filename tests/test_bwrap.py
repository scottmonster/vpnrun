"""Exercise the actual unprivileged launcher/Bubblewrap boundary, without VPN access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bwrap') and os.geteuid() != 0, 'needs Bubblewrap and a normal login')
class LauncherIntegration(unittest.TestCase):
    def test_real_payload_receives_marker_and_private_resolver(self):
        with tempfile.TemporaryDirectory(prefix='vpnrun-launch-test-') as directory:
            dns = Path(directory)
            (dns / 'resolv.conf').write_text('nameserver 10.64.0.1\n')
            (dns / 'nsswitch.conf').write_text('hosts: files dns\n')
            with tempfile.TemporaryFile() as request:
                payload = "import os; from pathlib import Path; assert os.environ['VPNRUN']=='1'; assert 'HTTP_PROXY' not in os.environ; assert Path('/etc/resolv.conf').read_text()=='nameserver 10.64.0.1\\n'; print('PAYLOAD_OK')"
                request.write(json.dumps({'command': ['/usr/bin/python3', '-I', '-B', '-c', payload],
                                          'cwd': str(ROOT), 'env': {'VPNRUN': '0', 'HTTP_PROXY': 'http://invalid'}}).encode())
                request.seek(0)
                read_ready, write_ready = os.pipe()
                code = (f'import sys; sys.path.insert(0,{str(ROOT)!r}); import launch; '
                        f'original=launch.sandbox; launch.sandbox=lambda user,cwd,command: original(user,cwd,command,dns=__import__("pathlib").Path({str(dns)!r})); '
                        f'sys.argv=["launch.py",{str(request.fileno())!r},{str(write_ready)!r}]; launch.main()')
                try:
                    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', code],
                                            pass_fds=(request.fileno(), write_ready), capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), 'PAYLOAD_OK')
                    self.assertEqual(os.read(read_ready, 1), b'1')
                finally:
                    os.close(read_ready)
                    os.close(write_ready)
