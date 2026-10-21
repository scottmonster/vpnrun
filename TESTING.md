# Testing

Run from the repository root:

```sh
python3 -B -m unittest discover -s tests -v
sh tests/kernel.sh
```

The first command runs offline regression tests. The real launcher test requires
Bubblewrap and a normal login; it checks the actual sandbox, environment marker,
and resolver mounts. It is skipped when those prerequisites are absent.

The kernel script requires Linux user/network/mount namespaces, iproute2,
WireGuard, nftables, and ping. It refuses to run without separate network and
mount namespaces, overlays `/run` and `/etc`, and uses disposable keys and IPs.
It never changes host networking/services, reads installed credentials, or
contacts a Mullvad account. Connectivity probes are stubbed in the kernel tests.

Verified locally on 2026-10-21:

- 49 regression/integration tests, including command parsing, descriptor
  passing, marker enforcement, lock contention, stale health results,
  maintenance recovery, atomic code exchange, and SHA-pinned update handling.
- Real WireGuard creation and IPv4/IPv6 defaults, firewall and resolver setup.
- Damaged setup rejected promptly; repair preserved a running process and its
  namespace. Interrupted server selection restored the saved requested peer.
- A reachable direct-route positive control worked with the firewall removed;
  the same direct route was blocked with the firewall installed and VPN down.
- Loss of volatile namespace state was repaired from disk, simulating reboot.
  Intentional stop was preserved by the watchdog.
- Python/shell syntax checks and `systemd-analyze verify` passed.

Healthy launch preparation measured 11.14 ms median / 13.84 ms p95 over 30
samples, versus 11.72 ms / 15.36 ms for the previous launch preparation on the
same machine. This measures local checks/locking only, not systemd activation,
Bubblewrap, application startup, or cold namespace creation. Reproduce a baseline
comparison by setting `VPNRUN_TEST_BASELINE` to the old runtime.py before running
the kernel script. Timing varies with hardware and load.

Not established by these checks: installing this revision into the host,
live account registration/handshake, an actual host reboot, or downloading and
installing this revision from GitHub before publication. After installing, check:

```sh
vpnrun switch EXACT-SERVER
vpnrun -- curl --fail --max-time 10 https://am.i.mullvad.net/connected
vpnrun status
```

Then verify boot restoration, intentional stop, and watchdog restart on the host.
