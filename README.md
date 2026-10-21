# vpnrun

Run selected CLI programs through Mullvad while everything else uses your normal
connection. Requires Linux/systemd, WireGuard, and unprivileged Bubblewrap user
namespaces. No Mullvad desktop app or Python packages needed.

## Install

With `curl` and Python 3.8+ installed, run as your normal login:

```sh
curl -fsSL https://raw.githubusercontent.com/scottmonster/vpnrun/master/bootstrap | sh
```

Or download/clone this repository and run `sh install`. The installer requests
sudo, installs missing networking tools (apt/dnf/pacman), and privately asks for
your Mullvad account number. It creates a dedicated device/key; an available
Mullvad device slot is required. Reinstalling reuses that identity.

## Use

```sh
vpnrun servers us-                  # List available servers
vpnrun switch EXACT-SERVER          # Select one hostname from the list
vpnrun -- ./script.sh arg1 arg2     # Launch through the VPN
vpnrun -- curl --max-time 10 https://am.i.mullvad.net/connected
vpnrun status                      # Configuration + background connectivity
vpnrun stop                        # Requires all tunnel programs to have exited
vpnrun update                      # Upgrade from GitHub master; asks for sudo
# vpnrun upgrade is an alias for update
vpnrun uninstall                   # Offers device revocation/credential removal
```

`vpnrun ./script.sh "$@"` also works. In a wrapper that has no further work, use
`exec vpnrun -- /absolute/path/script.sh "$@"`. All launched programs receive
`VPNRUN=1`; this is a convenience marker, not proof of connectivity. `vpnctl`
remains an alias for control commands. The old `vpn-run` name is removed on upgrade.
Use `--` to launch a program named `update`, `status`, or another reserved command.

One server is shared by all tunnel programs. Switching changes their exit IP and
may break existing connections. No automatic switch to a different server occurs.
The updater requires tunnel programs to exit first and preserves credentials,
server choice, and settings. Install/update commands become available from GitHub
once the source is published there.

## Recovery and startup

The control socket and watchdog start at boot. The watchdog restores the last
accepted server, repairs interrupted configuration, and checks DNS/connectivity
in the background. `stop` persists across reboot; the next explicit launch or
`switch` starts the tunnel again. Programs themselves are never auto-restarted.
A request-service crash or client disconnect ends its associated program.

Healthy launches perform local isolation checks only: no API calls, connectivity
probes, handshake waits, or retry sleeps. Concurrent healthy launches share a read
lock. Cold starts require local tunnel creation. Damaged/busy configuration fails
promptly by default while the watchdog repairs it; optional waiting is configurable.
Connection loss blocks network access rather than falling back to the host network.

Settings are root-only JSON; edit with:

```sh
sudoedit /var/lib/inverse-split-tunnel/settings.json
```

Defaults: `launch_wait_ms: 0`, `check_interval: 15` seconds, `probe_timeout: 3`
seconds, `failure_threshold: 3`, `max_backoff: 120` seconds. The watchdog reloads
settings and uses bounded retries. Status includes the time of the last probe;
configured state alone does not prove connectivity. A damaged installation that
cannot be verified requires rerunning `sh install` from a trusted checkout.

## Isolation and troubleshooting

Programs run as your login in a network namespace with WireGuard-only routes and
a firewall; DNS goes through Mullvad. Bubblewrap hides host `/run`, `/tmp`, display,
D-Bus, and proxy settings. Home remains writable; most other paths are read-only.
This targets trusted CLI programs, not hostile code, GUI apps, or GPU workloads.
Host VPN/firewall rules can still block the encrypted WireGuard transport.

Credentials remain root-only in `/var/lib/inverse-split-tunnel/identity.json`.
The internal directory and systemd names retain `inverse-split-tunnel` for upgrade
compatibility. Never copy installed state or credentials into this repository.
Errors go to the terminal/journal, without diagnostic bundles or account/key data.

```sh
sudo journalctl -u inverse-split-tunnel-watchdog.service -u 'inverse-split-tunnel@*' -b
sudo systemctl status inverse-split-tunnel.socket inverse-split-tunnel-watchdog.service
```

See [changes](CHANGELOG.md) and [testing](TESTING.md) for details.
Licensed under [MIT](LICENSE).
