# Changes

## Unreleased

- Resolve bare application names through `PATH`, falling back to the current
  directory when no executable is found there (`vpnrun vt` tries `./vt`).

## 0.2.0

- Rename `vpn-run` to `vpnrun`; set `VPNRUN=1` in every launched program.
  Keep `vpnctl` for existing control-command usage.
- Add `vpnrun update` / `upgrade` and a GitHub bootstrap installer. Updates use
  an exact upstream commit and validate the package before invoking installation.
- Save one durable requested server; reconcile its peer after interrupted changes.
- Add a systemd-supervised watchdog for local repair, background DNS/VPN checks,
  outage reporting, socket recovery, and bounded retries without server failover.
- Persist intentional stop across reboot; resume on explicit launch or switch.
- Keep network probes off the startup path. Default additional recovery wait is
  zero; healthy launches use shared locks and perform local safety checks only.
- Validate interface state, addresses, both default routes, firewall, resolver,
  local WireGuard identity and selected peer before launching.
- Preserve active processes during repair; refuse destructive namespace rebuilds
  while programs remain. Programs are never automatically relaunched.
- Use atomic code exchange, a maintenance ownership lock, and verified recovery
  after an interrupted update. Preserve the existing dedicated Mullvad identity.
- Retain terminal-input fixes and terminal/journal errors without fault bundles.
- Add local regression and real sandbox/kernel checks; shorten the README.
