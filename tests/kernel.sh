#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VPNRUN_TEST_PARENT_NET=$(stat -Lc %i /proc/self/ns/net)
VPNRUN_TEST_PARENT_MNT=$(stat -Lc %i /proc/self/ns/mnt)
export VPNRUN_TEST_PARENT_NET VPNRUN_TEST_PARENT_MNT
exec unshare --user --map-root-user --mount --net --pid --fork --mount-proc \
    python3 -I -B "$base/tests/kernel_checks.py"
