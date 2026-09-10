#!/bin/bash
# Run the meson test-suite (or a subset) against the sidecar MongoDB.
# Any arguments are forwarded to `meson test`, e.g. `attach ipv6-pd`.
set -euo pipefail
/open5gs/docker/devtest/setup-net.sh

# Wait for MongoDB.
for i in $(seq 1 60); do
    if bash -c 'exec 3<>/dev/tcp/mongodb/27017' 2>/dev/null; then
        break
    fi
    sleep 1
done

cd /open5gs/build
rc=0
meson test --no-rebuild -v -t 5 "$@" || rc=$?

# meson test writes logs as root; hand them back to the host user.
chown -R "${HOST_UID}:${HOST_GID}" /open5gs/build/meson-logs 2>/dev/null || true
exit $rc
