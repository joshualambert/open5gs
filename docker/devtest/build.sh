#!/bin/bash
# Configure (first time only) and build Open5GS into /open5gs/build.
# Runs as root only long enough to hand the build volume to the host user,
# then drops privileges so nothing root-owned ends up in the source tree.
set -euo pipefail
cd /open5gs
if [ "$(id -u)" = "0" ]; then
    chown "${HOST_UID}:${HOST_GID}" /open5gs/build
    exec setpriv --reuid="${HOST_UID}" --regid="${HOST_GID}" --clear-groups "$0" "$@"
fi
if [ ! -f build/build.ninja ]; then
    # shellcheck disable=SC2086
    meson setup build ${MESON_SETUP_ARGS} "$@"
fi
jobs="${NINJA_JOBS:-0}"
if [ "${jobs}" = "0" ]; then
    exec ninja -C build
fi
exec ninja -C build -j "${jobs}"
