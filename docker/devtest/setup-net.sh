#!/bin/sh
# Create the ogstun device the UPF/SMF tests expect (see docker/build/setup.sh).
set -e
if ! grep -q "ogstun" /proc/net/dev; then
    ip tuntap add name ogstun mode tun
fi
ip addr replace 10.45.0.1/16 dev ogstun
ip addr replace 2001:db8:cafe::1/48 dev ogstun
ip link set ogstun up
