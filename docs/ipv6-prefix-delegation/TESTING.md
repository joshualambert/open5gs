# Testing IPv6 Prefix Delegation

Everything runs in Docker; nothing is installed on the host. The containers
need `NET_ADMIN` and `/dev/net/tun` because the real UPF opens `ogstun`, and
MongoDB runs as a sidecar for the subscriber database.

## One-time setup

```bash
# Base image with the build dependencies (Ubuntu 24.04)
DIST=ubuntu TAG=noble docker compose -f docker/docker-compose.yml build base
```

## Build and run the suite

```bash
export HOST_UID=$(id -u) HOST_GID=$(id -g)
C="docker compose -f docker/devtest/docker-compose.yml"

$C run --rm build                 # meson setup + ninja into a named volume
$C run --rm test ipv6-pd          # the prefix-delegation suite (EPC + 5GC)
$C run --rm test                  # the whole Open5GS suite
$C run --rm test unit             # codec / pool unit tests only
$C down
```

Any arguments after `test` are passed to `meson test`. Logs land in the
build volume under `meson-logs/`; `$C run --rm shell` opens a shell in a
container with `ogstun` already configured (`./build/tests/ipv6-pd/ipv6-pd
-l` lists the individual cases, `... ipv6-pd epc-test -d` runs one with
debug logging).

## What the `ipv6-pd` suite does

`tests/ipv6-pd` starts the complete EPC and 5GC (MME, SGW-C/U, SMF, UPF,
HSS, PCRF, AMF, NRF, UDM, ...) from `configs/ipv6-pd.yaml`, then plays a
simulated eNB/UE (S1AP + NAS-EPS) and gNB/UE (NGAP + NAS-5GS) against them
and injects raw user-plane packets through GTP-U into the real UPF. The
DHCPv6 client side is an independent implementation in
`tests/common/dhcpv6.c`, so the server codec is cross-checked rather than
tested against itself. Every read on the S1AP/NGAP and GTP-U sockets is
bounded, so a missing answer fails the case instead of hanging the suite.

The `internet` DNN of the test configuration has three IPv6 subnets, all
with `prefix_delegation: 56`, in this order:

| Subnet | Purpose |
|---|---|
| `2001:db8:beef::/48`, range `2001:db8:beef:100::0-2001:db8:beef:1ff::0` | Dynamic pool 1 with exactly one block (`2001:db8:beef:100::/56`). The first dynamic UE of every case lands here. |
| `2001:db8:cafe::/48`, range `2001:db8:cafe:100::0-2001:db8:cafe:3fff::0` | Dynamic pool 2 (`2001:db8:cafe:100::/56` .. `2001:db8:cafe:3f00::/56`); the static subscriber `2001:db8:cafe:4200::1` is inside the subnet but outside the range. |
| `2001:db8:5a7c::/48`, `static: true` | Static-only subnet: no pool, per-session kernel routes. Deliberately *not* configured on `ogstun` (`docker/devtest/setup-net.sh` only adds the cafe and beef gateways). |

The SMF uses `dhcpv6.binding_policy: sticky`,
`dhcpv6.information_refresh_time: 600` and
`router_advertisement.link_layer_address: 02:00:00:00:01:01`.

Per RAT (EPC and 5GC), for IPv4v6 and IPv6-only sessions:

| Case | Checks |
|---|---|
| basic | RA: /64, M=0, O=1, A=1, L=0, RDNSS, plus the `router_advertisement` defaults pinned exactly (5.6): Source Link-Layer Address `02:00:00:00:01:01`, router lifetime 64800, hop limit 255. Solicit → Advertise and Request → Reply: Server-ID, Client-ID echo, xid, IAID, T1/T2 (300/480), one IAPREFIX = the /56 containing the RA /64 with lifetimes 600/1200, PD_EXCLUDE = RA /64, DNS. Echo request from an address inside the /56 but outside the /64 is answered (UPF uplink acceptance + downlink block lookup). |
| lifecycle | Renew → Reply, Rebind → Reply, Release → Status Success, Renew after Release → NoBinding. |
| no_exclude | Client without RFC 6603 gets the /57 half that does not contain the link /64; ping from it works. |
| rapid_commit | Solicit + Rapid Commit → Reply with Rapid Commit; prefix usable. |
| negative | Unicast Solicit → Advertise with UseMulticast; Request with a foreign Server-ID, Solicit carrying a Server-ID, random garbage and a truncated message → no reply and the NFs keep working; Information-request → DNS only; ping from a foreign /56 is dropped, ping from the own block still works. |
| two_ues | Two concurrent UEs get distinct /64 and /56. |
| reattach | Three attach/PD/detach cycles of the same UE (no leaked bindings or pool entries). |
| static_pd | Subscriber with static UE IPv6 `2001:db8:cafe:4200::1` (inside the dynamic cafe subnet, outside its range): RA /64 and delegated /56 are exactly `2001:db8:cafe:4200::/64` and `/56`, identical after re-attach; fallback half is `2001:db8:cafe:4280::/57`. Statics nested in a dynamic subnet keep resolving to that subnet. |

Second iteration (hardware findings, DESIGN section 5), also per RAT:

| Case | Checks |
|---|---|
| neighbour_discovery | 5.1: NS for the RA source (`ra.src`) from the UE link-local to the solicited-node group, from the UE global (SLAAC) address, and unicast to the gateway (NUD re-probe) each get a unicast NA: hop limit 255, R\|S\|O set, target = `ra.src`, Target Link-Layer Address `02:00:00:00:01:01`, destination = the NS source. Silence (1 s) for a DAD probe from `::` for the UE's own address, for a DAD-style probe from `::` for the gateway address, and for an NS whose target is `fe80::2`. The gateway still answers afterwards. |
| rs_unspecified | 5.7: RS from `::` → RA to `ff02::1` from the same router with the same /64, O=1, SLLA; a link-local RS afterwards still gets a unicast RA. |
| leaky_cpe | 5.2 (UPF): a UDP datagram (mDNS-like, port 5353) and an echo request from the UE link-local to `2001:db8:cafe::1` get no reply; a ping from the delegated prefix works right after each, and RS→RA and Renew→Reply from link-local keep working. |
| sticky_binding | 5.2 (SMF): client A binds; client B (another DUID) gets IA_PD `NoPrefixAvail` without a prefix on Solicit and Request, `NoBinding` on Renew; A's Renew still returns the same prefix; A releases (Success); B is then delegated the same block and can forward. |
| hx220 | 5.8: byte-exact replay of the HX220 Information-request → Reply with DNS and Information Refresh Time 600, no IA; replay of the HX220 Solicit → Advertise with IAID `0xd0b8f19d`, T1/T2 300/480, one `/57` (no PD_EXCLUDE requested); a Request built with the same DUID → Reply and forwarding works; a Solicit carrying IA_NA(1) → Advertise with the delegation and Status `NoAddrsAvail` inside the IA_NA. The test codec parses the Vendor-Class option (16) as unknown and option 32. |
| static_only | 5.3 + 5.5: static UE IPv6 `2001:db8:5a7c:4200::1` lands in the static-only subnet: RA /64 `2001:db8:5a7c:4200::/64`, block `/56`; `ip -6 route show proto 250` lists `2001:db8:5a7c:4200::/56` while attached and not after detach (twice, IPv4v6 then IPv6-only re-attach with identical prefixes); a ping from the delegated prefix is answered although nothing configured `2001:db8:5a7c::/48` on `ogstun`. |
| static_orphan | 5.3: static UE IPv6 `2001:db8:dead::1` (outside every subnet) is rejected, not routed into the wrong pool: EPC Attach Reject with EMM cause #17 (network failure) followed by UE Context Release; 5GC PDU Session Establishment Reject with 5GSM cause #67 in a DownlinkNASTransport, the UE stays registered and de-registers cleanly. |
| multi_pool | 5.4: UE1's block and delegated prefix are in `2001:db8:beef::/48`, UE2's in `2001:db8:cafe::/48`, both forward; after both detach a third UE lands in `2001:db8:beef::/48` again (no leak of the single block). |

Unit tests (`meson test unit`): `tests/unit/dhcpv6-test.c` (codec
round-trips, RFC 6603 example, rejection table, truncation at every offset,
random/mutated fuzz loops, undersized buffers, checksum vectors) and
`tests/unit/pfcp-ue-ip-test.c` (UE IP Address IE with IPv6D, pool block
generation with and without ranges, YAML validation).

## Sanitizers and fuzzing

```bash
MESON_SETUP_ARGS="-Db_sanitize=address,undefined -Db_lundef=false" \
OPEN5GS_BUILD_VOLUME=open5gs-asan-build $C run --rm build
OPEN5GS_BUILD_VOLUME=open5gs-asan-build $C run --rm test unit ipv6-pd
```

The DHCPv6 parser also has a libFuzzer target,
`tests/fuzzing/dhcpv6-message-fuzz.c`, built with `-Dfuzzing=true`
(see `tests/fuzzing/meson.build`).

## Testing with real hardware

1. Configure `prefix_delegation` on the SMF pool and route the pool subnet
   to the UPF host (see README.md).
2. Attach the CPE. In the SMF log look for `DHCPv6-PD delegated
   2001:db8:cafe:XX00::/56 ... to client DUID[...]`; in the UPF log the
   session line shows `IPv6[.../56]`.
3. On the LAN behind the CPE, hosts should get addresses from
   `2001:db8:cafe:XX01::/64` (or whichever /64 the CPE picks) and reach the
   internet. `tcpdump -ni ogstun ip6` on the UPF host shows the traffic.
4. Capture on the S1-U/N3 side (`tcpdump -ni any udp port 2152`) to see the
   DHCPv6 exchange inside GTP-U if the CPE misbehaves; Wireshark decodes
   GTP-U → IPv6 → UDP → DHCPv6.

## Validation status

Validated in Docker on Ubuntu 24.04 (Noble), 2026-09-10:

* Full Open5GS suite: 17/17 pass, including the new `ipv6-pd` suite
  (26 scenarios across EPC and 5GC, IPv4v6 and IPv6-only, static and
  dynamic delegation).
* `ipv6-pd` run three additional times back to back: no flakiness.
* AddressSanitizer + UndefinedBehaviorSanitizer: the `dhcpv6` and
  `pfcp-ue-ip` unit suites and the `ipv6-pd` integration suite are clean.
  No sanitizer finding points at any prefix-delegation source file
  (`lib/proto/dhcpv6.c`, `src/smf/dhcpv6.c`, `lib/gtp/util.c`,
  `src/upf/*`, `lib/pfcp/*`). Pre-existing UBSan notes in
  `lib/nas/*/ies.c` and `lib/asn1c/util/conv.c`, and a freeDiameter
  extension ODR-violation false positive, are unrelated to this work.
* The DHCPv6 message parser has a libFuzzer target
  (`tests/fuzzing/dhcpv6-message-fuzz.c`).

Hardware validation (Global Telecom Titan 4000, Nokia FastMile 5G-16A in
IP passthrough on an HX510) is performed separately following the "Testing
with real hardware" steps above.
