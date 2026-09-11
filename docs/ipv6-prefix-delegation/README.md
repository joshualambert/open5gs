# IPv6 Prefix Delegation (DHCPv6-PD) in Open5GS

This fork adds a standards-based DHCPv6 Prefix Delegation server to the
Open5GS SMF (PGW-C) and the matching forwarding logic to the UPF (PGW-U), so a
UE that is a router (a 5G/LTE fixed-wireless CPE, a phone in tethering mode,
an industrial gateway) can obtain a whole IPv6 prefix for the LAN behind it.
It works for 4G (EPC, S1AP/GTPv2) and 5G (5GC, NGAP/SBI) sessions alike.

* Design notes and the exact protocol behaviour: [DESIGN.md](DESIGN.md).
* Test procedure (everything runs in Docker): [TESTING.md](TESTING.md).

## How it works in one picture

```
   LAN (2001:db8:cafe:1201::/64, :1202::/64, ...)          IPv6 Internet
        │                                                        │
   ┌────┴─────┐   PDN link  2001:db8:cafe:1200::/64 (SLAAC)  ┌───┴───┐
   │ CPE / UE │ ◄───────── RA (M=0 O=1 A=1 L=0, RDNSS) ───── │  SMF  │ DHCPv6 server
   │ DHCPv6   │ ── Solicit(IA_PD, ORO=[DNS, PD_EXCLUDE]) ──► │(PGW-C)│ (delegating router)
   │ client   │ ◄── Advertise/Reply IA_PD 2001:db8:cafe:1200::/56 ── │       │
   └────┬─────┘        + PD_EXCLUDE 2001:db8:cafe:1200::/64  └───┬───┘
        │ GTP-U                                                  │ PFCP (UE IP Address IE, IPv6D, PD bits = 8)
   ┌────┴─────┐                                              ┌───┴───┐
   │ eNB/gNB  │ ════════════════ N3 / S1-U ══════════════════│  UPF  │ routes 2001:db8:cafe:1200::/56 ↔ tunnel
   └──────────┘                                              └───────┘
```

1. At attach / PDU session establishment the SMF allocates one **network
   prefix** per session from the IPv6 pool, e.g. a `/56`. The lowest `/64`
   inside it is the normal SLAAC prefix the UE already gets today (PAA /
   PDU address / Router Advertisement). Nothing changes for UEs that never
   ask for a delegated prefix.
2. The SMF tells the UPF the size of the prefix in the PFCP *UE IP Address*
   IE (`IPv6D` flag, TS 29.244 §8.2.62), so the UPF forwards every downlink
   packet for the whole `/56` into the tunnel and accepts uplink packets from
   any source inside it.
3. The UE's DHCPv6 client sends Solicit/Request to `ff02::1:2`. The UPF
   steers those packets (like Router Solicitations) to the SMF, which acts
   as the DHCPv6 server per RFC 8415 and returns the prefix:
   * If the client announced RFC 6603 support (`OPTION_PD_EXCLUDE` in its
     ORO), it receives the full `/56` with the link `/64` excluded. This is
     the 3GPP way (TS 23.401 §5.3.1.2.2, TS 23.501 §5.8.2.2.4, TS 29.061
     §11.2.1.3.5).
   * Otherwise it receives the half of the block that does not contain the
     link `/64`, e.g. `2001:db8:cafe:1280::/57`, as a plain RFC 8415
     delegation.
4. Renew/Rebind refresh the lifetimes, Release gives the prefix back, and the
   whole block is freed when the session is released.

## Configuration

### SMF (`smf.yaml`)

```yaml
smf:
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
    - subnet: 2001:db8:cafe::/48
      gateway: 2001:db8:cafe::1
      prefix_delegation: 56        # one /56 per session; the /64 SLAAC prefix
                                   # is the first /64 of it (1..63, omit = off)
  dns:
    - 8.8.8.8
    - 2001:4860:4860::8888         # advertised via RA RDNSS and DHCPv6
  dhcpv6:                          # all keys optional
    preferred_lifetime: 3600       # seconds (default 3600)
    valid_lifetime: 7200           # seconds (default 7200, >= preferred)
    t1: 1800                       # default 0.5 * preferred_lifetime
    t2: 2880                       # default 0.8 * preferred_lifetime
    rapid_commit: true             # Solicit+Rapid Commit -> Reply (default true)
    preference: 0                  # OPTION_PREFERENCE (default 0 = omitted)
    # duid: 00:04:...              # server DUID (hex); default: stable DUID-UUID
```

### UPF (`upf.yaml`)

The UPF learns the prefix length from PFCP, so no UPF configuration is
required. If the UPF allocates addresses from its own pool (`session:` in
`upf.yaml` without an SMF pool), add the same `prefix_delegation: 56` to
its IPv6 subnet.

### Pool sizing

| Pool | `prefix_delegation` | Sessions |
|---|---|---|
| `/48` | off (`/64`) | 65 536 |
| `/48` | 60 | 4 096 |
| `/48` | 56 | 256 |
| `/40` | 56 | 65 536 |

Use `range:` (see `configs/open5gs/smf.yaml.in`) to carve the dynamic pool;
ranges are aligned to block boundaries automatically.

### Static delegated prefixes (per subscriber)

Give the subscriber a static **UE IPv6 Address** (WebUI → Subscriber →
Session → UE IPv6 Address, or `session.ue.ipv6` in MongoDB), for example
`2001:db8:cafe:4200::1`. The SMF derives:

* link prefix `2001:db8:cafe:4200::/64` (as today),
* delegated block `2001:db8:cafe:4200::/56` (address masked to the pool's
  `prefix_delegation` length).

Both are identical on every re-attach. Keep static blocks outside the dynamic
`range:` of the pool; as a safety net the UPF refuses a session whose block
is already owned by another session.

### Worked example: one static block per subscriber, shared by two APNs

Requirement: a subscriber's static `/56` is the same whether the SIM is on
the `edge` APN (`ogstun2`) or the `public` APN (`ogstun3`); dynamic
subscribers draw from a per-APN pool. Declare the static region once per
APN as a `static: true` subnet and keep the dynamic pool separate:

```yaml
smf:                                  # identical `session:` list in upf.yaml
  session:
    # dynamic blocks for edge
    - subnet: 2602:f815:ff::/48
      gateway: 2602:f815:ff::1
      dnn: edge
      dev: ogstun2
      prefix_delegation: 56
    # per-subscriber statics: same region on every APN, different tun
    - subnet: 2602:f815:f0::/45
      dnn: edge
      dev: ogstun2
      prefix_delegation: 56
      static: true
    - subnet: 2602:f815:f0::/45
      dnn: public
      dev: ogstun3
      prefix_delegation: 56
      static: true
```

* A `static: true` subnet has no dynamic pool. It is only ever selected by
  containment of the subscriber's static UE IPv6 address, and it carries its
  own `prefix_delegation` (it need not match the dynamic pool's).
  `gateway:` is optional for it.
* Precedence for a static address: `static: true` subnets of the DNN first,
  then dynamic subnets of the DNN that contain the address (so today's
  practice of keeping statics inside a dynamic subnet but outside its
  `range:` keeps working), then DNN-less subnets in the same order. An
  address inside no subnet rejects the session with a logged error instead
  of guessing a pool.
* For every session in a `static: true` subnet the UPF installs a kernel
  route for the **block** (`/56` here, not the `/64`) to that subnet's `dev`
  (rtnetlink, protocol 250, flushed at UPF start, removed at session
  release). Longest match does the rest: with `2602:f815:f0::1/44` on
  `ogstun2`, a public-APN session's `/56` route to `ogstun3` wins for that
  block while it exists.
* Sticky DHCPv6 bindings are per PDN session and die with it (Release,
  detach, re-attach, SMF/UPF restart). Under IP passthrough, swapping only the
  LAN router (new DUID) without the CPE re-attaching leaves the old binding
  in place until the old router has been silent past T2 (default 0.8 x
  `preferred_lifetime`, 2880 s) or the binding's `valid_lifetime` expires; a
  subscriber kick (Cancel-Location → re-attach) clears it immediately.

### N6 routing

The whole pool subnet (`2001:db8:cafe::/48` above) must be routed to the UPF
host and the UPF host must forward it to `ogstun`, exactly as for the `/64`
case today (`sysctl net.ipv6.conf.all.forwarding=1`, the `ip addr add
2001:db8:cafe::1/48 dev ogstun` from the quick-start guide). No per-prefix
routes are needed: everything inside the pool is delivered to `ogstun` and
the UPF picks the tunnel by longest match.

## Router Advertisement changes

The RA sent by the SMF now follows TS 29.061 §11.2.1.3.2 and RFC 8106:

| Field | Before | Now |
|---|---|---|
| M flag | 0 | 0 |
| O flag | 0 | 1 when the session has a delegated block or IPv6 DNS is configured |
| Prefix Information A flag | 1 | 1 |
| Prefix Information L flag | 1 | 0 (the 3GPP link is point-to-point; no on-link determination) |
| RDNSS option | absent | present when `dns:` contains IPv6 servers |
| Prefix lifetimes | infinite | infinite |

The Prefix Information option stays the first option, so existing UEs and
tools that only read the first option are unaffected.

## Client interoperability notes

* **OpenWrt / odhcp6c** (`option reqprefix '56'` or `auto`) supports
  RFC 6603 and receives the full `/56` with the `/64` excluded.
* **ISC dhclient / dhcpcd / Windows / most consumer CPEs** do not send
  `OPTION_PD_EXCLUDE`; they receive the `/57` half. Prefix-length hints
  (RFC 8168) are accepted but the size is operator policy.
* **IP passthrough / bridge mode CPEs** (for example Nokia FastMile 5G
  gateways in IP passthrough towards a LAN router): the LAN router is the
  DHCPv6 client. The UPF accepts DHCPv6 from any link-local source inside the
  tunnel, so the router does not need to use the 3GPP-assigned interface
  identifier. Renew traffic is unicast to the SMF link-local address that
  sourced the RA; the UPF steers it to the SMF as well.
* Clients that lose state and Solicit again get the same prefix (it belongs
  to the PDN connection, not to the DUID); a client with a new DUID replaces
  the old binding, which is logged.

## Logging and troubleshooting

* SMF: `ogs_info` when a delegation is committed (`DHCPv6-PD ... committed
  2001:db8:cafe:1200::/56 ...`) and released; per-message detail at debug
  level (`logger.level: debug`, domain `smf`).
* UPF: the session log line shows `IPv6[2001:db8:cafe:1200::/56]` when a
  block is installed; uplink packets from outside the block are dropped
  with `Source IPv6[...] is not in the session's prefix`.
* No Advertise? Check (1) the RA arrives and has O=1, (2) the SMF pool has
  `prefix_delegation`, (3) the UPF log shows the block, (4) the client sends
  to `ff02::1:2` from a link-local address.
* `NoPrefixAvail` in the Advertise means the session has no block (pool
  without `prefix_delegation`, or the pool is exhausted at attach time —
  the attach itself would then fail).

## What is not implemented

* DHCPv6 address assignment (IA_NA/IA_TA): the SMF answers `NoAddrsAvail`;
  3GPP uses SLAAC for the UE address.
* DHCPv6 relay to an external server, Reconfigure, authentication options.
* Multiple delegated prefixes per session or per-subscriber prefix lengths
  (the length is per pool).
* RADIUS/Diameter `Delegated-IPv6-Prefix` signalling towards a PCRF/AAA.
