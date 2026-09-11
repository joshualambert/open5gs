# IPv6 Prefix Delegation (DHCPv6-PD) — Design Notes

This document is the engineering design for DHCPv6 Prefix Delegation in
Open5GS. It is written so that the individual pieces (address pool, PFCP,
SMF DHCPv6 server, UPF forwarding, tests) can be implemented independently
against a fixed set of interfaces. The user-facing guide lives in
`README.md` next to this file.

## 1. Standards followed

| Spec | What we take from it |
|---|---|
| IETF RFC 8415 (DHCPv6) | Message/option formats, server message validation (§16), server behaviour for Solicit/Request/Renew/Rebind/Release/Information-request (§18.3), IA_PD (§21.21), IA Prefix (§21.22), Status Codes (§21.13), Rapid Commit (§21.14), DNS option (RFC 3646 §3), T1/T2 recommendations. |
| IETF RFC 6603 (Prefix Exclude) | `OPTION_PD_EXCLUDE` (67) so a delegated prefix may contain the /64 already in use on the UE link. |
| IETF RFC 8168 (Prefix-length hints) | Client hints are accepted and logged; the delegated size is operator policy. |
| IETF RFC 4861 / 4862 / 8106 | Router Advertisement: M=0, O flag, A=1, L=0, RDNSS option. |
| 3GPP TS 29.061 §11.2.1.3.2 / §11.2.1.3.4 / §11.2.1.3.5 | SLAAC on the PDN link, RA configuration variables (infinite prefix lifetime, L-flag cleared, M-flag cleared), *"a single network prefix shorter than the default /64 prefix may be assigned to a PDN connection. In this case, the /64 default prefix used for IPv6 stateless autoconfiguration will be allocated from this network prefix; the remaining address space from the network prefix can be delegated to the PDN connection using prefix delegation"*. |
| 3GPP TS 23.401 §5.3.1.2.2, TS 23.501 §5.8.2.2.4 | The UE is the Requesting Router; the PGW-C/SMF is the Delegating Router (DHCPv6 server). If the UE supports prefix exclusion and the delegated prefix contains the /64 of the PDN connection, RFC 6603 exclusion shall be used. |
| 3GPP TS 29.244 §5.14, §8.2.62 | PFCP UE IP Address IE: `IPv6D` flag + *IPv6 Prefix Delegation Bits* = number of bits below /64 that belong to the delegated network prefix ("if /60 prefix is used the value is 4"). The UP function matches downlink packets on the whole network prefix. |

## 2. Address model

One **network prefix** ("block") of length `L` (`prefix_delegation: L`,
1 ≤ L ≤ 63, typically 56 or 60) is allocated per PDN connection / PDU
session from the configured IPv6 pool. Inside the block:

```
block  = 2001:db8:cafe:1200::/56        (L = 56, the whole thing belongs to this session)
link   = 2001:db8:cafe:1200::/64        (first /64 of the block, advertised in the RA / PAA)
```

* For dynamically allocated entries the link /64 is the **lowest** /64 of
  the block. For static entries (see 2.1) it can be any /64 inside the block.
  The interface identifier sent to the UE in the PAA / PDU address is
  unchanged.
* DHCPv6-PD delegates the remainder of the block:
  * client sent `OPTION_PD_EXCLUDE` in its ORO (RFC 6603): one IA Prefix
    `block/L` with `OPTION_PD_EXCLUDE = link/64`.
  * otherwise (RFC 3633 fallback): one IA Prefix `/(L+1)` covering the
    **half of the block that does not contain the link /64** (for dynamic
    entries that is always the upper half, `block + 2^(63-L)`). Example:
    `2001:db8:cafe:1280::/57` for block `2001:db8:cafe:1200::/56` with link
    `2001:db8:cafe:1200::/64`.
* The block is released with the session; the DHCPv6 binding never outlives
  the PDN connection. Nothing needs a timer on the server side.
* Pool arithmetic is done on the 64-bit prefix as an integer; entry `i` of
  the pool is `base + (i << (64 - L))`. Blocks that contain the subnet
  address or the configured gateway are skipped. `range:` low/high are
  aligned to block boundaries (low up, high down).
* `prefix_delegation` absent or `0` ⇒ `L = 64` ⇒ exactly today's behaviour.

### 2.1 Static delegated prefixes (per subscriber)

A subscriber with a static UE IPv6 address (WebUI "UE IPv6 Address",
`session.ue.ipv6` in MongoDB, delivered today via S6a to the MME → PAA →
SMF for 4G and via Nudm `staticIpAddress` for 5G) keeps today's behaviour
for the link /64 and additionally gets a **static delegated prefix**:

```
static address  2001:db8:cafe:4200::1        (pool prefix_delegation: 56)
link /64        2001:db8:cafe:4200::/64
block           2001:db8:cafe:4200::/56      = address masked to L, never changes
```

* The block is derived by masking the static address to the subnet's
  `prefix_delegation` length; nothing new has to be stored per subscriber
  and the prefix is identical on every re-attach.
* Static blocks must not overlap the dynamic pool: operators keep the dynamic
  `range:` away from the static blocks (same rule as for static IPv4 today).
  As a safety net the UPF rejects a session whose block is already owned by
  another session (extension of `upf_sess_ue_ip_conflict()`), and the SMF
  logs an error if a static link /64 is already in use.
* The link /64 of a static entry may sit anywhere in the block, hence the
  "half not containing the link /64" fallback rule above.

Capacity: a `/48` pool gives 65 536 sessions at L=64, 256 at L=56, 4 096 at
L=60. Operators wanting PD at scale should configure e.g. a `/40`.

## 3. Interfaces between the pieces

### 3.1 `lib/pfcp` (pool + PFCP IE)

```c
/* ogs_pfcp_subnet_t */
uint8_t pd_prefixlen;   /* 0 = disabled, else 1..63 (IPv6 subnets only) */

/* Effective prefix length of an IPv6 pool entry: subnet->pd_prefixlen or 64 */
uint8_t ogs_pfcp_ue_ip_prefixlen(const ogs_pfcp_ue_ip_t *ue_ip);

/* YAML: session[].prefix_delegation: <int 1..63> (parsed in lib/pfcp/context.c) */

/* ogs_pfcp_ue_ip_addr_t – wire layout is unchanged for existing users, one
 * trailing octet ("IPv6 Prefix Delegation Bits") is appended when ipv6d=1 */
typedef struct ogs_pfcp_ue_ip_addr_s {
    ... flags (spare, ip6pl, chv6, chv4, ipv6d, sd, ipv4, ipv6) ...
    union {
        uint32_t addr;
        struct {
            uint8_t addr6[OGS_IPV6_LEN];
            uint8_t ipv6_prefix_delegation_bits;
        } __attribute__ ((packed));
        struct {
            uint32_t addr;
            uint8_t addr6[OGS_IPV6_LEN];
            uint8_t ipv6_prefix_delegation_bits;
        } __attribute__ ((packed)) both;
    };
} __attribute__ ((packed)) ogs_pfcp_ue_ip_addr_t;

/* Set IPv6D + delegation bits (prefixlen < 64) or clear them (== 64).
 * Adjusts *len. Returns OGS_OK / OGS_ERROR (bad prefixlen / no ipv6). */
int ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(
        ogs_pfcp_ue_ip_addr_t *addr, int *len, uint8_t prefixlen);
/* Returns 64 when IPv6D is not set; validates len and range, 0 on error. */
uint8_t ogs_pfcp_ue_ip_addr_ipv6_prefixlen(
        const ogs_pfcp_ue_ip_addr_t *addr, int len);
```

Encoding on the wire (TS 29.244 8.2.62): flags(1) [IPv4(4)] [IPv6(16)]
[PD-bits(1) if IPv6D] [prefix-length(1) if IP6PL]. We never set IP6PL.

### 3.2 `lib/proto/ogs-dhcpv6.h` (codec, shared by SMF, unit tests, fuzzer)

Pure functions, no allocation, strict bounds checking, unknown options are
skipped, duplicated singleton options and truncated options make the parse
fail. Max sizes are compile-time constants so a hostile UE cannot make the
SMF allocate.

```c
#define OGS_DHCPV6_CLIENT_PORT 546
#define OGS_DHCPV6_SERVER_PORT 547
/* msg types */ OGS_DHCPV6_SOLICIT 1, ADVERTISE 2, REQUEST 3, CONFIRM 4, RENEW 5,
   REBIND 6, REPLY 7, RELEASE 8, DECLINE 9, RECONFIGURE 10, INFORMATION_REQUEST 11
/* options */ CLIENTID 1, SERVERID 2, IA_NA 3, IA_TA 4, IAADDR 5, ORO 6, PREFERENCE 7,
   ELAPSED_TIME 8, STATUS_CODE 13, RAPID_COMMIT 14, RECONF_ACCEPT 20,
   DNS_SERVERS 23, DOMAIN_LIST 24, IA_PD 25, IAPREFIX 26, PD_EXCLUDE 67,
   SOL_MAX_RT 82, INF_MAX_RT 83
/* status */ SUCCESS 0, UNSPEC_FAIL 1, NO_ADDRS_AVAIL 2, NO_BINDING 3,
   NOT_ON_LINK 4, USE_MULTICAST 5, NO_PREFIX_AVAIL 6
#define OGS_DHCPV6_MAX_DUID_LEN 130
#define OGS_DHCPV6_MAX_NUM_OF_IA_PD 4
#define OGS_DHCPV6_MAX_NUM_OF_IA_NA 4
#define OGS_DHCPV6_MAX_NUM_OF_IAPREFIX 4
#define OGS_DHCPV6_MAX_NUM_OF_ORO 32
#define OGS_DHCPV6_MAX_NUM_OF_DNS 4
#define OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN 64

typedef struct ogs_dhcpv6_duid_s { uint16_t len; uint8_t data[OGS_DHCPV6_MAX_DUID_LEN]; } ogs_dhcpv6_duid_t;
typedef struct ogs_dhcpv6_status_s { bool presence; uint16_t code; char message[OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN+1]; } ogs_dhcpv6_status_t;
typedef struct ogs_dhcpv6_iaprefix_s {
    uint32_t preferred_lifetime, valid_lifetime;
    uint8_t prefixlen; uint8_t prefix[OGS_IPV6_LEN];
    struct { bool presence; uint8_t prefixlen; uint8_t prefix[OGS_IPV6_LEN]; } pd_exclude;
} ogs_dhcpv6_iaprefix_t;
typedef struct ogs_dhcpv6_ia_pd_s {
    uint32_t iaid, t1, t2;
    int num_of_prefix; ogs_dhcpv6_iaprefix_t prefix[OGS_DHCPV6_MAX_NUM_OF_IAPREFIX];
    ogs_dhcpv6_status_t status;
} ogs_dhcpv6_ia_pd_t;
typedef struct ogs_dhcpv6_ia_na_s { uint32_t iaid, t1, t2; ogs_dhcpv6_status_t status; } ogs_dhcpv6_ia_na_t;
typedef struct ogs_dhcpv6_message_s {
    uint8_t msg_type; uint32_t transaction_id;   /* 24 bit */
    ogs_dhcpv6_duid_t client_id, server_id;      /* len == 0 → absent */
    int num_of_ia_pd; ogs_dhcpv6_ia_pd_t ia_pd[OGS_DHCPV6_MAX_NUM_OF_IA_PD];
    int num_of_ia_na; ogs_dhcpv6_ia_na_t ia_na[OGS_DHCPV6_MAX_NUM_OF_IA_NA];
    bool ia_ta_presence;                         /* IA_TA seen (we only need to know) */
    int num_of_oro; uint16_t oro[OGS_DHCPV6_MAX_NUM_OF_ORO];
    bool rapid_commit, reconf_accept;
    struct { bool presence; uint16_t value; } elapsed_time;
    struct { bool presence; uint8_t value; } preference;
    ogs_dhcpv6_status_t status;                  /* top-level */
    int num_of_dns; uint8_t dns[OGS_DHCPV6_MAX_NUM_OF_DNS][OGS_IPV6_LEN];
    uint32_t sol_max_rt, inf_max_rt;             /* 0 = absent */
} ogs_dhcpv6_message_t;

int  ogs_dhcpv6_parse(ogs_dhcpv6_message_t *msg, const uint8_t *data, size_t len); /* OGS_OK/OGS_ERROR */
int  ogs_dhcpv6_build(const ogs_dhcpv6_message_t *msg, uint8_t *buf, size_t buflen); /* bytes or -1 */
bool ogs_dhcpv6_oro_contains(const ogs_dhcpv6_message_t *msg, uint16_t code);
const char *ogs_dhcpv6_msg_type_name(uint8_t type);
const char *ogs_dhcpv6_status_name(uint16_t code);
```

Also added: `uint16_t ogs_in6_cksum(const uint8_t *src, const uint8_t *dst,
uint8_t nxt, const void *payload, size_t len)` in `lib/gtp/util.h` (IPv6
pseudo-header checksum, used for UDP/ICMPv6 by the SMF and by the tests).

### 3.3 SMF

Configuration (`smf.yaml`):

```yaml
smf:
  session:
    - subnet: 2001:db8:cafe::/48
      gateway: 2001:db8:cafe::1
      prefix_delegation: 56        # NEW: per-session network prefix length
  dhcpv6:                          # NEW, all optional
    duid: 00:04:2c:0d:…            # server DUID (hex, ':' allowed). Default: DUID-UUID derived from
                                   # SHA-256 of the SMF PFCP node address (stable across restarts)
    preferred_lifetime: 3600       # seconds, default 3600
    valid_lifetime: 7200           # seconds, default 7200 (must be >= preferred)
    t1: 1800                       # default 0.5 * preferred_lifetime
    t2: 2880                       # default 0.8 * preferred_lifetime
    rapid_commit: true             # answer Solicit+RapidCommit with Reply (default true)
    preference: 0                  # OPTION_PREFERENCE value (default 0 → option omitted)
```

Per session state (`smf_sess_t.dhcpv6`):

```c
typedef struct smf_dhcpv6_binding_s {
    bool active;                 /* a Request/Rapid-commit committed the delegation */
    ogs_dhcpv6_duid_t client_id; /* DUID of the requesting router */
    uint32_t iaid;
    bool pd_exclude;             /* client supports RFC 6603 */
    ogs_time_t bound_at;         /* last (re)binding time, for logging/expiry */
} smf_dhcpv6_binding_t;
```

Server behaviour (all replies carry Server-ID + echoed Client-ID and copy the
transaction-id; source = SMF link-local used for RAs, dst = packet source,
UDP 547 → 546, hop limit 255):

| Received | Validation (§16) | Action |
|---|---|---|
| Solicit | must have Client-ID, no Server-ID; discarded if unicast (UseMulticast per §18.4). | Advertise with IA_PD(prefix) [+PD_EXCLUDE], NoPrefixAvail if the session has no block; IA_NA → NoAddrsAvail. With Rapid Commit and `rapid_commit: true` → commit and send Reply with Rapid Commit. |
| Request | Client-ID + Server-ID == ours (else discard) | Commit binding (replaces any previous binding for the session, warn if DUID changed), Reply with IA_PD. |
| Renew | Client-ID + Server-ID == ours | Same DUID (any IAID) → refresh, Reply with IA_PD. Different DUID → IA_PD with Status NoBinding. Prefix in request not equal to ours → echoed with lifetimes 0 plus the correct prefix. |
| Rebind | Client-ID, no Server-ID | Like Renew but a different DUID gets NoBinding only if we have an active binding; prefixes not ours are returned with lifetimes 0. |
| Release | Client-ID + Server-ID == ours | Deactivate binding, Reply Status Success; unknown IAID → IA_PD with NoBinding. |
| Information-request | no IA options; Server-ID if present must match | Reply with DNS servers (and SOL/INF_MAX_RT if in ORO). |
| Confirm/Decline/others | — | Discard (we never delegate addresses). |

Only one IA_PD per session can be satisfied; additional IA_PDs in a message
get `NoPrefixAvail`. Extra IA_PD/IA_NA beyond the compile-time limits are
ignored by the parser.

Other SMF changes:

* `up2cp` PDR gets a second SDF filter:
  `permit out 17 from any 547 to assigned` (uplink DHCPv6, both the
  ff02::1:2 multicast case and a unicast Renew/Release to the server) in
  addition to the existing ICMPv6 RS rule (gx-handler.c, npcf-handler.c).
* UE IP Address IE in DL and UL PDRs carries `IPv6D` + delegation bits when
  the session block is shorter than /64.
* Router Advertisement: M=0, **O=1** when the session has a block or IPv6
  DNS is configured, **L cleared** (TS 29.061), A=1, plus an RDNSS option
  (RFC 8106) when `dns6` is configured.
* Logging: one `ogs_info` per committed/released delegation; `ogs_debug` per
  message; `ogs_warn` on validation failures (rate is bounded by the UE's own
  bearer, no amplification: at most one reply per request).

### 3.4 UPF

* `upf_sess_t` gains `uint8_t ipv6_prefixlen` (64 default) taken from the UE IP
  Address IE (`ogs_pfcp_ue_ip_addr_ipv6_prefixlen`), or from the local pool
  when the UPF allocates.
* New hash `upf_context_t.ipv6_pd_hash` keyed by `{masked 8-byte prefix, L}`
  (9 bytes) plus `int ipv6_pd_len_refcnt[65]` so the lookup only tries the
  prefix lengths actually in use:
  `upf_sess_find_by_ipv6()` = /64 hash → for each L with refcnt>0, from
  longest to shortest: mask and probe → framed-route trie.
* Uplink source check (gtp-path.c) accepts: any link-local source
  (fe80::/10; such packets can only reach the SMF via the UP2CP PDR or are
  dropped by the kernel), any source inside the session block, framed
  routes. Everything else is dropped as spoofed, as today.
* `upf_sess_clear_ue_ip()` removes the PD hash entry.

### 3.5 Tests (`tests/ipv6-pd`, suite `app`, config `configs/ipv6-pd.yaml.in`)

Both EPC (S1AP/NAS-EPS) and 5GC (NGAP/NAS-5GS) attach flows, then, over
GTP-U through the real UPF/SMF:

1. RS → RA; assert prefix length 64, flags (M=0, O=1, L=0, A=1), RDNSS.
2. Solicit(IA_PD, ORO=[DNS, PD_EXCLUDE]) → Advertise; assert Server-ID,
   Client-ID echo, IAID, T1/T2, IAPREFIX == block/56 containing the RA /64,
   PD_EXCLUDE == RA /64, DNS.
3. Request → Reply, same checks; then ICMPv6 echo from an address in the
   delegated block (outside the link /64) to the ogstun gateway and back:
   proves UPF uplink acceptance and downlink lookup on the block.
4. Renew → Reply (lifetimes refreshed); Rebind → Reply; Release → Reply
   Success; Renew after Release → NoBinding.
5. Solicit without PD_EXCLUDE → upper-half /57; ping from it.
6. Solicit + Rapid Commit → Reply directly.
7. Negative: unicast Solicit → UseMulticast; Request with foreign Server-ID →
   no reply; Solicit carrying a Server-ID → no reply; Information-request →
   Reply with DNS only; truncated / garbage options → no reply, NFs alive;
   ping from an address outside the block → dropped.
8. Two UEs → two distinct blocks; detach/re-attach → block returned to the
   pool (no leak: pool `avail` counter back to its starting value, checked
   through a third attach getting an address).
9. IPv6-only (PDN type IPv6) and IPv4v6 sessions.

Unit tests (`tests/unit/dhcpv6-test.c`): codec round-trips, RFC 6603
subnet-id encoding example from the RFC, parser robustness (random bytes,
truncation at every offset).

## 4. Security considerations

* All DHCPv6 traffic arrives inside the UE's own GTP-U tunnel; a UE can only
  ever obtain or affect *its own* delegation. There is no cross-UE state.
* Replies are 1:1 with requests and are never larger than a few hundred
  bytes, so there is no amplification vector towards the UE.
* The parser is bounds-checked, allocation-free, and fuzzed; the SMF never
  trusts lengths from the wire without validation.
* Uplink anti-spoofing in the UPF is preserved and extended to the block.
* Server DUID is stable and non-secret; transaction IDs are chosen by the
  client and only echoed.

## 5. Hardware findings (2026-09-11) and the second iteration

First deployment on a live EPC (Global Telecom Titan 4000 in IP passthrough →
TP-Link HX220 → laptop) exposed eight defects. This section is the design
for fixing them; interfaces are fixed here so the pieces can be built in
parallel. Threat model that drives most of it: **a passthrough CPE leaks LAN
link-local traffic onto the bearer** (mDNS, ND, DHCPv6 from LAN hosts were
all seen on the wire), so anything the core accepts from a link-local source
inside the tunnel must be treated as potentially coming from an untrusted LAN
host, not from the subscriber's router.

### 5.1 Neighbour Discovery for the gateway (Defect 1)

A router behind a passthrough CPE has an Ethernet WAN. Its default gateway
is the RA source (`fe80::1` or the SMF link-local), and it must resolve that
address to a MAC before it can forward anything; it sends NS to
`ff02::1:ff00:1` (solicited-node) and, for NUD re-probes, unicast NS to
`fe80::1`. Nothing answered. Fix:

* **SMF** answers NS whose *target* is the SMF link-local with a unicast
  Neighbour Advertisement to the solicitor (R=1, S=1, O=1, Target
  Link-Layer Address option = the virtual MAC). Sources may be link-local or
  global. NS from `::` (DAD) is never answered.
* **RA** carries a Source Link-Layer Address option (type 1) with the same
  virtual MAC, so routers usually do not need to ask.
* **UP2CP SDF filters** (SMF `smf_sess_set_up2cp_flow_description()`,
  computed from the actual SMF link-local `L`):
  `permit out 58 from <solicited-node(L)>/128 to assigned` and
  `permit out 58 from <L>/128 to assigned`, in addition to the RS and
  DHCPv6 rules. `solicited-node(L) = ff02::1:ff00:0000 | (L & 0xffffff)`.
* Knobs (`smf.router_advertisement`, see 5.6): `link_layer_address`
  (default `02:00:00:00:01:01`, locally administered; proven on hardware to
  be accepted regardless of value) and `source_link_layer_address: true`.

### 5.2 Link-local sources and sticky bindings (Defect 2)

* **UPF**: a link-local (`fe80::/10`) or unspecified (`::`) uplink source is
  accepted **only when the packet matched a PDR whose FAR destination is the
  CP function** (RS, NS-for-gateway, DHCPv6). On any other PDR it is dropped
  in the UPF (`[DROP] Link-local source not for the control plane`) and
  counted (Prometheus `upf_ul_drop_link_local`, log rate-limited to one line per second). Nothing link-local ever
  reaches `ogstun`.
* **SMF binding policy** (`smf.dhcpv6.binding_policy: sticky | replace`,
  default `sticky`): while a binding is live (committed and
  `now < bound_at + valid_lifetime`), a Solicit/Request from a different
  DUID gets IA_PD `NoPrefixAvail` ("prefix is bound to another client"),
  Renew/Rebind from a different DUID get `NoBinding`; both are logged at
  `ogs_warn` with both DUIDs. The bound client's Release or the lifetime
  expiry frees the binding. `replace` restores the first-iteration
  behaviour. Binding expiry is evaluated lazily on each message; there is
  still no server-side timer.

### 5.3 Static addresses must land in the containing subnet (Defect 3)

`ogs_pfcp_ue_ip_alloc()` for a static address chooses, among the subnets
matching family and DNN (an exact DNN match first, then DNN-less subnets),
the one whose network **contains** the address:
`ogs_pfcp_find_subnet_by_addr(int family, const char *dnn, const uint8_t *addr)`.
If none contains it the allocation fails with
`OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE` and
`ogs_error("Static UE IPv6 %s is not inside any subnet of DNN[%s]")`; the
session is rejected rather than routed into the wrong pool.

### 5.4 Several pools per DNN (Defect 4)

Dynamic allocation walks the subnets of the DNN in configuration order and
takes the first with `pool.avail > 0` (already the case); the UPF downlink
lookup is global across subnets. This is now covered by an integration test
with two `prefix_delegation` subnets on one DNN, the first sized to a single
block: UE1 lands in pool 1, UE2 in pool 2, both forward, both free on
detach.

### 5.5 Static-only subnets and per-session kernel routes (Defect 5)

A subnet entry may be declared

```yaml
    - subnet: 2602:f815:e1::/48
      dev: ogstun2
      prefix_delegation: 56
      static: true          # NEW: no dynamic pool, statics only, per-session routes
```

`ogs_pfcp_subnet_t.static_only` (bool). Such a subnet generates no pool
(`pool.size == 0`) and is only ever chosen by containment (5.3). The same
subnet may be listed under several DNNs with different `dev`s: a
subscriber's static block is then identical on every APN and the traffic
follows the session to the right tun.

Because the block is not covered by the address the operator put on the tun,
the **UPF installs a kernel route** for it when the session is created and
removes it when the session is deleted (Linux rtnetlink, `RTM_NEWROUTE` /
`RTM_DELROUTE`, `rtm_protocol = 250` so the routes are recognisable, output
interface = the subnet's `dev`). Rules:

* route the session block (`ipv6->addr` masked to L) when
  `sess->ipv6->subnet->static_only`; route each IPv6/IPv4 framed route
  likewise;
* at UPF start, dump the routing table and delete every route with protocol
  250 (left over from a previous instance);
* non-Linux builds log once that per-session routes are unsupported.

Implemented in `src/upf/route.c` (`upf_route_init()`, `upf_route_final()`,
`upf_route_add(int family, const uint8_t *prefix, uint8_t prefixlen, const char *ifname)`,
`upf_route_del(...)`; framed routes always get a kernel route, static-only
blocks get one too; failures are logged and never fail the session) and called from `upf_sess_set_ue_ip()` /
`upf_sess_clear_ue_ip()` / framed-route setters.

### 5.6 Router Advertisement knobs (Defect 6)

```yaml
smf:
  router_advertisement:           # NEW, all optional
    other_config: auto            # auto | true | false  (O flag; auto = 1 when PD block or IPv6 DNS)
    on_link: false                # L flag on the Prefix Information option (TS 29.061: cleared)
    rdnss: true                   # RFC 8106 RDNSS option from `dns`
    source_link_layer_address: true
    link_layer_address: 02:00:00:00:01:01
    router_lifetime: 64800        # seconds
```

Defaults are the first-iteration behaviour plus SLLA. Stock Open5GS
corresponds to `other_config: false, on_link: true, rdnss: false,
source_link_layer_address: false`.

### 5.7 RS from the unspecified address (Defect 7)

RFC 4861 §4.1 allows an RS sourced from `::`. The UPF accepts `::` under the
same CP-function-only rule as link-local (5.2). The SMF answers an RS from
`::` with an RA sent to `ff02::1` (all-nodes), as §6.2.6 requires; an RS
from a unicast source keeps getting a unicast RA. RS handling never looks at
the interface identifier.

### 5.8 Client fixtures (Defect 8)

From the capture, encoded as unit-test vectors in `tests/unit/dhcpv6-test.c`
and as an integration scenario:

* HX220 Information-request: Client-ID DUID-LL `2e:2f:d0:b8:f1:9d`,
  Elapsed-Time, Vendor-Class (enterprise 11863 "TP-Link Technology
  Co.,Ltd"), ORO `[32, 23, 16]` — sent even when the RA had O=0.
* HX220 Solicit: IA_PD IAID `0xd0b8f19d`, T1 = T2 = `0xffffffff`, no
  IAPREFIX hint, no PD_EXCLUDE, no Rapid Commit; then Request → Reply.
* New option: `OPTION_INFORMATION_REFRESH_TIME` (32) is encoded/decoded and
  included in the Reply to an Information-request when requested
  (`smf.dhcpv6.information_refresh_time`, default 86400 s).
* IA_NA in any message is answered with a Status Code **inside** the IA_NA
  (`NoAddrsAvail`), so RFC 7550 clients do not abandon the exchange.
* The Request→Release loop seen on 2026-09-10 (`00:13:26–00:13:39`) is
  analysed in TESTING.md; root cause was the wrong-subnet block of 5.3.

### 5.9 New configuration keys, summary

| Key | Default | Section |
|---|---|---|
| `smf.session[].static` / `upf.session[].static` | `false` | 5.5 |
| `smf.dhcpv6.binding_policy` | `sticky` | 5.2 |
| `smf.dhcpv6.information_refresh_time` | `86400` | 5.8 |
| `smf.router_advertisement.other_config` | `auto` | 5.6 |
| `smf.router_advertisement.on_link` | `false` | 5.6 |
| `smf.router_advertisement.rdnss` | `true` | 5.6 |
| `smf.router_advertisement.source_link_layer_address` | `true` | 5.1 |
| `smf.router_advertisement.link_layer_address` | `02:00:00:00:01:01` | 5.1 |
| `smf.router_advertisement.router_lifetime` | `64800` | 5.6 |
