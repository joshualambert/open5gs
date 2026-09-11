/*
 * Copyright (C) 2026 by Josh Lambert <josh.lambert@alabamalightwave.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * DHCPv6 Prefix Delegation scenarios shared by the EPC and 5GC tests.
 *
 * The RAT-specific files attach a UE, fill a pd_ctx_t and hand it to the
 * scenario functions below, which only talk GTP-U (RS/RA, ND, DHCPv6,
 * ping).  Section numbers refer to docs/ipv6-prefix-delegation/DESIGN.md.
 */

#ifndef TEST_IPV6_PD_SCENARIO_H
#define TEST_IPV6_PD_SCENARIO_H

#include "test-app.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Expectations derived from configs/ipv6-pd.yaml.in */
#define PD_IAID                     1
#define PD_BLOCK_PREFIXLEN          56      /* session[].prefix_delegation */
#define PD_EXPECTED_T1              300     /* 0.5 * preferred_lifetime */
#define PD_EXPECTED_T2              480     /* 0.8 * preferred_lifetime */
#define PD_EXPECTED_PREFERRED       600     /* smf.dhcpv6.preferred_lifetime */
#define PD_EXPECTED_VALID           1200    /* smf.dhcpv6.valid_lifetime */
#define PD_INFORMATION_REFRESH_TIME 600     /* smf.dhcpv6.information_refresh_time */
#define PD_DNS6                     "2001:4860:4860::8888"

/* smf.router_advertisement (5.6): everything at its default except the
 * link-layer address, which the config sets to the documented default */
#define PD_ROUTER_LIFETIME          64800
extern const uint8_t pd_router_mac[6];      /* 02:00:00:00:01:01 */

/* Dynamic pools of the "internet" DNN in configuration order (5.4).
 * Pool 1 is sized to exactly one /56 block: the first dynamic UE always
 * lands there, the second one spills into pool 2. */
#define PD_POOL_PREFIXLEN           48
#define PD_POOL1                    "2001:db8:beef::"
#define PD_POOL2                    "2001:db8:cafe::"

/* Static subscriber inside the dynamic cafe subnet, outside its range */
#define PD_STATIC_UE_IPV6           "2001:db8:cafe:4200::1"
#define PD_STATIC_LINK              "2001:db8:cafe:4200::"  /* /64 */
#define PD_STATIC_BLOCK             "2001:db8:cafe:4200::"  /* /56 */

/* Static subscriber in the static-only subnet 2001:db8:5a7c::/48 (5.5).
 * Nothing puts that subnet on ogstun: the UPF has to install a kernel
 * route (protocol 250) for the block while the session exists. */
#define PD_STATIC_ONLY_UE_IPV6      "2001:db8:5a7c:4200::1"
#define PD_STATIC_ONLY_LINK         "2001:db8:5a7c:4200::"  /* /64 */
#define PD_STATIC_ONLY_BLOCK        "2001:db8:5a7c:4200::"  /* /56 */
#define PD_STATIC_ONLY_ROUTE        "2001:db8:5a7c:4200::/56"
#define PD_KERNEL_ROUTE_PROTO       250

/* Static address outside every configured subnet: rejected (5.3) */
#define PD_STATIC_ORPHAN_UE_IPV6    "2001:db8:dead::1"

#define PD_REPLY_TIMEOUT            3000    /* ms, a reply is expected */
#define PD_NO_REPLY_TIMEOUT         1000    /* ms, silence is expected */
#define PD_SIGNALLING_TIMEOUT       10000   /* ms, S1AP/NGAP message expected */

typedef struct pd_ctx_s {
    abts_case *tc;
    ogs_socknode_t *gtpu;
    test_ue_t *test_ue;
    test_sess_t *sess;
    test_bearer_t *bearer;              /* NULL until the session is up */

    test_gtpu_ra_t ra;                  /* Router Advertisement received */
    uint8_t link[OGS_IPV6_LEN];         /* RA prefix (/64) */
    uint8_t block[OGS_IPV6_LEN];        /* link masked to PD_BLOCK_PREFIXLEN */

    test_dhcpv6_duid_t client_id;       /* DUID used for the next messages */
    test_dhcpv6_duid_t server_id;       /* learned from the first reply */
    uint32_t iaid;                      /* IAID used for the next messages */
    uint32_t xid;                       /* transaction-id of the last request */
    test_dhcpv6_ia_pd_t ia_pd;          /* last IA_PD received with a prefix */
} pd_ctx_t;

/* bearer may be NULL when the attach did not get that far; the DHCPv6
 * client DUID is a DUID-LL derived from the interface identifier */
void pd_ctx_init(pd_ctx_t *ctx, abts_case *tc, ogs_socknode_t *gtpu,
        test_ue_t *test_ue, test_sess_t *sess, test_bearer_t *bearer);

/* Switch the requesting router identity (5.2 sticky bindings) */
void pd_ctx_set_client_id(pd_ctx_t *ctx, const test_dhcpv6_duid_t *duid);

/* RS -> RA, asserts on the RA, fills ctx->link/block and sess->ue_ip */
bool pd_router_discovery(pd_ctx_t *ctx);

/* smf.router_advertisement defaults: O=1, L=0, A=1, RDNSS, SLLA, lifetime */
void pd_check_ra_defaults(pd_ctx_t *ctx);

/* Solicit -> Advertise, Request -> Reply with all assertions */
bool pd_solicit_request(pd_ctx_t *ctx, bool pd_exclude);

void pd_scenario_basic(pd_ctx_t *ctx);
void pd_scenario_lifecycle(pd_ctx_t *ctx);
void pd_scenario_no_exclude(pd_ctx_t *ctx);
void pd_scenario_rapid_commit(pd_ctx_t *ctx);
void pd_scenario_negative(pd_ctx_t *ctx);
void pd_scenario_static(pd_ctx_t *ctx, bool pd_exclude);

/* Second iteration (DESIGN section 5) */
void pd_scenario_neighbour_discovery(pd_ctx_t *ctx);        /* 5.1 */
void pd_scenario_leaky_cpe(pd_ctx_t *ctx);                  /* 5.2 UPF */
void pd_scenario_sticky_binding(pd_ctx_t *ctx);             /* 5.2 SMF */
void pd_scenario_static_only(pd_ctx_t *ctx, bool pd_exclude); /* 5.3/5.5 */
void pd_scenario_in_pool(pd_ctx_t *ctx, const char *pool);  /* 5.4 */
void pd_scenario_rs_unspecified(pd_ctx_t *ctx);             /* 5.7 */
void pd_scenario_hx220(pd_ctx_t *ctx);                      /* 5.8 */

void pd_check_distinct_blocks(pd_ctx_t *a, pd_ctx_t *b);
void pd_check_same_prefixes(pd_ctx_t *ctx,
        const uint8_t *link, const uint8_t *block);
/* The session block (and delegated prefix, if any) lies in pool/48 */
void pd_check_block_in_pool(pd_ctx_t *ctx, const char *pool);
/* `ip -6 route show proto 250` lists (or does not list) route (5.5) */
void pd_check_kernel_route(abts_case *tc, const char *route, bool expected);

/* Text -> 16 byte address (asserts on failure) */
void pd_addr_from_string(const char *str, uint8_t *addr6);

#ifdef __cplusplus
}
#endif

#endif /* TEST_IPV6_PD_SCENARIO_H */
