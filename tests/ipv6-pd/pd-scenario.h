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
 * scenario functions below, which only talk GTP-U (RS/RA, DHCPv6, ping).
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
#define PD_DNS6                     "2001:4860:4860::8888"

/* Static subscriber (outside the dynamic pool range of the config) */
#define PD_STATIC_UE_IPV6           "2001:db8:cafe:4200::1"
#define PD_STATIC_LINK              "2001:db8:cafe:4200::"  /* /64 */
#define PD_STATIC_BLOCK             "2001:db8:cafe:4200::"  /* /56 */

#define PD_REPLY_TIMEOUT            3000    /* ms, a reply is expected */
#define PD_NO_REPLY_TIMEOUT         1000    /* ms, silence is expected */

typedef struct pd_ctx_s {
    abts_case *tc;
    ogs_socknode_t *gtpu;
    test_ue_t *test_ue;
    test_sess_t *sess;
    test_bearer_t *bearer;

    test_gtpu_ra_t ra;                  /* Router Advertisement received */
    uint8_t link[OGS_IPV6_LEN];         /* RA prefix (/64) */
    uint8_t block[OGS_IPV6_LEN];        /* link masked to PD_BLOCK_PREFIXLEN */

    test_dhcpv6_duid_t client_id;
    test_dhcpv6_duid_t server_id;       /* learned from the first reply */
    uint32_t xid;                       /* transaction-id of the last request */
    test_dhcpv6_ia_pd_t ia_pd;          /* last IA_PD received */
} pd_ctx_t;

void pd_ctx_init(pd_ctx_t *ctx, abts_case *tc, ogs_socknode_t *gtpu,
        test_ue_t *test_ue, test_sess_t *sess, test_bearer_t *bearer);

/* RS -> RA, asserts on the RA, fills ctx->link/block and sess->ue_ip */
bool pd_router_discovery(pd_ctx_t *ctx);

/* Solicit -> Advertise, Request -> Reply with all assertions */
bool pd_solicit_request(pd_ctx_t *ctx, bool pd_exclude);

void pd_scenario_basic(pd_ctx_t *ctx);
void pd_scenario_lifecycle(pd_ctx_t *ctx);
void pd_scenario_no_exclude(pd_ctx_t *ctx);
void pd_scenario_rapid_commit(pd_ctx_t *ctx);
void pd_scenario_negative(pd_ctx_t *ctx);
void pd_scenario_static(pd_ctx_t *ctx, bool pd_exclude);

void pd_check_distinct_blocks(pd_ctx_t *a, pd_ctx_t *b);
void pd_check_same_prefixes(pd_ctx_t *ctx,
        const uint8_t *link, const uint8_t *block);

/* Text -> 16 byte address (asserts on failure) */
void pd_addr_from_string(const char *str, uint8_t *addr6);

#ifdef __cplusplus
}
#endif

#endif /* TEST_IPV6_PD_SCENARIO_H */
