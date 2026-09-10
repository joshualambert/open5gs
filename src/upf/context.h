/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef UPF_CONTEXT_H
#define UPF_CONTEXT_H

#include "upf-config.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ogs-gtp.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#include "ipfw/ogs-ipfw.h"

#include "timer.h"
#include "upf-sm.h"
#include "metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __upf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __upf_log_domain

struct upf_route_trie_node;

/*
 * IPv6 prefix helpers (pure, shared by the session table and the uplink
 * source check). The upper 64 bits of an IPv6 address are handled as one
 * host-order integer so that a prefix of length 1..64 is a single mask:
 *
 *   prefixlen   upf_ipv6_prefix_mask64()
 *   ---------   ------------------------
 *   64          0xffffffffffffffff   (exactly the /64 link prefix)
 *   60          0xfffffffffffffff0
 *   56          0xffffffffffffff00
 *   48          0xffffffffffff0000
 *   1           0x8000000000000000
 *
 * prefixlen 0 is not a valid input (shift by 64 is undefined); callers
 * validate the length before it is stored in upf_sess_t.ipv6_prefixlen.
 */
#define UPF_IPV6_PD_KEY_LEN 9
#define upf_ipv6_prefix_mask64(prefixlen) \
    (~UINT64_C(0) << (OGS_IPV6_DEFAULT_PREFIX_LEN - (prefixlen)))

OGS_STATIC_ASSERT(upf_ipv6_prefix_mask64(64) == UINT64_C(0xffffffffffffffff));
OGS_STATIC_ASSERT(upf_ipv6_prefix_mask64(60) == UINT64_C(0xfffffffffffffff0));
OGS_STATIC_ASSERT(upf_ipv6_prefix_mask64(56) == UINT64_C(0xffffffffffffff00));
OGS_STATIC_ASSERT(upf_ipv6_prefix_mask64(48) == UINT64_C(0xffffffffffff0000));
OGS_STATIC_ASSERT(upf_ipv6_prefix_mask64(1) == UINT64_C(0x8000000000000000));

/* Upper 64 bits (network prefix part) of an IPv6 address in host order */
static inline uint64_t upf_ipv6_prefix64(const uint32_t *addr6)
{
    return ((uint64_t)be32toh(addr6[0]) << 32) | be32toh(addr6[1]);
}

/* true when the first prefixlen (1..64) bits of addr6 and prefix6 match */
static inline bool upf_ipv6_prefix_match(
        const uint32_t *addr6, const uint32_t *prefix6, uint8_t prefixlen)
{
    return ((upf_ipv6_prefix64(addr6) ^ upf_ipv6_prefix64(prefix6)) &
            upf_ipv6_prefix_mask64(prefixlen)) == 0;
}

/* Key of upf_context_t.ipv6_pd_hash for the block of addr6/prefixlen */
static inline void upf_ipv6_pd_key(
        uint8_t key[UPF_IPV6_PD_KEY_LEN],
        const uint32_t *addr6, uint8_t prefixlen)
{
    uint64_t prefix = htobe64(
            upf_ipv6_prefix64(addr6) & upf_ipv6_prefix_mask64(prefixlen));

    memcpy(key, &prefix, sizeof(prefix));
    key[sizeof(prefix)] = prefixlen;
}

typedef struct upf_context_s {
    ogs_hash_t *upf_n4_seid_hash;   /* hash table (UPF-N4-SEID) */
    ogs_hash_t *smf_n4_seid_hash;   /* hash table (SMF-N4-SEID) */
    ogs_hash_t *smf_n4_f_seid_hash; /* hash table (SMF-N4-F-SEID) */
    ogs_hash_t *ipv4_hash;  /* hash table (IPv4 Address) */
    ogs_hash_t *ipv6_hash;  /* hash table (IPv6 Address) */

    /*
     * IPv6 prefix delegation (DHCPv6-PD):
     * hash table of the network prefixes ("blocks") shorter than /64,
     * keyed by upf_ipv6_pd_key() = { 8 bytes of the address masked to the
     * block length, block length }. ipv6_pd_len_refcnt[L] counts the
     * entries of length L so that upf_sess_find_by_ipv6() only probes the
     * lengths actually in use.
     */
    ogs_hash_t *ipv6_pd_hash;
    int ipv6_pd_len_refcnt[OGS_IPV6_DEFAULT_PREFIX_LEN + 1];

    /* IPv4 framed routes trie */
    struct upf_route_trie_node *ipv4_framed_routes;
    /* IPv6 framed routes trie */
    struct upf_route_trie_node *ipv6_framed_routes;

    ogs_list_t sess_list;
} upf_context_t;

/* trie mapping from IP framed routes to session. */
struct upf_route_trie_node {
    struct upf_route_trie_node *left;
    struct upf_route_trie_node *right;
    upf_sess_t *sess;
};

/* Accounting: */
typedef struct upf_sess_urr_acc_s {
    bool reporting_enabled;
    ogs_timer_t *t_validity_time; /* Quota Validity Time expiration handler */
    ogs_timer_t *t_time_quota; /* Time Quota expiration handler */
    ogs_timer_t *t_time_threshold; /* Time Threshold expiration handler */
    uint32_t time_start; /* When t_time_* started */
    ogs_pfcp_urr_ur_seqn_t report_seqn; /* Next seqn to use when reporting */
    uint64_t total_octets;
    uint64_t ul_octets;
    uint64_t dl_octets;
    uint64_t total_pkts;
    uint64_t ul_pkts;
    uint64_t dl_pkts;
    ogs_time_t time_of_first_packet;
    ogs_time_t time_of_last_packet;
    /* Snapshot of measurement when last report was sent: */
    struct {
        uint64_t total_octets;
        uint64_t ul_octets;
        uint64_t dl_octets;
        uint64_t total_pkts;
        uint64_t ul_pkts;
        uint64_t dl_pkts;
        ogs_time_t timestamp;
    } last_report;
} upf_sess_urr_acc_t;

#define UPF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, upf_sess_t, pfcp)
typedef struct upf_sess_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_pool_id_t   *upf_n4_seid_node;  /* A node of UPF-N4-SEID */

    ogs_pfcp_sess_t pfcp;

    uint64_t        upf_n4_seid;        /* UPF SEID is derived from NODE */
    struct {
        uint64_t    seid;
        ogs_ip_t    ip;
    } smf_n4_f_seid;                    /* SMF SEID is received from Peer */

    /* APN Configuration */
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;
    /*
     * Length of the IPv6 network prefix ("block") owned by the session:
     * OGS_IPV6_DEFAULT_PREFIX_LEN (64) unless the UE IP Address IE carried
     * IPv6D or the UPF pool is configured with prefix_delegation.
     * ipv6->addr[0..1] masked to ipv6_prefixlen is the block.
     */
    uint8_t          ipv6_prefixlen;
    /* Key of this session's entry in upf_context_t.ipv6_pd_hash
     * (the hash table keeps a pointer to the key, not a copy) */
    uint8_t          ipv6_pd_key[UPF_IPV6_PD_KEY_LEN];

    ogs_ipsubnet_t   *ipv4_framed_routes;
    ogs_ipsubnet_t   *ipv6_framed_routes;

    char            *gx_sid;            /* Gx Session ID */
    ogs_pfcp_node_t *pfcp_node;

    /* Accounting: */
    upf_sess_urr_acc_t urr_acc[OGS_MAX_NUM_OF_URR]; /* FIXME: This probably needs to be mved to a hashtable or alike */
    char            *apn_dnn;            /* APN/DNN Item */
} upf_sess_t;

void upf_context_init(void);
void upf_context_final(void);
upf_context_t *upf_self(void);

int upf_context_parse_config(void);

upf_sess_t *upf_sess_add_by_message(ogs_pfcp_message_t *message);

upf_sess_t *upf_sess_add(ogs_pfcp_f_seid_t *f_seid);
int upf_sess_remove(upf_sess_t *sess);
void upf_sess_remove_all(void);
upf_sess_t *upf_sess_find_by_smf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_smf_n4_f_seid(ogs_pfcp_f_seid_t *f_seid);
upf_sess_t *upf_sess_find_by_upf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_ipv4(uint32_t addr);
upf_sess_t *upf_sess_find_by_ipv6(uint32_t *addr6);
upf_sess_t *upf_sess_find_by_id(ogs_pool_id_t id);

uint8_t upf_sess_set_ue_ip(upf_sess_t *sess,
        uint8_t session_type, ogs_pfcp_pdr_t *pdr);
uint8_t upf_sess_set_ue_ipv4_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);
uint8_t upf_sess_set_ue_ipv6_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);

void upf_sess_urr_acc_add(upf_sess_t *sess, ogs_pfcp_urr_t *urr, size_t size, bool is_uplink);
void upf_sess_urr_acc_fill_usage_report(upf_sess_t *sess, const ogs_pfcp_urr_t *urr,
                                        ogs_pfcp_user_plane_report_t *report, unsigned int idx);
void upf_sess_urr_acc_snapshot(upf_sess_t *sess, ogs_pfcp_urr_t *urr);
void upf_sess_urr_acc_timers_setup(upf_sess_t *sess, ogs_pfcp_urr_t *urr);

#ifdef __cplusplus
}
#endif

#endif /* UPF_CONTEXT_H */
