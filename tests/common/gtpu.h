/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef TEST_COMMON_GTPU_H
#define TEST_COMMON_GTPU_H

#ifdef __cplusplus
extern "C" {
#endif

#define testgnb_gtpu_read(x) test_gtpu_read(x)
#define testgnb_gtpu_close(x) test_gtpu_close(x)

ogs_socknode_t *test_gtpu_server(int index, int family);
ogs_pkbuf_t *test_gtpu_read(ogs_socknode_t *node);
void test_gtpu_close(ogs_socknode_t *node);

void testgtpu_recv(test_ue_t *test_ue, ogs_pkbuf_t *pkbuf);

int test_gtpu_send(
        ogs_socknode_t *node, test_bearer_t *bearer,
        ogs_gtp2_header_desc_t *header_desc, ogs_pkbuf_t *pkbuf);
int test_gtpu_send_ping(
        ogs_socknode_t *node, test_bearer_t *bearer, const char *dst_ip);
int test_gtpu_send_slacc_rs(ogs_socknode_t *node, test_bearer_t *bearer);
int test_gtpu_send_slacc_rs_with_unspecified_source_address(
        ogs_socknode_t *node, test_bearer_t *bearer);
int test_gtpu_send_end_marker(
        ogs_socknode_t *node, test_bearer_t *bearer);
int test_gtpu_send_error_indication(
        ogs_socknode_t *node, test_bearer_t *bearer);
int test_gtpu_send_indirect_data_forwarding(
        ogs_socknode_t *node, test_bearer_t *bearer, ogs_pkbuf_t *pkbuf);

/*
 * IPv6 / DHCPv6-PD helpers (tests/ipv6-pd)
 */

struct ip6_hdr;

/* Parsed Router Advertisement (RFC 4861 / RFC 8106) */
typedef struct test_gtpu_ra_s {
    uint8_t src[OGS_IPV6_LEN];      /* router link-local address */
    uint8_t dst[OGS_IPV6_LEN];
    uint8_t hlim;                   /* IPv6 hop limit (must be 255) */
    uint8_t cur_hop_limit;
    uint8_t flags;                  /* ND_RA_FLAG_MANAGED/_OTHER */
    uint16_t router_lifetime;

    bool has_prefix;                /* Prefix Information option */
    uint8_t prefixlen;
    uint8_t prefix[OGS_IPV6_LEN];
    uint8_t pi_flags;               /* ND_OPT_PI_FLAG_ONLINK / _AUTO */
    uint32_t preferred;
    uint32_t valid;

    bool has_mtu;
    uint32_t mtu;

    bool has_rdnss;                 /* RDNSS option (RFC 8106) */
    int num_of_rdnss;
    uint8_t rdnss[4][OGS_IPV6_LEN];
    uint32_t rdnss_lifetime;

    bool has_slla;                  /* Source Link-Layer Address option */
    uint8_t slla[6];
} test_gtpu_ra_t;

/* Neighbour Advertisement flags (first octet after the ICMPv6 header) */
#define TEST_ND_NA_FLAG_ROUTER          0x80
#define TEST_ND_NA_FLAG_SOLICITED       0x40
#define TEST_ND_NA_FLAG_OVERRIDE        0x20

/* Parsed Neighbour Advertisement (RFC 4861 section 4.4) */
typedef struct test_gtpu_na_s {
    uint8_t src[OGS_IPV6_LEN];
    uint8_t dst[OGS_IPV6_LEN];
    uint8_t hlim;                   /* IPv6 hop limit (must be 255) */
    uint8_t flags;                  /* TEST_ND_NA_FLAG_* */
    uint8_t target[OGS_IPV6_LEN];

    bool has_tlla;                  /* Target Link-Layer Address option */
    uint8_t tlla[6];
} test_gtpu_na_t;

/* Like test_gtpu_read() but returns NULL when nothing arrives in time */
ogs_pkbuf_t *test_gtpu_read_timeout(ogs_socknode_t *node, int timeout_ms);

/* IPv6 pseudo-header checksum (UDP/ICMPv6), returned in network order */
uint16_t test_in6_cksum(const uint8_t *src, const uint8_t *dst,
        uint8_t nxt, const void *payload, size_t len);

/* fe80::<interface identifier of sess->ue_ip.addr6> */
void test_gtpu_link_local(test_sess_t *sess, uint8_t *addr6);
/* ff02::1:ffXX:XXXX for addr6 (RFC 4291 section 2.7.1) */
void test_gtpu_solicited_node(const uint8_t *addr6, uint8_t *out6);
/* MAC-48 recovered from the EUI-64 interface identifier of sess */
void test_gtpu_mac(test_sess_t *sess, uint8_t *mac);

/* pkbuf must carry OGS_GTPV1U_5GC_HEADER_LEN headroom; it is consumed */
int test_gtpu_send_ipv6(
        ogs_socknode_t *node, test_bearer_t *bearer, ogs_pkbuf_t *ip6pkt);
/* src6 NULL = fe80::<IID>, dst6 NULL = ff02::1:2; UDP 546 -> 547 */
int test_gtpu_send_dhcpv6(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6,
        const void *dhcp, size_t dhcp_len);
/* Arbitrary UDP datagram; src6 NULL = fe80::<IID> */
int test_gtpu_send_udp(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6,
        uint16_t src_port, uint16_t dst_port,
        const void *payload, size_t payload_len);
/* ICMPv6 echo request with an explicit source address */
int test_gtpu_send_ping_from(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const char *dst_ip);
/* Router Solicitation to ff02::2 with a valid checksum; src6 NULL =
 * fe80::<IID>, :: allowed (no SLLA option is added then, RFC 4861 4.1) */
int test_gtpu_send_rs_from(
        ogs_socknode_t *node, test_bearer_t *bearer, const uint8_t *src6);
/* Neighbour Solicitation for target6; src6 NULL = fe80::<IID>, dst6 NULL =
 * solicited-node multicast of target6; SLLA unless src6 is :: */
int test_gtpu_send_ns(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6, const uint8_t *target6);

/* Skip the GTP-U header of a received G-PDU and locate the IPv6 payload */
int test_gtpu_parse_ipv6(ogs_pkbuf_t *pkbuf,
        struct ip6_hdr **ip6_h, uint8_t **payload, size_t *payload_len);
/* Router Advertisement; the pkbuf is NOT freed (call testgtpu_recv after) */
int test_gtpu_parse_ra(ogs_pkbuf_t *pkbuf, test_gtpu_ra_t *ra);
/* Neighbour Advertisement with a valid checksum; the pkbuf is NOT freed */
int test_gtpu_parse_na(ogs_pkbuf_t *pkbuf, test_gtpu_na_t *na);
/* UDP 547 -> 546 to client6 (NULL = fe80::<IID>) with a valid checksum */
int test_gtpu_parse_dhcpv6_reply(ogs_pkbuf_t *pkbuf, test_bearer_t *bearer,
        const uint8_t *client6, test_dhcpv6_msg_t *msg);
/* ICMPv6 echo reply addressed to expected_dst6 */
int test_gtpu_parse_ping_reply(
        ogs_pkbuf_t *pkbuf, const uint8_t *expected_dst6);

#ifdef __cplusplus
}
#endif

#endif /* TEST_COMMON_GTPU_H */
