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

#include "test-common.h"
#include "ipfw/ipfw2.h"

ogs_socknode_t *test_gtpu_server(int index, int family)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    if (index == 1) {
        if (family == AF_INET6)
            ogs_assert(OGS_OK ==
                ogs_copyaddrinfo(&addr, test_self()->gnb1_addr6));
        else
            ogs_assert(OGS_OK ==
                ogs_copyaddrinfo(&addr, test_self()->gnb1_addr));
    } else if (index == 2) {
        if (family == AF_INET6)
            ogs_assert(OGS_OK ==
                ogs_copyaddrinfo(&addr, test_self()->gnb2_addr6));
        else
            ogs_assert(OGS_OK ==
                ogs_copyaddrinfo(&addr, test_self()->gnb2_addr));
    } else
        ogs_assert_if_reached();

    node = ogs_socknode_new(addr);
    ogs_assert(node);

    sock = ogs_udp_server(node->addr, NULL);
    ogs_assert(sock);

    node->sock = sock;

    return node;
}

ogs_pkbuf_t *test_gtpu_read(ogs_socknode_t *node)
{
    int rc = 0;
    ogs_sockaddr_t from;
    ogs_pkbuf_t *recvbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(recvbuf);
    ogs_pkbuf_reserve(recvbuf, 4); /* For additional extension header */
    ogs_pkbuf_put(recvbuf, OGS_MAX_SDU_LEN-4);

    ogs_assert(node);
    ogs_assert(node->sock);

    while (1) {
        rc = ogs_recvfrom(
                node->sock->fd, recvbuf->data, recvbuf->len, 0, &from);
        if (rc <= 0) {
            ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "ogs_recvfrom() failed");
        }
        break;
    }
    recvbuf->len = rc;

    return recvbuf;
}

void test_gtpu_close(ogs_socknode_t *node)
{
    ogs_socknode_free(node);
}

#include "upf/upf-config.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

void testgtpu_recv(test_ue_t *test_ue, ogs_pkbuf_t *pkbuf)
{
    test_sess_t *sess = NULL;
    test_bearer_t *bearer = NULL;

    ogs_gtp2_header_t *gtp_h = NULL;
    struct ip6_hdr *ip6_h =  NULL;
    struct nd_router_advert *advert_h = NULL;
    struct nd_opt_prefix_info *prefix = NULL;

    uint32_t teid;
    uint8_t mask[OGS_IPV6_LEN];

    ogs_assert(test_ue);
    ogs_assert(pkbuf);

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    ogs_assert(gtp_h);

    ogs_assert(gtp_h->version == OGS_GTP1_VERSION_1);
    ogs_assert(gtp_h->type == OGS_GTPU_MSGTYPE_GPDU);

    teid = be32toh(gtp_h->teid);

    if (test_ue->mme_ue_s1ap_id) {
        /* EPC */
        ogs_list_for_each(&test_ue->sess_list, sess) {
            ogs_list_for_each(&sess->bearer_list, bearer) {
                if (teid == bearer->enb_s1u_teid) goto found;
            }
            ogs_assert(bearer);
        }
        ogs_assert(sess);
    } else if (test_ue->amf_ue_ngap_id) {
        /* 5GC */
        ogs_list_for_each(&test_ue->sess_list, sess) {
            if (sess->gnb_n3_teid == teid) goto found;
        }
        ogs_assert(sess);
    } else {
        ogs_assert_if_reached();
    }

found:
    ogs_assert(sess);

    ip6_h = pkbuf->data + ogs_gtpu_parse_header(NULL, pkbuf);
    ogs_assert(ip6_h);
    if (ip6_h->ip6_nxt == IPPROTO_ICMPV6) {
        struct nd_router_advert *advert_h = (struct nd_router_advert *)
            ((unsigned char*)ip6_h + sizeof(struct ip6_hdr));
        ogs_assert(advert_h);
        if (advert_h->nd_ra_hdr.icmp6_type == ND_ROUTER_ADVERT) {
            int i;
            struct nd_opt_prefix_info *prefix = (struct nd_opt_prefix_info *)
                ((unsigned char*)advert_h + sizeof(struct nd_router_advert));
            ogs_assert(prefix);
            n2mask(mask, prefix->nd_opt_pi_prefix_len);
            for (i = 0; i < OGS_IPV6_LEN; i++) {
                sess->ue_ip.addr6[i] |=
                    (mask[i] & prefix->nd_opt_pi_prefix.s6_addr[i]);
            }
        }
    }
    ogs_pkbuf_free(pkbuf);
}

int test_gtpu_send(
        ogs_socknode_t *node, test_bearer_t *bearer,
        ogs_gtp2_header_desc_t *header_desc, ogs_pkbuf_t *pkbuf)
{
    ogs_gtp_node_t gnode;
    test_sess_t *sess = NULL;

    ogs_assert(header_desc);
    ogs_assert(pkbuf);

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    memset(&gnode, 0, sizeof(ogs_gtp_node_t));

    gnode.addr.ogs_sin_port = htobe16(OGS_GTPV1_U_UDP_PORT);
    gnode.sock = node->sock;
    ogs_assert(gnode.sock);

    if (bearer->qfi) {
        if (sess->upf_n3_ip.ipv4) {
            gnode.addr.ogs_sa_family = AF_INET;
            gnode.addr.sin.sin_addr.s_addr = sess->upf_n3_ip.addr;
        } else if (sess->upf_n3_ip.ipv6) {
            gnode.addr.ogs_sa_family = AF_INET6;
            memcpy(gnode.addr.sin6.sin6_addr.s6_addr,
                    sess->upf_n3_ip.addr6, OGS_IPV6_LEN);
        } else {
            ogs_fatal("Not implemented");
            ogs_assert_if_reached();
        }

    } else if (bearer->ebi) {
        if (bearer->sgw_s1u_ip.ipv4) {
            gnode.addr.ogs_sa_family = AF_INET;
            gnode.addr.sin.sin_addr.s_addr = bearer->sgw_s1u_ip.addr;
        } else if (bearer->sgw_s1u_ip.ipv6) {
            gnode.addr.ogs_sa_family = AF_INET6;
            memcpy(gnode.addr.sin6.sin6_addr.s6_addr,
                    bearer->sgw_s1u_ip.addr6, OGS_IPV6_LEN);
        } else {
            ogs_fatal("Not implemented");
            ogs_assert_if_reached();
        }
    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    ogs_gtp2_encapsulate_header(header_desc, pkbuf);

    ogs_assert(OGS_OK == ogs_gtp_send_with_teid(
            gnode.sock, pkbuf, header_desc->teid, &gnode.addr));

    ogs_pkbuf_free(pkbuf);

    return OGS_OK;
}

int test_gtpu_send_ping(
        ogs_socknode_t *node, test_bearer_t *bearer, const char *dst_ip)
{
    int rv;
    test_sess_t *sess = NULL;

    ogs_gtp2_header_desc_t header_desc;

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_ipsubnet_t dst_ipsub;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);
    ogs_assert(dst_ip);

    rv = ogs_ipsubnet(&dst_ipsub, dst_ip, NULL);
    ogs_assert(rv == OGS_OK);

    pkbuf = ogs_pkbuf_alloc(
            NULL, 200 /* enough for ICMP; use smaller buffer */);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, 200-OGS_GTPV1U_5GC_HEADER_LEN);
    memset(pkbuf->data, 0, pkbuf->len);

    if (dst_ipsub.family == AF_INET) {
        struct ip *ip_h = NULL;
        struct icmp *icmp_h = NULL;

        ogs_pkbuf_trim(pkbuf, sizeof *ip_h + ICMP_MINLEN);

        ip_h = (struct ip *)pkbuf->data;
        icmp_h = (struct icmp *)((uint8_t *)ip_h + sizeof *ip_h);

        ip_h->ip_v = 4;
        ip_h->ip_hl = 5;
        ip_h->ip_tos = 0;
        ip_h->ip_id = rand();
        ip_h->ip_off = 0;
        ip_h->ip_ttl = 255;
        ip_h->ip_p = IPPROTO_ICMP;
        ip_h->ip_len = htobe16(sizeof *ip_h + ICMP_MINLEN);
        ip_h->ip_src.s_addr = sess->ue_ip.addr;
        ip_h->ip_dst.s_addr = dst_ipsub.sub[0];
        ip_h->ip_sum = ogs_in_cksum((uint16_t *)ip_h, sizeof *ip_h);

        icmp_h->icmp_type = 8;
        icmp_h->icmp_seq = rand();
        icmp_h->icmp_id = rand();
        icmp_h->icmp_cksum = ogs_in_cksum((uint16_t *)icmp_h, ICMP_MINLEN);

    } else if (dst_ipsub.family == AF_INET6) {
        struct ip6_hdr *ip6_h = NULL;
        struct icmp6_hdr *icmp6_h = NULL;
        uint16_t plen = 0;
        uint8_t nxt = 0;
        uint8_t *p = NULL;

        ogs_pkbuf_trim(pkbuf, sizeof *ip6_h + sizeof *icmp6_h);

        p = (uint8_t *)pkbuf->data;
        plen =  htobe16(sizeof *icmp6_h);
        nxt = IPPROTO_ICMPV6;

        ip6_h = (struct ip6_hdr *)p;
        icmp6_h = (struct icmp6_hdr *)((uint8_t *)ip6_h + sizeof *ip6_h);

        memcpy(p, sess->ue_ip.addr6, sizeof sess->ue_ip.addr6);
        p += sizeof sess->ue_ip.addr6;
        memcpy(p, dst_ipsub.sub, sizeof dst_ipsub.sub);
        p += sizeof dst_ipsub.sub;
        p += 2; memcpy(p, &plen, 2); p += 2;
        p += 3; *p = nxt; p += 1;

        icmp6_h->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6_h->icmp6_seq = rand();
        icmp6_h->icmp6_id = rand();

        icmp6_h->icmp6_cksum = ogs_in_cksum(
                (uint16_t *)ip6_h, sizeof *ip6_h + sizeof *icmp6_h);

        ip6_h->ip6_flow = htobe32(0x60000001);
        ip6_h->ip6_plen = plen;
        ip6_h->ip6_nxt = nxt;;
        ip6_h->ip6_hlim = 0xff;
        memcpy(ip6_h->ip6_src.s6_addr,
                sess->ue_ip.addr6, sizeof sess->ue_ip.addr6);
        memcpy(ip6_h->ip6_dst.s6_addr, dst_ipsub.sub, sizeof dst_ipsub.sub);
    } else {
        ogs_fatal("Invalid family[%d]", dst_ipsub.family);
        ogs_assert_if_reached();
    }

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_GPDU;

    if (bearer->qfi) {
        header_desc.teid = sess->upf_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;
    } else if (bearer->ebi) {
        header_desc.teid = bearer->sgw_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

int test_gtpu_send_slacc_rs(ogs_socknode_t *node, test_bearer_t *bearer)
{
    test_sess_t *sess = NULL;

    ogs_gtp2_header_desc_t header_desc;

    ogs_pkbuf_t *pkbuf = NULL;
    struct ip6_hdr *ip6_h = NULL;
    uint8_t *src_addr = NULL;

    const char *payload =
        "6000000000083aff fe80000000000000 0000000000000002"
        "ff02000000000000 0000000000000002 85007d3500000000";
    unsigned char tmp[OGS_HUGE_LEN];
    int payload_len = 48;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    pkbuf = ogs_pkbuf_alloc(
            NULL, 200 /* enough for ICMP; use smaller buffer */);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, 200-OGS_GTPV1U_5GC_HEADER_LEN);
    memset(pkbuf->data, 0, pkbuf->len);

    ogs_hex_from_string(payload, tmp, sizeof(tmp));
    memcpy(pkbuf->data, tmp, payload_len);

    ip6_h = pkbuf->data;
    ogs_assert(ip6_h);

    src_addr = (uint8_t *)ip6_h->ip6_src.s6_addr;
    ogs_assert(src_addr);

    memcpy(src_addr + 8, sess->ue_ip.addr6 + 8, 8);

    ogs_pkbuf_trim(pkbuf, payload_len);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_GPDU;
    header_desc.flags = OGS_GTPU_FLAGS_S;

    if (bearer->qfi) {
/*
 * Discussion #1506
 * Router Soliciation should include QFI in 5G Core
 */
        header_desc.teid = sess->upf_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        header_desc.teid = bearer->sgw_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

int test_gtpu_send_slacc_rs_with_unspecified_source_address(
        ogs_socknode_t *node, test_bearer_t *bearer)
{
    test_sess_t *sess = NULL;

    ogs_gtp2_header_desc_t header_desc;

    ogs_pkbuf_t *pkbuf = NULL;
    struct ip6_hdr *ip6_h = NULL;
    uint8_t *src_addr = NULL;

    const char *payload =
        "60000000"
        "00103afffe800000 0000000074ee25ff fee4b579ff020000 0000000000000000"
        "000000028500da95 00000000010176ee 25e4b579";
    unsigned char tmp[OGS_HUGE_LEN];
    int payload_len = 56;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    pkbuf = ogs_pkbuf_alloc(
            NULL, 200 /* enough for ICMP; use smaller buffer */);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, 200-OGS_GTPV1U_5GC_HEADER_LEN);
    memset(pkbuf->data, 0, pkbuf->len);

    ogs_hex_from_string(payload, tmp, sizeof(tmp));
    memcpy(pkbuf->data, tmp, payload_len);

    ogs_pkbuf_trim(pkbuf, payload_len);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_GPDU;
    header_desc.flags = OGS_GTPU_FLAGS_S;

    if (bearer->qfi) {
        header_desc.teid = sess->upf_n3_teid;
/*
 * Discussion #1506
 * Router Soliciation should include QFI in 5G Core
 */
        header_desc.teid = sess->upf_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        header_desc.teid = bearer->sgw_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

int test_gtpu_send_end_marker(
        ogs_socknode_t *node, test_bearer_t *bearer)
{
    test_sess_t *sess = NULL;

    ogs_gtp2_header_desc_t header_desc;

    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_END_MARKER;

    if (bearer->qfi) {
        /* 5GC */
        header_desc.teid = sess->upf_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        /* EPC */
        header_desc.teid = bearer->sgw_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

int test_gtpu_send_error_indication(
        ogs_socknode_t *node, test_bearer_t *bearer)
{
    test_sess_t *sess = NULL;
    uint32_t teid = 0;

    ogs_gtp2_header_desc_t header_desc;

    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_ERR_IND;
    header_desc.flags = OGS_GTPU_FLAGS_S|OGS_GTPU_FLAGS_E;
    header_desc.udp.presence = true;
    header_desc.udp.port = 0;

    if (bearer->qfi) {
        /* 5GC */
        teid = sess->gnb_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        /* EPC */
        teid = bearer->enb_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    pkbuf = ogs_gtp1_build_error_indication(teid, node->addr);
    ogs_assert(pkbuf);

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

int test_gtpu_send_indirect_data_forwarding(
        ogs_socknode_t *node, test_bearer_t *bearer, ogs_pkbuf_t *pkbuf)
{
    test_sess_t *sess = NULL;

    ogs_gtp2_header_desc_t header_desc;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);
    ogs_assert(pkbuf);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_GPDU;

    if (bearer->qfi) {
        header_desc.teid = sess->handover.upf_dl_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        header_desc.teid = bearer->handover.ul_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    header_desc.pdcp_number_presence = true;
    header_desc.pdcp_number = 0x4567;

    return test_gtpu_send(node, bearer, &header_desc, pkbuf);
}

/*
 * IPv6 / DHCPv6-PD helpers (tests/ipv6-pd)
 */

#include <poll.h>
#include <arpa/inet.h>

#define TEST_ND_OPT_RDNSS 25            /* RFC 8106 */

static const uint8_t all_routers_addr[OGS_IPV6_LEN] = {
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02
};
static const uint8_t unspecified_addr[OGS_IPV6_LEN];

typedef struct test_udp_hdr_s {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t cksum;
} __attribute__ ((packed)) test_udp_hdr_t;

static const char *addr6_str(const void *addr6, char *buf)
{
    const char *s = inet_ntop(AF_INET6, addr6, buf, INET6_ADDRSTRLEN);
    return s ? s : "?";
}

ogs_pkbuf_t *test_gtpu_read_timeout(ogs_socknode_t *node, int timeout_ms)
{
    struct pollfd pfd;
    int rc;

    ogs_assert(node);
    ogs_assert(node->sock);

    memset(&pfd, 0, sizeof pfd);
    pfd.fd = node->sock->fd;
    pfd.events = POLLIN;

    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    if (rc == 0)
        return NULL;
    if (rc < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "poll() failed");
        return NULL;
    }

    return test_gtpu_read(node);
}

static uint32_t cksum_add(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)data[0] << 8;
    return sum;
}

uint16_t test_in6_cksum(const uint8_t *src, const uint8_t *dst,
        uint8_t nxt, const void *payload, size_t len)
{
    uint8_t ph[40];
    uint32_t sum;

    ogs_assert(src);
    ogs_assert(dst);
    ogs_assert(payload || len == 0);

    /* RFC 8200 section 8.1 pseudo-header */
    memset(ph, 0, sizeof ph);
    memcpy(ph, src, OGS_IPV6_LEN);
    memcpy(ph + OGS_IPV6_LEN, dst, OGS_IPV6_LEN);
    ph[32] = (len >> 24) & 0xff;
    ph[33] = (len >> 16) & 0xff;
    ph[34] = (len >> 8) & 0xff;
    ph[35] = len & 0xff;
    ph[39] = nxt;

    sum = cksum_add(0, ph, sizeof ph);
    sum = cksum_add(sum, payload, len);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htobe16((uint16_t)~sum);
}

void test_gtpu_link_local(test_sess_t *sess, uint8_t *addr6)
{
    ogs_assert(sess);
    ogs_assert(addr6);

    memset(addr6, 0, OGS_IPV6_LEN);
    addr6[0] = 0xfe;
    addr6[1] = 0x80;
    memcpy(addr6 + 8, sess->ue_ip.addr6 + 8, 8);
}

void test_gtpu_solicited_node(const uint8_t *addr6, uint8_t *out6)
{
    ogs_assert(addr6);
    ogs_assert(out6);

    memset(out6, 0, OGS_IPV6_LEN);
    out6[0] = 0xff;
    out6[1] = 0x02;
    out6[11] = 0x01;
    out6[12] = 0xff;
    memcpy(out6 + 13, addr6 + 13, 3);
}

void test_gtpu_mac(test_sess_t *sess, uint8_t *mac)
{
    const uint8_t *iid = NULL;

    ogs_assert(sess);
    ogs_assert(mac);

    /* EUI-64 -> MAC-48 (drop ff:fe, toggle the U/L bit) */
    iid = sess->ue_ip.addr6 + 8;
    mac[0] = iid[0] ^ 0x02;
    mac[1] = iid[1];
    mac[2] = iid[2];
    mac[3] = iid[5];
    mac[4] = iid[6];
    mac[5] = iid[7];
}

static ogs_pkbuf_t *ipv6_pkbuf_alloc(size_t len)
{
    ogs_pkbuf_t *pkbuf = NULL;

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_GTPV1U_5GC_HEADER_LEN + len);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, len);
    memset(pkbuf->data, 0, len);

    return pkbuf;
}

static void ipv6_header_init(struct ip6_hdr *ip6_h,
        const uint8_t *src6, const uint8_t *dst6,
        uint8_t nxt, uint16_t plen, uint8_t hlim)
{
    ip6_h->ip6_flow = htobe32(0x60000000);
    ip6_h->ip6_plen = htobe16(plen);
    ip6_h->ip6_nxt = nxt;
    ip6_h->ip6_hlim = hlim;
    memcpy(ip6_h->ip6_src.s6_addr, src6, OGS_IPV6_LEN);
    memcpy(ip6_h->ip6_dst.s6_addr, dst6, OGS_IPV6_LEN);
}

int test_gtpu_send_ipv6(
        ogs_socknode_t *node, test_bearer_t *bearer, ogs_pkbuf_t *ip6pkt)
{
    test_sess_t *sess = NULL;
    ogs_gtp2_header_desc_t header_desc;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);
    ogs_assert(ip6pkt);
    ogs_assert(ogs_pkbuf_headroom(ip6pkt) >= OGS_GTPV1U_5GC_HEADER_LEN);

    memset(&header_desc, 0, sizeof(header_desc));

    header_desc.type = OGS_GTPU_MSGTYPE_GPDU;
    header_desc.flags = OGS_GTPU_FLAGS_S;

    if (bearer->qfi) {
        /* 5GC: uplink PDU session information with QFI (Discussion #1506) */
        header_desc.teid = sess->upf_n3_teid;
        header_desc.pdu_type =
            OGS_GTP2_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
        header_desc.qos_flow_identifier = bearer->qfi;

    } else if (bearer->ebi) {
        /* EPC */
        header_desc.teid = bearer->sgw_s1u_teid;

    } else {
        ogs_fatal("No QFI[%d] and EBI[%d]", bearer->qfi, bearer->ebi);
        ogs_assert_if_reached();
    }

    return test_gtpu_send(node, bearer, &header_desc, ip6pkt);
}

int test_gtpu_send_udp(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6,
        uint16_t src_port, uint16_t dst_port,
        const void *payload, size_t payload_len)
{
    test_sess_t *sess = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    struct ip6_hdr *ip6_h = NULL;
    test_udp_hdr_t *udp_h = NULL;
    uint8_t link_local[OGS_IPV6_LEN];
    size_t udp_len;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);
    ogs_assert(dst6);
    ogs_assert(payload || payload_len == 0);

    if (!src6) {
        test_gtpu_link_local(sess, link_local);
        src6 = link_local;
    }

    udp_len = sizeof *udp_h + payload_len;
    pkbuf = ipv6_pkbuf_alloc(sizeof *ip6_h + udp_len);

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    udp_h = (test_udp_hdr_t *)(ip6_h + 1);
    if (payload_len)
        memcpy(udp_h + 1, payload, payload_len);

    udp_h->src = htobe16(src_port);
    udp_h->dst = htobe16(dst_port);
    udp_h->len = htobe16(udp_len);
    udp_h->cksum = 0;
    udp_h->cksum = test_in6_cksum(src6, dst6, IPPROTO_UDP, udp_h, udp_len);
    if (udp_h->cksum == 0)
        udp_h->cksum = 0xffff;

    ipv6_header_init(ip6_h, src6, dst6, IPPROTO_UDP, udp_len, 255);

    return test_gtpu_send_ipv6(node, bearer, pkbuf);
}

int test_gtpu_send_dhcpv6(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6,
        const void *dhcp, size_t dhcp_len)
{
    if (!dst6)
        dst6 = test_dhcpv6_all_servers_addr;

    return test_gtpu_send_udp(node, bearer, src6, dst6,
            TEST_DHCPV6_CLIENT_PORT, TEST_DHCPV6_SERVER_PORT, dhcp, dhcp_len);
}

/*
 * ICMPv6 Neighbour Discovery message: type/code/checksum, body_len bytes
 * of body (starting with the 4 reserved/flags octets), optionally a
 * link-layer address option (type 1 = source, 2 = target) carrying the UE
 * MAC. Hop limit 255 as RFC 4861 requires.
 */
static ogs_pkbuf_t *nd_pkbuf(test_sess_t *sess,
        const uint8_t *src6, const uint8_t *dst6,
        uint8_t type, const void *body, size_t body_len, uint8_t lladdr_type)
{
    ogs_pkbuf_t *pkbuf = NULL;
    struct ip6_hdr *ip6_h = NULL;
    struct icmp6_hdr *icmp6_h = NULL;
    uint8_t *p = NULL;
    size_t plen;

    plen = 4 + body_len + (lladdr_type ? 8 : 0);
    pkbuf = ipv6_pkbuf_alloc(sizeof *ip6_h + plen);

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    icmp6_h = (struct icmp6_hdr *)(ip6_h + 1);
    icmp6_h->icmp6_type = type;
    icmp6_h->icmp6_code = 0;

    p = (uint8_t *)icmp6_h + 4;
    if (body_len) {
        memcpy(p, body, body_len);
        p += body_len;
    }
    if (lladdr_type) {
        p[0] = lladdr_type;
        p[1] = 1;       /* 8 octets */
        test_gtpu_mac(sess, p + 2);
    }

    icmp6_h->icmp6_cksum = 0;
    icmp6_h->icmp6_cksum = test_in6_cksum(src6, dst6,
            IPPROTO_ICMPV6, icmp6_h, plen);

    ipv6_header_init(ip6_h, src6, dst6, IPPROTO_ICMPV6, plen, 255);

    return pkbuf;
}

int test_gtpu_send_rs_from(
        ogs_socknode_t *node, test_bearer_t *bearer, const uint8_t *src6)
{
    test_sess_t *sess = NULL;
    uint8_t link_local[OGS_IPV6_LEN];
    uint8_t reserved[4] = { 0, 0, 0, 0 };
    bool unspecified;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);

    if (!src6) {
        test_gtpu_link_local(sess, link_local);
        src6 = link_local;
    }
    unspecified = memcmp(src6, unspecified_addr, OGS_IPV6_LEN) == 0;

    return test_gtpu_send_ipv6(node, bearer,
            nd_pkbuf(sess, src6, all_routers_addr, ND_ROUTER_SOLICIT,
                reserved, sizeof reserved,
                unspecified ? 0 : ND_OPT_SOURCE_LINKADDR));
}

int test_gtpu_send_ns(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const uint8_t *dst6, const uint8_t *target6)
{
    test_sess_t *sess = NULL;
    uint8_t link_local[OGS_IPV6_LEN], solicited_node[OGS_IPV6_LEN];
    uint8_t body[4 + OGS_IPV6_LEN];
    bool unspecified;

    ogs_assert(bearer);
    sess = bearer->sess;
    ogs_assert(sess);
    ogs_assert(target6);

    if (!src6) {
        test_gtpu_link_local(sess, link_local);
        src6 = link_local;
    }
    if (!dst6) {
        test_gtpu_solicited_node(target6, solicited_node);
        dst6 = solicited_node;
    }
    unspecified = memcmp(src6, unspecified_addr, OGS_IPV6_LEN) == 0;

    memset(body, 0, 4);                     /* reserved */
    memcpy(body + 4, target6, OGS_IPV6_LEN);

    return test_gtpu_send_ipv6(node, bearer,
            nd_pkbuf(sess, src6, dst6, ND_NEIGHBOR_SOLICIT,
                body, sizeof body,
                unspecified ? 0 : ND_OPT_SOURCE_LINKADDR));
}

int test_gtpu_send_ping_from(
        ogs_socknode_t *node, test_bearer_t *bearer,
        const uint8_t *src6, const char *dst_ip)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_ipsubnet_t dst_ipsub;
    struct ip6_hdr *ip6_h = NULL;
    struct icmp6_hdr *icmp6_h = NULL;

    ogs_assert(bearer);
    ogs_assert(src6);
    ogs_assert(dst_ip);

    rv = ogs_ipsubnet(&dst_ipsub, dst_ip, NULL);
    ogs_assert(rv == OGS_OK);
    ogs_assert(dst_ipsub.family == AF_INET6);

    pkbuf = ipv6_pkbuf_alloc(sizeof *ip6_h + sizeof *icmp6_h);

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    icmp6_h = (struct icmp6_hdr *)(ip6_h + 1);

    icmp6_h->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_h->icmp6_code = 0;
    icmp6_h->icmp6_id = rand();
    icmp6_h->icmp6_seq = rand();
    icmp6_h->icmp6_cksum = 0;
    icmp6_h->icmp6_cksum = test_in6_cksum(src6, (uint8_t *)dst_ipsub.sub,
            IPPROTO_ICMPV6, icmp6_h, sizeof *icmp6_h);

    ipv6_header_init(ip6_h, src6, (uint8_t *)dst_ipsub.sub,
            IPPROTO_ICMPV6, sizeof *icmp6_h, 64);

    return test_gtpu_send_ipv6(node, bearer, pkbuf);
}

int test_gtpu_parse_ipv6(ogs_pkbuf_t *pkbuf,
        struct ip6_hdr **ip6_h, uint8_t **payload, size_t *payload_len)
{
    ogs_gtp2_header_t *gtp_h = NULL;
    struct ip6_hdr *h = NULL;
    int hlen;
    size_t remaining, plen;

    ogs_assert(pkbuf);
    ogs_assert(ip6_h);
    ogs_assert(payload);
    ogs_assert(payload_len);

    if (pkbuf->len < OGS_GTPV1U_HEADER_LEN) {
        ogs_error("Short GTP-U packet [%d]", pkbuf->len);
        return OGS_ERROR;
    }

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP1_VERSION_1 ||
        gtp_h->type != OGS_GTPU_MSGTYPE_GPDU) {
        ogs_error("Not a G-PDU: version[%d] type[%d]",
                gtp_h->version, gtp_h->type);
        return OGS_ERROR;
    }

    hlen = ogs_gtpu_parse_header(NULL, pkbuf);
    if (hlen < 0 || hlen > pkbuf->len) {
        ogs_error("Invalid GTP-U header");
        return OGS_ERROR;
    }

    remaining = pkbuf->len - hlen;
    if (remaining < sizeof(struct ip6_hdr)) {
        ogs_error("Short G-PDU payload [%zu]", remaining);
        return OGS_ERROR;
    }

    h = (struct ip6_hdr *)(pkbuf->data + hlen);
    if ((h->ip6_vfc >> 4) != 6) {
        ogs_error("Not IPv6: version[%d]", h->ip6_vfc >> 4);
        return OGS_ERROR;
    }

    plen = be16toh(h->ip6_plen);
    if (plen > remaining - sizeof(struct ip6_hdr)) {
        ogs_error("IPv6 payload length [%zu] exceeds packet [%zu]",
                plen, remaining);
        return OGS_ERROR;
    }

    *ip6_h = h;
    *payload = (uint8_t *)h + sizeof(struct ip6_hdr);
    *payload_len = plen;

    return OGS_OK;
}

int test_gtpu_parse_ra(ogs_pkbuf_t *pkbuf, test_gtpu_ra_t *ra)
{
    struct ip6_hdr *ip6_h = NULL;
    struct nd_router_advert *advert_h = NULL;
    uint8_t *payload = NULL, *p = NULL;
    size_t payload_len, remaining;

    ogs_assert(pkbuf);
    ogs_assert(ra);

    memset(ra, 0, sizeof *ra);

    if (test_gtpu_parse_ipv6(pkbuf, &ip6_h, &payload, &payload_len) != OGS_OK)
        return OGS_ERROR;

    if (ip6_h->ip6_nxt != IPPROTO_ICMPV6) {
        ogs_error("Not ICMPv6: next header[%d]", ip6_h->ip6_nxt);
        return OGS_ERROR;
    }
    if (payload_len < sizeof *advert_h) {
        ogs_error("Short ICMPv6 payload [%zu]", payload_len);
        return OGS_ERROR;
    }

    advert_h = (struct nd_router_advert *)payload;
    if (advert_h->nd_ra_type != ND_ROUTER_ADVERT || advert_h->nd_ra_code) {
        ogs_error("Not a Router Advertisement: type[%d] code[%d]",
                advert_h->nd_ra_type, advert_h->nd_ra_code);
        return OGS_ERROR;
    }

    if (test_in6_cksum(ip6_h->ip6_src.s6_addr, ip6_h->ip6_dst.s6_addr,
                IPPROTO_ICMPV6, payload, payload_len) != 0) {
        ogs_error("Router Advertisement checksum mismatch");
        return OGS_ERROR;
    }

    memcpy(ra->src, ip6_h->ip6_src.s6_addr, OGS_IPV6_LEN);
    memcpy(ra->dst, ip6_h->ip6_dst.s6_addr, OGS_IPV6_LEN);
    ra->hlim = ip6_h->ip6_hlim;
    ra->cur_hop_limit = advert_h->nd_ra_curhoplimit;
    ra->flags = advert_h->nd_ra_flags_reserved;
    ra->router_lifetime = be16toh(advert_h->nd_ra_router_lifetime);

    p = payload + sizeof *advert_h;
    remaining = payload_len - sizeof *advert_h;

    while (remaining >= 8) {
        uint8_t type = p[0];
        size_t olen = (size_t)p[1] * 8;

        if (olen == 0 || olen > remaining) {
            ogs_error("Invalid ND option: type[%d] len[%zu]", type, olen);
            return OGS_ERROR;
        }

        if (type == ND_OPT_PREFIX_INFORMATION) {
            struct nd_opt_prefix_info *pi = (struct nd_opt_prefix_info *)p;
            if (olen != sizeof *pi) {
                ogs_error("Invalid Prefix Information length [%zu]", olen);
                return OGS_ERROR;
            }
            if (!ra->has_prefix) {
                ra->has_prefix = true;
                ra->prefixlen = pi->nd_opt_pi_prefix_len;
                memcpy(ra->prefix, pi->nd_opt_pi_prefix.s6_addr,
                        OGS_IPV6_LEN);
                ra->pi_flags = pi->nd_opt_pi_flags_reserved;
                ra->valid = be32toh(pi->nd_opt_pi_valid_time);
                ra->preferred = be32toh(pi->nd_opt_pi_preferred_time);
            }
        } else if (type == ND_OPT_MTU) {
            struct nd_opt_mtu *mtu = (struct nd_opt_mtu *)p;
            if (olen != sizeof *mtu) {
                ogs_error("Invalid MTU option length [%zu]", olen);
                return OGS_ERROR;
            }
            ra->has_mtu = true;
            ra->mtu = be32toh(mtu->nd_opt_mtu_mtu);
        } else if (type == ND_OPT_SOURCE_LINKADDR) {
            if (olen != 8) {
                ogs_error("Invalid SLLA option length [%zu]", olen);
                return OGS_ERROR;
            }
            ra->has_slla = true;
            memcpy(ra->slla, p + 2, 6);
        } else if (type == TEST_ND_OPT_RDNSS) {
            size_t i, n;
            uint32_t lifetime;
            if (olen < 8 + OGS_IPV6_LEN || (olen - 8) % OGS_IPV6_LEN) {
                ogs_error("Invalid RDNSS option length [%zu]", olen);
                return OGS_ERROR;
            }
            ra->has_rdnss = true;
            memcpy(&lifetime, p + 4, 4);
            ra->rdnss_lifetime = be32toh(lifetime);
            n = (olen - 8) / OGS_IPV6_LEN;
            for (i = 0; i < n && ra->num_of_rdnss < 4; i++) {
                memcpy(ra->rdnss[ra->num_of_rdnss++],
                        p + 8 + i * OGS_IPV6_LEN, OGS_IPV6_LEN);
            }
        }

        p += olen;
        remaining -= olen;
    }

    return OGS_OK;
}

int test_gtpu_parse_na(ogs_pkbuf_t *pkbuf, test_gtpu_na_t *na)
{
    struct ip6_hdr *ip6_h = NULL;
    struct icmp6_hdr *icmp6_h = NULL;
    uint8_t *payload = NULL, *p = NULL;
    size_t payload_len, remaining;
    const size_t na_len = 8 + OGS_IPV6_LEN;    /* header + flags + target */

    ogs_assert(pkbuf);
    ogs_assert(na);

    memset(na, 0, sizeof *na);

    if (test_gtpu_parse_ipv6(pkbuf, &ip6_h, &payload, &payload_len) != OGS_OK)
        return OGS_ERROR;

    if (ip6_h->ip6_nxt != IPPROTO_ICMPV6) {
        ogs_error("Not ICMPv6: next header[%d]", ip6_h->ip6_nxt);
        return OGS_ERROR;
    }
    if (payload_len < na_len) {
        ogs_error("Short ICMPv6 payload [%zu]", payload_len);
        return OGS_ERROR;
    }

    icmp6_h = (struct icmp6_hdr *)payload;
    if (icmp6_h->icmp6_type != ND_NEIGHBOR_ADVERT || icmp6_h->icmp6_code) {
        ogs_error("Not a Neighbour Advertisement: type[%d] code[%d]",
                icmp6_h->icmp6_type, icmp6_h->icmp6_code);
        return OGS_ERROR;
    }

    if (test_in6_cksum(ip6_h->ip6_src.s6_addr, ip6_h->ip6_dst.s6_addr,
                IPPROTO_ICMPV6, payload, payload_len) != 0) {
        ogs_error("Neighbour Advertisement checksum mismatch");
        return OGS_ERROR;
    }

    memcpy(na->src, ip6_h->ip6_src.s6_addr, OGS_IPV6_LEN);
    memcpy(na->dst, ip6_h->ip6_dst.s6_addr, OGS_IPV6_LEN);
    na->hlim = ip6_h->ip6_hlim;
    /* R|S|O live in the first octet of the "flags/reserved" word */
    na->flags = payload[4] & (TEST_ND_NA_FLAG_ROUTER |
            TEST_ND_NA_FLAG_SOLICITED | TEST_ND_NA_FLAG_OVERRIDE);
    memcpy(na->target, payload + 8, OGS_IPV6_LEN);

    p = payload + na_len;
    remaining = payload_len - na_len;

    while (remaining >= 8) {
        uint8_t type = p[0];
        size_t olen = (size_t)p[1] * 8;

        if (olen == 0 || olen > remaining) {
            ogs_error("Invalid ND option: type[%d] len[%zu]", type, olen);
            return OGS_ERROR;
        }

        if (type == ND_OPT_TARGET_LINKADDR) {
            if (olen != 8) {
                ogs_error("Invalid TLLA option length [%zu]", olen);
                return OGS_ERROR;
            }
            na->has_tlla = true;
            memcpy(na->tlla, p + 2, 6);
        }

        p += olen;
        remaining -= olen;
    }

    return OGS_OK;
}

int test_gtpu_parse_dhcpv6_reply(ogs_pkbuf_t *pkbuf, test_bearer_t *bearer,
        const uint8_t *client6, test_dhcpv6_msg_t *msg)
{
    struct ip6_hdr *ip6_h = NULL;
    test_udp_hdr_t *udp_h = NULL;
    uint8_t *payload = NULL;
    size_t payload_len, udp_len;
    uint8_t link_local[OGS_IPV6_LEN];
    char buf[INET6_ADDRSTRLEN];

    ogs_assert(pkbuf);
    ogs_assert(bearer);
    ogs_assert(bearer->sess);
    ogs_assert(msg);

    if (!client6) {
        test_gtpu_link_local(bearer->sess, link_local);
        client6 = link_local;
    }

    if (test_gtpu_parse_ipv6(pkbuf, &ip6_h, &payload, &payload_len) != OGS_OK)
        return OGS_ERROR;

    if (ip6_h->ip6_nxt != IPPROTO_UDP) {
        ogs_error("Not UDP: next header[%d]", ip6_h->ip6_nxt);
        return OGS_ERROR;
    }
    if (payload_len < sizeof *udp_h) {
        ogs_error("Short UDP payload [%zu]", payload_len);
        return OGS_ERROR;
    }

    udp_h = (test_udp_hdr_t *)payload;
    udp_len = be16toh(udp_h->len);
    if (udp_len < sizeof *udp_h || udp_len > payload_len) {
        ogs_error("Invalid UDP length [%zu] (payload %zu)",
                udp_len, payload_len);
        return OGS_ERROR;
    }
    if (be16toh(udp_h->src) != TEST_DHCPV6_SERVER_PORT ||
        be16toh(udp_h->dst) != TEST_DHCPV6_CLIENT_PORT) {
        ogs_error("Not DHCPv6 server->client: ports %d -> %d",
                be16toh(udp_h->src), be16toh(udp_h->dst));
        return OGS_ERROR;
    }
    if (memcmp(ip6_h->ip6_dst.s6_addr, client6, OGS_IPV6_LEN) != 0) {
        ogs_error("DHCPv6 reply to unexpected destination %s",
                addr6_str(ip6_h->ip6_dst.s6_addr, buf));
        return OGS_ERROR;
    }
    if (udp_h->cksum == 0 ||
        test_in6_cksum(ip6_h->ip6_src.s6_addr, ip6_h->ip6_dst.s6_addr,
                IPPROTO_UDP, udp_h, udp_len) != 0) {
        ogs_error("DHCPv6 reply UDP checksum mismatch");
        return OGS_ERROR;
    }

    if (test_dhcpv6_parse(msg,
                payload + sizeof *udp_h, udp_len - sizeof *udp_h) != OGS_OK) {
        ogs_error("Malformed DHCPv6 message [%zu bytes]",
                udp_len - sizeof *udp_h);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int test_gtpu_parse_ping_reply(
        ogs_pkbuf_t *pkbuf, const uint8_t *expected_dst6)
{
    struct ip6_hdr *ip6_h = NULL;
    struct icmp6_hdr *icmp6_h = NULL;
    uint8_t *payload = NULL;
    size_t payload_len;
    char buf[INET6_ADDRSTRLEN];

    ogs_assert(pkbuf);
    ogs_assert(expected_dst6);

    if (test_gtpu_parse_ipv6(pkbuf, &ip6_h, &payload, &payload_len) != OGS_OK)
        return OGS_ERROR;

    if (ip6_h->ip6_nxt != IPPROTO_ICMPV6) {
        ogs_error("Not ICMPv6: next header[%d]", ip6_h->ip6_nxt);
        return OGS_ERROR;
    }
    if (payload_len < sizeof *icmp6_h) {
        ogs_error("Short ICMPv6 payload [%zu]", payload_len);
        return OGS_ERROR;
    }

    icmp6_h = (struct icmp6_hdr *)payload;
    if (icmp6_h->icmp6_type != ICMP6_ECHO_REPLY) {
        ogs_error("Not an echo reply: ICMPv6 type[%d]", icmp6_h->icmp6_type);
        return OGS_ERROR;
    }
    if (memcmp(ip6_h->ip6_dst.s6_addr, expected_dst6, OGS_IPV6_LEN) != 0) {
        ogs_error("Echo reply to unexpected destination %s",
                addr6_str(ip6_h->ip6_dst.s6_addr, buf));
        return OGS_ERROR;
    }
    if (test_in6_cksum(ip6_h->ip6_src.s6_addr, ip6_h->ip6_dst.s6_addr,
                IPPROTO_ICMPV6, payload, payload_len) != 0) {
        ogs_error("Echo reply checksum mismatch");
        return OGS_ERROR;
    }

    return OGS_OK;
}
