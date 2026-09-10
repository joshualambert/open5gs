/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#include <arpa/inet.h>

#include "ogs-gtp.h"
#include "core/abts.h"

/*****************************************************************************
 * Helpers
 *****************************************************************************/

static void ip6(uint8_t out[OGS_IPV6_LEN], const char *str)
{
    int rv = inet_pton(AF_INET6, str, out);
    ogs_assert(rv == 1);
}

/*
 * Parse from a heap buffer of exactly `len` bytes so that AddressSanitizer
 * catches any read past the end of the message.
 */
static int parse_exact(ogs_dhcpv6_message_t *msg,
        const uint8_t *data, size_t len)
{
    uint8_t *copy = NULL;
    int rv;

    if (len) {
        copy = ogs_malloc(len);
        ogs_assert(copy);
        memcpy(copy, data, len);
    }
    rv = ogs_dhcpv6_parse(msg, copy, len);
    if (copy)
        ogs_free(copy);
    return rv;
}

/* Build into a heap buffer of exactly `buflen` bytes */
static int build_exact(const ogs_dhcpv6_message_t *msg,
        uint8_t *out, size_t buflen)
{
    uint8_t *buf = NULL;
    int rv;

    if (buflen) {
        buf = ogs_malloc(buflen);
        ogs_assert(buf);
    }
    rv = ogs_dhcpv6_build(msg, buf, buflen);
    if (rv > 0 && out)
        memcpy(out, buf, rv);
    if (buf)
        ogs_free(buf);
    return rv;
}

static const uint8_t client_duid_ll[] = {
    0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const uint8_t server_duid_uuid[] = {
    0x00, 0x04,
    0x8b, 0xf3, 0x4a, 0x1e, 0x12, 0x34, 0x4d, 0x9c,
    0xa1, 0x77, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
};

static void fill_solicit(ogs_dhcpv6_message_t *msg)
{
    memset(msg, 0, sizeof(*msg));

    msg->msg_type = OGS_DHCPV6_SOLICIT;
    msg->transaction_id = 0xabcdef;

    msg->client_id.len = sizeof(client_duid_ll);
    memcpy(msg->client_id.data, client_duid_ll, sizeof(client_duid_ll));

    msg->num_of_ia_pd = 1;
    msg->ia_pd[0].iaid = 1;
    msg->ia_pd[0].num_of_prefix = 1;
    msg->ia_pd[0].prefix[0].prefixlen = 56;      /* hint ::/56 */

    msg->num_of_oro = 2;
    msg->oro[0] = OGS_DHCPV6_OPTION_DNS_SERVERS;
    msg->oro[1] = OGS_DHCPV6_OPTION_PD_EXCLUDE;

    msg->elapsed_time.presence = true;
    msg->elapsed_time.value = 0x0123;

    msg->rapid_commit = true;
}

/* 4 + CLIENTID(14) + IA_PD(4+12+29) + ORO(8) + ELAPSED(6) + RAPID(4) */
#define SOLICIT_WIRE_LEN 81

static void fill_reply(ogs_dhcpv6_message_t *msg)
{
    ogs_dhcpv6_iaprefix_t *iaprefix = NULL;

    memset(msg, 0, sizeof(*msg));

    msg->msg_type = OGS_DHCPV6_REPLY;
    msg->transaction_id = 0x123456;

    msg->server_id.len = sizeof(server_duid_uuid);
    memcpy(msg->server_id.data, server_duid_uuid, sizeof(server_duid_uuid));
    msg->client_id.len = sizeof(client_duid_ll);
    memcpy(msg->client_id.data, client_duid_ll, sizeof(client_duid_ll));

    msg->num_of_ia_pd = 1;
    msg->ia_pd[0].iaid = 1;
    msg->ia_pd[0].t1 = 1800;
    msg->ia_pd[0].t2 = 2880;
    msg->ia_pd[0].num_of_prefix = 1;
    iaprefix = &msg->ia_pd[0].prefix[0];
    iaprefix->preferred_lifetime = 3600;
    iaprefix->valid_lifetime = 7200;
    iaprefix->prefixlen = 56;
    ip6(iaprefix->prefix, "2001:db8:cafe:1200::");
    iaprefix->pd_exclude.presence = true;
    iaprefix->pd_exclude.prefixlen = 64;
    ip6(iaprefix->pd_exclude.prefix, "2001:db8:cafe:1200::");

    msg->num_of_dns = 2;
    ip6(msg->dns[0], "2001:4860:4860::8888");
    ip6(msg->dns[1], "2001:4860:4860::8844");

    msg->status.presence = true;
    msg->status.code = OGS_DHCPV6_STATUS_SUCCESS;
    strcpy(msg->status.message, "Granted");
}

/*
 * 4 + SERVERID(22) + CLIENTID(14) + IA_PD(4+12+IAPREFIX(4+25+PD_EXCLUDE(6)))
 *   + STATUS(4+2+7) + DNS(4+32)
 */
#define REPLY_WIRE_LEN 140

/*****************************************************************************
 * Round trips
 *****************************************************************************/

static void test_solicit_round_trip(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg, out;
    uint8_t buf[512];
    int len;

    fill_solicit(&msg);

    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, SOLICIT_WIRE_LEN, len);
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&out, buf, len));

    ABTS_INT_EQUAL(tc, OGS_DHCPV6_SOLICIT, out.msg_type);
    ABTS_INT_EQUAL(tc, 0xabcdef, out.transaction_id);
    ABTS_INT_EQUAL(tc, sizeof(client_duid_ll), out.client_id.len);
    ABTS_TRUE(tc, memcmp(out.client_id.data, client_duid_ll,
                sizeof(client_duid_ll)) == 0);
    ABTS_INT_EQUAL(tc, 0, out.server_id.len);

    ABTS_INT_EQUAL(tc, 1, out.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 1, out.ia_pd[0].iaid);
    ABTS_INT_EQUAL(tc, 0, out.ia_pd[0].t1);
    ABTS_INT_EQUAL(tc, 0, out.ia_pd[0].t2);
    ABTS_INT_EQUAL(tc, 1, out.ia_pd[0].num_of_prefix);
    ABTS_INT_EQUAL(tc, 0, out.ia_pd[0].prefix[0].preferred_lifetime);
    ABTS_INT_EQUAL(tc, 0, out.ia_pd[0].prefix[0].valid_lifetime);
    ABTS_INT_EQUAL(tc, 56, out.ia_pd[0].prefix[0].prefixlen);
    ABTS_TRUE(tc, memcmp(out.ia_pd[0].prefix[0].prefix,
                msg.ia_pd[0].prefix[0].prefix, OGS_IPV6_LEN) == 0);
    ABTS_TRUE(tc, out.ia_pd[0].prefix[0].pd_exclude.presence == false);
    ABTS_TRUE(tc, out.ia_pd[0].status.presence == false);
    ABTS_INT_EQUAL(tc, 0, out.num_of_ia_na);
    ABTS_TRUE(tc, out.ia_ta_presence == false);

    ABTS_INT_EQUAL(tc, 2, out.num_of_oro);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_OPTION_DNS_SERVERS, out.oro[0]);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_OPTION_PD_EXCLUDE, out.oro[1]);
    ABTS_TRUE(tc, ogs_dhcpv6_oro_contains(&out, OGS_DHCPV6_OPTION_DNS_SERVERS));
    ABTS_TRUE(tc, ogs_dhcpv6_oro_contains(&out, OGS_DHCPV6_OPTION_PD_EXCLUDE));
    ABTS_TRUE(tc, !ogs_dhcpv6_oro_contains(&out,
                OGS_DHCPV6_OPTION_DOMAIN_LIST));

    ABTS_TRUE(tc, out.rapid_commit == true);
    ABTS_TRUE(tc, out.reconf_accept == false);
    ABTS_TRUE(tc, out.elapsed_time.presence == true);
    ABTS_INT_EQUAL(tc, 0x0123, out.elapsed_time.value);
    ABTS_TRUE(tc, out.preference.presence == false);
    ABTS_TRUE(tc, out.status.presence == false);
    ABTS_INT_EQUAL(tc, 0, out.num_of_dns);
    ABTS_INT_EQUAL(tc, 0, out.sol_max_rt);
    ABTS_INT_EQUAL(tc, 0, out.inf_max_rt);

    /* Both were zeroed before being filled, so they must be identical */
    ABTS_TRUE(tc, memcmp(&msg, &out, sizeof(msg)) == 0);

    /* Wire header: msg-type + 24-bit transaction-id */
    ABTS_INT_EQUAL(tc, 0x01, buf[0]);
    ABTS_INT_EQUAL(tc, 0xab, buf[1]);
    ABTS_INT_EQUAL(tc, 0xcd, buf[2]);
    ABTS_INT_EQUAL(tc, 0xef, buf[3]);
}

static void test_reply_round_trip(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg, out;
    ogs_dhcpv6_iaprefix_t *iaprefix = NULL;
    uint8_t buf[512], addr[OGS_IPV6_LEN];
    /* OPTION_PD_EXCLUDE(67) len 2, prefix-len 64, subnet-id 0x00 */
    static const uint8_t pd_exclude_wire[] = {
        0x00, 0x43, 0x00, 0x02, 0x40, 0x00 };
    int len, i;
    bool found = false;

    fill_reply(&msg);

    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, REPLY_WIRE_LEN, len);
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&out, buf, len));

    ABTS_INT_EQUAL(tc, OGS_DHCPV6_REPLY, out.msg_type);
    ABTS_INT_EQUAL(tc, 0x123456, out.transaction_id);
    ABTS_INT_EQUAL(tc, sizeof(server_duid_uuid), out.server_id.len);
    ABTS_TRUE(tc, memcmp(out.server_id.data, server_duid_uuid,
                sizeof(server_duid_uuid)) == 0);
    ABTS_INT_EQUAL(tc, sizeof(client_duid_ll), out.client_id.len);
    ABTS_TRUE(tc, memcmp(out.client_id.data, client_duid_ll,
                sizeof(client_duid_ll)) == 0);

    ABTS_INT_EQUAL(tc, 1, out.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 1, out.ia_pd[0].iaid);
    ABTS_INT_EQUAL(tc, 1800, out.ia_pd[0].t1);
    ABTS_INT_EQUAL(tc, 2880, out.ia_pd[0].t2);
    ABTS_INT_EQUAL(tc, 1, out.ia_pd[0].num_of_prefix);
    ABTS_TRUE(tc, out.ia_pd[0].status.presence == false);

    iaprefix = &out.ia_pd[0].prefix[0];
    ABTS_INT_EQUAL(tc, 3600, iaprefix->preferred_lifetime);
    ABTS_INT_EQUAL(tc, 7200, iaprefix->valid_lifetime);
    ABTS_INT_EQUAL(tc, 56, iaprefix->prefixlen);
    ip6(addr, "2001:db8:cafe:1200::");
    ABTS_TRUE(tc, memcmp(iaprefix->prefix, addr, OGS_IPV6_LEN) == 0);
    ABTS_TRUE(tc, iaprefix->pd_exclude.presence == true);
    ABTS_INT_EQUAL(tc, 64, iaprefix->pd_exclude.prefixlen);
    ABTS_TRUE(tc, memcmp(iaprefix->pd_exclude.prefix, addr, OGS_IPV6_LEN) == 0);

    ABTS_INT_EQUAL(tc, 2, out.num_of_dns);
    ip6(addr, "2001:4860:4860::8888");
    ABTS_TRUE(tc, memcmp(out.dns[0], addr, OGS_IPV6_LEN) == 0);
    ip6(addr, "2001:4860:4860::8844");
    ABTS_TRUE(tc, memcmp(out.dns[1], addr, OGS_IPV6_LEN) == 0);

    ABTS_TRUE(tc, out.status.presence == true);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_STATUS_SUCCESS, out.status.code);
    ABTS_STR_EQUAL(tc, "Granted", out.status.message);

    ABTS_INT_EQUAL(tc, 0, out.num_of_oro);
    ABTS_INT_EQUAL(tc, 0, out.num_of_ia_na);
    ABTS_TRUE(tc, out.rapid_commit == false);
    ABTS_TRUE(tc, out.elapsed_time.presence == false);
    ABTS_TRUE(tc, out.preference.presence == false);

    ABTS_TRUE(tc, memcmp(&msg, &out, sizeof(msg)) == 0);

    /* The PD_EXCLUDE option must be encoded per RFC 6603 */
    for (i = 0; i + (int)sizeof(pd_exclude_wire) <= len; i++) {
        if (memcmp(buf + i, pd_exclude_wire, sizeof(pd_exclude_wire)) == 0) {
            found = true;
            break;
        }
    }
    ABTS_TRUE(tc, found);
}

static void test_reply_no_prefix_avail(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg, out;
    uint8_t buf[512];
    int len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = OGS_DHCPV6_REPLY;
    msg.transaction_id = 0x000001;
    msg.server_id.len = sizeof(server_duid_uuid);
    memcpy(msg.server_id.data, server_duid_uuid, sizeof(server_duid_uuid));
    msg.client_id.len = sizeof(client_duid_ll);
    memcpy(msg.client_id.data, client_duid_ll, sizeof(client_duid_ll));
    msg.num_of_ia_pd = 1;
    msg.ia_pd[0].iaid = 0x12345678;
    msg.ia_pd[0].status.presence = true;
    msg.ia_pd[0].status.code = OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL;
    strcpy(msg.ia_pd[0].status.message, "no prefix");

    len = build_exact(&msg, buf, sizeof(buf));
    /* 4 + 22 + 14 + IA_PD(4 + 12 + STATUS(4 + 2 + 9)) */
    ABTS_INT_EQUAL(tc, 4 + 22 + 14 + 31, len);
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&out, buf, len));

    ABTS_INT_EQUAL(tc, 1, out.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 0x12345678, out.ia_pd[0].iaid);
    ABTS_INT_EQUAL(tc, 0, out.ia_pd[0].num_of_prefix);
    ABTS_TRUE(tc, out.ia_pd[0].status.presence == true);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL,
            out.ia_pd[0].status.code);
    ABTS_STR_EQUAL(tc, "no prefix", out.ia_pd[0].status.message);
    ABTS_STR_EQUAL(tc, "NoPrefixAvail",
            ogs_dhcpv6_status_name(out.ia_pd[0].status.code));
    ABTS_TRUE(tc, out.status.presence == false);

    ABTS_TRUE(tc, memcmp(&msg, &out, sizeof(msg)) == 0);
}

/*****************************************************************************
 * RFC 6603 section 4.2 example
 *****************************************************************************/

static void test_rfc6603_example(abts_case *tc, void *data)
{
    uint8_t delegated[OGS_IPV6_LEN], excluded[OGS_IPV6_LEN];
    uint8_t out[OGS_IPV6_LEN], back[OGS_IPV6_LEN], out_len = 0;
    uint8_t buf[512];
    ogs_dhcpv6_message_t msg, parsed;
    /* OPTION_PD_EXCLUDE(67) len 2: prefix-len 64, 0xef << 3 = 0x78 */
    static const uint8_t wire[] = { 0x00, 0x43, 0x00, 0x02, 0x40, 0x78 };
    int len, i;
    bool found = false;

    ip6(delegated, "2001:db8:dead:bee0::");
    ip6(excluded, "2001:db8:dead:beef::");

    /* Encode: 2001:db8:dead:bee0::/59 excluding 2001:db8:dead:beef::/64 */
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 59, excluded, 64));
    ABTS_INT_EQUAL(tc, 1, out_len);
    ABTS_INT_EQUAL(tc, 0x78, out[0]);

    /* Decode it back */
    memset(back, 0xaa, sizeof(back));
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 59, out, out_len, 64));
    ABTS_TRUE(tc, memcmp(back, excluded, OGS_IPV6_LEN) == 0);

    /* Wrong subnet-id length is rejected */
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 59, out, 2, 64));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 59, out, 0, 64));
    /* excluded_len must be in [delegated_len+1, 128] */
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 59, out, 1, 59));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 64, excluded, 64));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 59, excluded, 129));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 128, excluded, 128));
    /* excluded prefix must be inside the delegated one */
    ip6(back, "2001:db8:dead:bf00::");
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 59, back, 64));

    /* Corner cases: /0 -> /128 needs 16 octets, /63 -> /64 one octet */
    ip6(excluded, "2001:db8:dead:beef:1:2:3:4");
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 0, excluded, 128));
    ABTS_INT_EQUAL(tc, 16, out_len);
    ABTS_TRUE(tc, memcmp(out, excluded, OGS_IPV6_LEN) == 0);
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 0, out, out_len, 128));
    ABTS_TRUE(tc, memcmp(back, excluded, OGS_IPV6_LEN) == 0);

    ip6(delegated, "2001:db8:dead:beee::");
    ip6(excluded, "2001:db8:dead:beef::");
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_encode(
                out, &out_len, delegated, 63, excluded, 64));
    ABTS_INT_EQUAL(tc, 1, out_len);
    ABTS_INT_EQUAL(tc, 0x80, out[0]);
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_dhcpv6_pd_exclude_decode(
                back, delegated, 63, out, out_len, 64));
    ABTS_TRUE(tc, memcmp(back, excluded, OGS_IPV6_LEN) == 0);

    /* Through the message builder / parser */
    ip6(delegated, "2001:db8:dead:bee0::");
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = OGS_DHCPV6_ADVERTISE;
    msg.transaction_id = 0x00abcd;
    msg.num_of_ia_pd = 1;
    msg.ia_pd[0].iaid = 7;
    msg.ia_pd[0].num_of_prefix = 1;
    msg.ia_pd[0].prefix[0].preferred_lifetime = 1;
    msg.ia_pd[0].prefix[0].valid_lifetime = 2;
    msg.ia_pd[0].prefix[0].prefixlen = 59;
    memcpy(msg.ia_pd[0].prefix[0].prefix, delegated, OGS_IPV6_LEN);
    msg.ia_pd[0].prefix[0].pd_exclude.presence = true;
    msg.ia_pd[0].prefix[0].pd_exclude.prefixlen = 64;
    memcpy(msg.ia_pd[0].prefix[0].pd_exclude.prefix, excluded, OGS_IPV6_LEN);

    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, 4 + 4 + 12 + 4 + 25 + 6, len);
    for (i = 0; i + (int)sizeof(wire) <= len; i++) {
        if (memcmp(buf + i, wire, sizeof(wire)) == 0) {
            found = true;
            break;
        }
    }
    ABTS_TRUE(tc, found);

    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&parsed, buf, len));
    ABTS_TRUE(tc, parsed.ia_pd[0].prefix[0].pd_exclude.presence == true);
    ABTS_INT_EQUAL(tc, 64, parsed.ia_pd[0].prefix[0].pd_exclude.prefixlen);
    ABTS_TRUE(tc, memcmp(parsed.ia_pd[0].prefix[0].pd_exclude.prefix,
                excluded, OGS_IPV6_LEN) == 0);
    ABTS_TRUE(tc, memcmp(&msg, &parsed, sizeof(msg)) == 0);
}

/*****************************************************************************
 * Hand-written Solicit (odhcp6c / dhclient style)
 *****************************************************************************/

static void test_parse_captured_solicit(abts_case *tc, void *data)
{
    static const uint8_t wire[] = {
        /* Solicit, transaction-id 0xa1b2c3 */
        0x01, 0xa1, 0xb2, 0xc3,
        /* CLIENTID: DUID-LLT, hw type 1, time 0x2a3b4c5d, 00:11:22:33:44:55 */
        0x00, 0x01, 0x00, 0x0e,
        0x00, 0x01, 0x00, 0x01, 0x2a, 0x3b, 0x4c, 0x5d,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        /* ELAPSED_TIME 0 */
        0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
        /* ORO: DNS_SERVERS, DOMAIN_LIST, PD_EXCLUDE */
        0x00, 0x06, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x43,
        /* IA_PD: IAID 1, T1 0, T2 0 */
        0x00, 0x19, 0x00, 0x29,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /*   IAPREFIX hint ::/56, lifetimes 0 */
        0x00, 0x1a, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* RAPID_COMMIT */
        0x00, 0x0e, 0x00, 0x00,
        /* RECONF_ACCEPT */
        0x00, 0x14, 0x00, 0x00,
        /* USER_CLASS (15): unknown to us, skipped */
        0x00, 0x0f, 0x00, 0x03, 0x41, 0x42, 0x43,
    };
    ogs_dhcpv6_message_t msg;
    uint8_t zero[OGS_IPV6_LEN];

    memset(zero, 0, sizeof(zero));
    ABTS_INT_EQUAL(tc, 98, sizeof(wire));
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, wire, sizeof(wire)));

    ABTS_INT_EQUAL(tc, OGS_DHCPV6_SOLICIT, msg.msg_type);
    ABTS_STR_EQUAL(tc, "Solicit", ogs_dhcpv6_msg_type_name(msg.msg_type));
    ABTS_INT_EQUAL(tc, 0xa1b2c3, msg.transaction_id);

    ABTS_INT_EQUAL(tc, 14, msg.client_id.len);
    ABTS_TRUE(tc, memcmp(msg.client_id.data, wire + 8, 14) == 0);
    ABTS_INT_EQUAL(tc, 0, msg.server_id.len);

    ABTS_TRUE(tc, msg.elapsed_time.presence == true);
    ABTS_INT_EQUAL(tc, 0, msg.elapsed_time.value);

    ABTS_INT_EQUAL(tc, 3, msg.num_of_oro);
    ABTS_INT_EQUAL(tc, 23, msg.oro[0]);
    ABTS_INT_EQUAL(tc, 24, msg.oro[1]);
    ABTS_INT_EQUAL(tc, 67, msg.oro[2]);
    ABTS_TRUE(tc, ogs_dhcpv6_oro_contains(&msg, OGS_DHCPV6_OPTION_PD_EXCLUDE));

    ABTS_INT_EQUAL(tc, 1, msg.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 1, msg.ia_pd[0].iaid);
    ABTS_INT_EQUAL(tc, 0, msg.ia_pd[0].t1);
    ABTS_INT_EQUAL(tc, 0, msg.ia_pd[0].t2);
    ABTS_INT_EQUAL(tc, 1, msg.ia_pd[0].num_of_prefix);
    ABTS_INT_EQUAL(tc, 0, msg.ia_pd[0].prefix[0].preferred_lifetime);
    ABTS_INT_EQUAL(tc, 0, msg.ia_pd[0].prefix[0].valid_lifetime);
    ABTS_INT_EQUAL(tc, 56, msg.ia_pd[0].prefix[0].prefixlen);
    ABTS_TRUE(tc, memcmp(msg.ia_pd[0].prefix[0].prefix, zero,
                OGS_IPV6_LEN) == 0);
    ABTS_TRUE(tc, msg.ia_pd[0].prefix[0].pd_exclude.presence == false);
    ABTS_TRUE(tc, msg.ia_pd[0].status.presence == false);

    ABTS_TRUE(tc, msg.rapid_commit == true);
    ABTS_TRUE(tc, msg.reconf_accept == true);
    ABTS_TRUE(tc, msg.preference.presence == false);
    ABTS_TRUE(tc, msg.status.presence == false);
    ABTS_INT_EQUAL(tc, 0, msg.num_of_ia_na);
    ABTS_TRUE(tc, msg.ia_ta_presence == false);
    ABTS_INT_EQUAL(tc, 0, msg.num_of_dns);
}

/*****************************************************************************
 * Rejection of malformed input
 *****************************************************************************/

#define HDR         0x01, 0x00, 0x00, 0x01          /* Solicit, xid 1 */
#define OPT(c, l)   0x00, (c), 0x00, (l)            /* code/len < 256 */
#define Z4          0x00, 0x00, 0x00, 0x00
#define Z8          Z4, Z4
#define Z12         Z8, Z4
#define Z16         Z8, Z8
#define IA_PD_HDR   Z12                             /* IAID, T1, T2 */
#define IAPREFIX56  Z8, 56, Z16                     /* lifetimes, ::/56 */

static const uint8_t r_short3[] = { 0x01, 0x00, 0x00 };
static const uint8_t r_short0[] = { 0x01 };
static const uint8_t r_opt_hdr_truncated[] = { HDR, 0x00, 0x01, 0x00 };
static const uint8_t r_opt_overrun[] = { HDR, OPT(1, 16), 0, 1, 0, 0 };
static const uint8_t r_dup_clientid[] = {
    HDR, OPT(1, 3), 0, 1, 0, OPT(1, 3), 0, 1, 0 };
static const uint8_t r_dup_serverid[] = {
    HDR, OPT(2, 3), 0, 1, 0, OPT(2, 3), 0, 1, 0 };
static const uint8_t r_dup_rapid_commit[] = { HDR, OPT(14, 0), OPT(14, 0) };
static const uint8_t r_dup_reconf_accept[] = { HDR, OPT(20, 0), OPT(20, 0) };
static const uint8_t r_dup_preference[] = { HDR, OPT(7, 1), 5, OPT(7, 1), 5 };
static const uint8_t r_dup_elapsed_time[] = {
    HDR, OPT(8, 2), 0, 0, OPT(8, 2), 0, 0 };
static const uint8_t r_dup_oro[] = { HDR, OPT(6, 2), 0, 23, OPT(6, 2), 0, 23 };
static const uint8_t r_dup_status[] = {
    HDR, OPT(13, 2), 0, 0, OPT(13, 2), 0, 0 };
static const uint8_t r_dup_dns[] = { HDR, OPT(23, 0), OPT(23, 0) };
static const uint8_t r_dup_sol_max_rt[] = {
    HDR, OPT(82, 4), 0, 0, 0, 60, OPT(82, 4), 0, 0, 0, 60 };
static const uint8_t r_dup_inf_max_rt[] = {
    HDR, OPT(83, 4), 0, 0, 0, 60, OPT(83, 4), 0, 0, 0, 60 };
static const uint8_t r_clientid_len2[] = { HDR, OPT(1, 2), 0, 1 };
static const uint8_t r_serverid_len2[] = { HDR, OPT(2, 2), 0, 1 };
static const uint8_t r_ia_pd_len11[] = { HDR, OPT(25, 11), Z8, 0, 0, 0 };
static const uint8_t r_ia_na_len11[] = { HDR, OPT(3, 11), Z8, 0, 0, 0 };
static const uint8_t r_ia_ta_len3[] = { HDR, OPT(4, 3), 0, 0, 0 };
static const uint8_t r_iaprefix_len24[] = {
    HDR, OPT(25, 12 + 4 + 24), IA_PD_HDR, OPT(26, 24), Z8, Z16 };
static const uint8_t r_iaprefix_prefixlen129[] = {
    HDR, OPT(25, 12 + 4 + 25), IA_PD_HDR, OPT(26, 25), Z8, 129, Z16 };
static const uint8_t r_iaprefix_overruns_ia_pd[] = {
    HDR, OPT(25, 12 + 4 + 25), IA_PD_HDR, OPT(26, 26), IAPREFIX56,
    OPT(14, 0) };
static const uint8_t r_iaaddr_len23[] = {
    HDR, OPT(3, 12 + 4 + 23), Z12, OPT(5, 23), Z16, Z4, 0, 0, 0 };
static const uint8_t r_pd_exclude_len1[] = {
    HDR, OPT(25, 12 + 4 + 25 + 5), IA_PD_HDR, OPT(26, 25 + 5), IAPREFIX56,
    OPT(67, 1), 64 };
static const uint8_t r_pd_exclude_len18[] = {
    HDR, OPT(25, 12 + 4 + 25 + 22), IA_PD_HDR, OPT(26, 25 + 22), IAPREFIX56,
    OPT(67, 18), 64, Z16, 0 };
static const uint8_t r_pd_exclude_prefixlen_eq[] = {
    HDR, OPT(25, 12 + 4 + 25 + 6), IA_PD_HDR, OPT(26, 25 + 6), IAPREFIX56,
    OPT(67, 2), 56, 0 };
static const uint8_t r_pd_exclude_prefixlen_lt[] = {
    HDR, OPT(25, 12 + 4 + 25 + 6), IA_PD_HDR, OPT(26, 25 + 6), IAPREFIX56,
    OPT(67, 2), 48, 0 };
static const uint8_t r_pd_exclude_prefixlen129[] = {
    HDR, OPT(25, 12 + 4 + 25 + 6), IA_PD_HDR, OPT(26, 25 + 6), IAPREFIX56,
    OPT(67, 2), 129, 0 };
static const uint8_t r_pd_exclude_inconsistent[] = {
    HDR, OPT(25, 12 + 4 + 25 + 7), IA_PD_HDR, OPT(26, 25 + 7), IAPREFIX56,
    OPT(67, 3), 64, 0, 0 };
static const uint8_t r_pd_exclude_dup[] = {
    HDR, OPT(25, 12 + 4 + 25 + 12), IA_PD_HDR, OPT(26, 25 + 12), IAPREFIX56,
    OPT(67, 2), 64, 0, OPT(67, 2), 64, 0 };
static const uint8_t r_pd_exclude_overruns_iaprefix[] = {
    HDR, OPT(25, 12 + 4 + 25 + 6), IA_PD_HDR, OPT(26, 25 + 6), IAPREFIX56,
    OPT(67, 3), 64, 0 };
static const uint8_t r_iaprefix_status_len1[] = {
    HDR, OPT(25, 12 + 4 + 25 + 5), IA_PD_HDR, OPT(26, 25 + 5), IAPREFIX56,
    OPT(13, 1), 0 };
static const uint8_t r_ia_pd_status_len1[] = {
    HDR, OPT(25, 12 + 5), IA_PD_HDR, OPT(13, 1), 0 };
static const uint8_t r_ia_pd_dup_status[] = {
    HDR, OPT(25, 12 + 12), IA_PD_HDR, OPT(13, 2), 0, 0, OPT(13, 2), 0, 0 };
static const uint8_t r_oro_odd[] = { HDR, OPT(6, 3), 0, 23, 0 };
static const uint8_t r_preference_len2[] = { HDR, OPT(7, 2), 0, 0 };
static const uint8_t r_elapsed_len1[] = { HDR, OPT(8, 1), 0 };
static const uint8_t r_rapid_commit_len1[] = { HDR, OPT(14, 1), 0 };
static const uint8_t r_reconf_accept_len1[] = { HDR, OPT(20, 1), 0 };
static const uint8_t r_dns_len15[] = { HDR, OPT(23, 15), Z8, Z4, 0, 0, 0 };
static const uint8_t r_sol_max_rt_len3[] = { HDR, OPT(82, 3), 0, 0, 0 };
static const uint8_t r_inf_max_rt_len5[] = { HDR, OPT(83, 5), 0, 0, 0, 0, 0 };
static const uint8_t r_status_len1[] = { HDR, OPT(13, 1), 0 };
static const uint8_t r_fifth_ia_pd_malformed[] = {
    HDR, OPT(25, 12), IA_PD_HDR, OPT(25, 12), IA_PD_HDR,
    OPT(25, 12), IA_PD_HDR, OPT(25, 12), IA_PD_HDR,
    OPT(25, 11), Z8, 0, 0, 0 };
static const uint8_t r_trailing_garbage[] = {
    HDR, OPT(1, 3), 0, 1, 0, 0xff };

#define REJECT_CASE(n) { n, sizeof(n), #n }

static const struct {
    const uint8_t *data;
    size_t len;
    const char *name;
} reject_cases[] = {
    REJECT_CASE(r_short3),
    REJECT_CASE(r_short0),
    REJECT_CASE(r_opt_hdr_truncated),
    REJECT_CASE(r_opt_overrun),
    REJECT_CASE(r_dup_clientid),
    REJECT_CASE(r_dup_serverid),
    REJECT_CASE(r_dup_rapid_commit),
    REJECT_CASE(r_dup_reconf_accept),
    REJECT_CASE(r_dup_preference),
    REJECT_CASE(r_dup_elapsed_time),
    REJECT_CASE(r_dup_oro),
    REJECT_CASE(r_dup_status),
    REJECT_CASE(r_dup_dns),
    REJECT_CASE(r_dup_sol_max_rt),
    REJECT_CASE(r_dup_inf_max_rt),
    REJECT_CASE(r_clientid_len2),
    REJECT_CASE(r_serverid_len2),
    REJECT_CASE(r_ia_pd_len11),
    REJECT_CASE(r_ia_na_len11),
    REJECT_CASE(r_ia_ta_len3),
    REJECT_CASE(r_iaprefix_len24),
    REJECT_CASE(r_iaprefix_prefixlen129),
    REJECT_CASE(r_iaprefix_overruns_ia_pd),
    REJECT_CASE(r_iaaddr_len23),
    REJECT_CASE(r_pd_exclude_len1),
    REJECT_CASE(r_pd_exclude_len18),
    REJECT_CASE(r_pd_exclude_prefixlen_eq),
    REJECT_CASE(r_pd_exclude_prefixlen_lt),
    REJECT_CASE(r_pd_exclude_prefixlen129),
    REJECT_CASE(r_pd_exclude_inconsistent),
    REJECT_CASE(r_pd_exclude_dup),
    REJECT_CASE(r_pd_exclude_overruns_iaprefix),
    REJECT_CASE(r_iaprefix_status_len1),
    REJECT_CASE(r_ia_pd_status_len1),
    REJECT_CASE(r_ia_pd_dup_status),
    REJECT_CASE(r_oro_odd),
    REJECT_CASE(r_preference_len2),
    REJECT_CASE(r_elapsed_len1),
    REJECT_CASE(r_rapid_commit_len1),
    REJECT_CASE(r_reconf_accept_len1),
    REJECT_CASE(r_dns_len15),
    REJECT_CASE(r_sol_max_rt_len3),
    REJECT_CASE(r_inf_max_rt_len5),
    REJECT_CASE(r_status_len1),
    REJECT_CASE(r_fifth_ia_pd_malformed),
    REJECT_CASE(r_trailing_garbage),
};

static const uint8_t a_header_only[] = { HDR };
static const uint8_t a_clientid_len3[] = { HDR, OPT(1, 3), 0, 1, 0 };
static const uint8_t a_ia_pd_len12[] = { HDR, OPT(25, 12), IA_PD_HDR };
static const uint8_t a_ia_na_status[] = {
    HDR, OPT(3, 12 + 4 + 2 + 2), Z12, OPT(13, 4), 0, 2, 'n', 'o' };
static const uint8_t a_ia_ta_len4[] = { HDR, OPT(4, 4), Z4 };
static const uint8_t a_pd_exclude_ok[] = {
    HDR, OPT(25, 12 + 4 + 25 + 6), IA_PD_HDR, OPT(26, 25 + 6), IAPREFIX56,
    OPT(67, 2), 64, 0 };
static const uint8_t a_unknown_options[] = {
    HDR, 0xff, 0xff, 0x00, 0x00, OPT(15, 5), 1, 2, 3, 4, 5,
    OPT(1, 3), 0, 1, 0 };
static const uint8_t a_iaprefix_status_and_unknown[] = {
    HDR, OPT(25, 12 + 4 + 25 + 4 + 4 + 2 + 3), IA_PD_HDR,
    OPT(26, 25 + 4 + 4 + 2 + 3), IAPREFIX56,
    OPT(13, 2), 0, 0, OPT(99, 3), 1, 2, 3 };
static const uint8_t a_empty_dns_and_oro[] = { HDR, OPT(23, 0), OPT(6, 0) };

static void test_reject_malformed(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg;
    uint8_t buf[1024];
    size_t i, pos;
    int rv;

    for (i = 0; i < OGS_ARRAY_SIZE(reject_cases); i++) {
        rv = parse_exact(&msg, reject_cases[i].data, reject_cases[i].len);
        ABTS_ASSERT(tc, reject_cases[i].name, rv == OGS_ERROR);
    }

    /* NULL data / zero length */
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_parse(&msg, NULL, 0));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_dhcpv6_parse(&msg, buf, 0));

    /* DUID of 131 bytes is rejected, 130 is accepted */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    buf[pos++] = 0x00; buf[pos++] = 131;
    memset(buf + pos, 0x5a, 131); pos += 131;
    ABTS_INT_EQUAL(tc, OGS_ERROR, parse_exact(&msg, buf, pos));
    buf[7] = 130;
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos - 1));
    ABTS_INT_EQUAL(tc, 130, msg.client_id.len);

    /* Accepted inputs */
    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_header_only, sizeof(a_header_only)));
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_SOLICIT, msg.msg_type);
    ABTS_INT_EQUAL(tc, 1, msg.transaction_id);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_clientid_len3, sizeof(a_clientid_len3)));
    ABTS_INT_EQUAL(tc, 3, msg.client_id.len);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_ia_pd_len12, sizeof(a_ia_pd_len12)));
    ABTS_INT_EQUAL(tc, 1, msg.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 0, msg.ia_pd[0].num_of_prefix);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_ia_na_status, sizeof(a_ia_na_status)));
    ABTS_INT_EQUAL(tc, 1, msg.num_of_ia_na);
    ABTS_TRUE(tc, msg.ia_na[0].status.presence == true);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL,
            msg.ia_na[0].status.code);
    ABTS_STR_EQUAL(tc, "no", msg.ia_na[0].status.message);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_ia_ta_len4, sizeof(a_ia_ta_len4)));
    ABTS_TRUE(tc, msg.ia_ta_presence == true);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_pd_exclude_ok, sizeof(a_pd_exclude_ok)));
    ABTS_TRUE(tc, msg.ia_pd[0].prefix[0].pd_exclude.presence == true);
    ABTS_INT_EQUAL(tc, 64, msg.ia_pd[0].prefix[0].pd_exclude.prefixlen);

    ABTS_INT_EQUAL(tc, OGS_OK,
            parse_exact(&msg, a_unknown_options, sizeof(a_unknown_options)));
    ABTS_INT_EQUAL(tc, 3, msg.client_id.len);

    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg,
            a_iaprefix_status_and_unknown,
            sizeof(a_iaprefix_status_and_unknown)));
    ABTS_INT_EQUAL(tc, 1, msg.ia_pd[0].num_of_prefix);
    ABTS_INT_EQUAL(tc, 56, msg.ia_pd[0].prefix[0].prefixlen);

    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg,
            a_empty_dns_and_oro, sizeof(a_empty_dns_and_oro)));
    ABTS_INT_EQUAL(tc, 0, msg.num_of_dns);
    ABTS_INT_EQUAL(tc, 0, msg.num_of_oro);
}

static void test_limits(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg;
    uint8_t buf[2048];
    size_t pos, i;
    static const uint8_t ia_pd12[] = { OPT(25, 12), IA_PD_HDR };
    static const uint8_t iaprefix[] = { OPT(26, 25), IAPREFIX56 };

    /* Status message longer than the maximum is truncated, NUL-terminated */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    buf[pos++] = 0x00; buf[pos++] = 13;
    buf[pos++] = 0x00; buf[pos++] = 102;
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    memset(buf + pos, 'x', 100); pos += 100;
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_TRUE(tc, msg.status.presence == true);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_STATUS_UNSPEC_FAIL, msg.status.code);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN,
            strlen(msg.status.message));
    ABTS_INT_EQUAL(tc, 0,
            msg.status.message[OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN]);

    /* 6 IA_PD: only the first 4 are kept */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_IA_PD + 2; i++) {
        memcpy(buf + pos, ia_pd12, sizeof(ia_pd12));
        buf[pos + 4 + 3] = (uint8_t)i;       /* IAID = i */
        pos += sizeof(ia_pd12);
    }
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_NUM_OF_IA_PD, msg.num_of_ia_pd);
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_IA_PD; i++)
        ABTS_INT_EQUAL(tc, (int)i, msg.ia_pd[i].iaid);

    /* 6 IA_NA: only the first 4 are kept */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_IA_NA + 2; i++) {
        memcpy(buf + pos, ia_pd12, sizeof(ia_pd12));
        buf[pos + 1] = OGS_DHCPV6_OPTION_IA_NA;
        pos += sizeof(ia_pd12);
    }
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_NUM_OF_IA_NA, msg.num_of_ia_na);

    /* 6 IAPREFIX in one IA_PD: only the first 4 are kept */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    buf[pos++] = 0x00; buf[pos++] = 25;
    buf[pos++] = 0x00; buf[pos++] = 12 + 6 * sizeof(iaprefix);
    memset(buf + pos, 0, 12); pos += 12;
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_IAPREFIX + 2; i++) {
        memcpy(buf + pos, iaprefix, sizeof(iaprefix));
        buf[pos + 4 + 8] = (uint8_t)(56 + i);    /* prefix-length */
        pos += sizeof(iaprefix);
    }
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_INT_EQUAL(tc, 1, msg.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_NUM_OF_IAPREFIX,
            msg.ia_pd[0].num_of_prefix);
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_IAPREFIX; i++)
        ABTS_INT_EQUAL(tc, 56 + (int)i, msg.ia_pd[0].prefix[i].prefixlen);

    /* 40 ORO entries: only the first 32 are kept */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    buf[pos++] = 0x00; buf[pos++] = 6;
    buf[pos++] = 0x00; buf[pos++] = 2 * (OGS_DHCPV6_MAX_NUM_OF_ORO + 8);
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_ORO + 8; i++) {
        buf[pos++] = 0x00;
        buf[pos++] = (uint8_t)(i + 1);
    }
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_NUM_OF_ORO, msg.num_of_oro);
    ABTS_TRUE(tc, ogs_dhcpv6_oro_contains(&msg, 1));
    ABTS_TRUE(tc, ogs_dhcpv6_oro_contains(&msg, OGS_DHCPV6_MAX_NUM_OF_ORO));
    ABTS_TRUE(tc, !ogs_dhcpv6_oro_contains(&msg,
                OGS_DHCPV6_MAX_NUM_OF_ORO + 1));

    /* 6 DNS servers: only the first 4 are kept */
    pos = 0;
    memcpy(buf + pos, a_header_only, 4); pos += 4;
    buf[pos++] = 0x00; buf[pos++] = 23;
    buf[pos++] = 0x00; buf[pos++] = 16 * (OGS_DHCPV6_MAX_NUM_OF_DNS + 2);
    for (i = 0; i < OGS_DHCPV6_MAX_NUM_OF_DNS + 2; i++) {
        memset(buf + pos, (int)i + 1, 16);
        pos += 16;
    }
    ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, pos));
    ABTS_INT_EQUAL(tc, OGS_DHCPV6_MAX_NUM_OF_DNS, msg.num_of_dns);
    ABTS_INT_EQUAL(tc, 4, msg.dns[3][0]);
}

/*****************************************************************************
 * Truncation at every offset
 *****************************************************************************/

static void test_truncation(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg, out;
    uint8_t buf[512];
    bool boundary[512];
    int len, l;
    size_t off;

    fill_reply(&msg);
    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, REPLY_WIRE_LEN, len);
    ABTS_TRUE(tc, len >= 120);

    /* A prefix is valid only if it ends exactly on a top-level boundary */
    memset(boundary, 0, sizeof(boundary));
    off = OGS_DHCPV6_HEADER_LEN;
    boundary[off] = true;
    while (off < (size_t)len) {
        uint16_t olen = (uint16_t)((buf[off+2] << 8) | buf[off+3]);
        off += OGS_DHCPV6_OPTION_HEADER_LEN + olen;
        ABTS_TRUE(tc, off <= (size_t)len);
        boundary[off] = true;
    }

    for (l = 0; l < len; l++) {
        int rv = parse_exact(&out, buf, l);
        if (boundary[l])
            ABTS_INT_EQUAL(tc, OGS_OK, rv);
        else
            ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    }

    /* The same for the Solicit */
    fill_solicit(&msg);
    len = build_exact(&msg, buf, sizeof(buf));
    memset(boundary, 0, sizeof(boundary));
    off = OGS_DHCPV6_HEADER_LEN;
    boundary[off] = true;
    while (off < (size_t)len) {
        uint16_t olen = (uint16_t)((buf[off+2] << 8) | buf[off+3]);
        off += OGS_DHCPV6_OPTION_HEADER_LEN + olen;
        boundary[off] = true;
    }
    for (l = 0; l < len; l++) {
        int rv = parse_exact(&out, buf, l);
        ABTS_INT_EQUAL(tc, boundary[l] ? OGS_OK : OGS_ERROR, rv);
    }
}

/*****************************************************************************
 * Deterministic pseudo-random garbage
 *****************************************************************************/

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void test_garbage(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg, out;
    uint8_t buf[512], valid[512], rebuilt[2048], rebuilt2[2048];
    uint32_t state = 0x12345678;
    int i, j, len, valid_len, parsed = 0;

    /* Pure random bytes of random length */
    for (i = 0; i < 2000; i++) {
        len = xorshift32(&state) % 300;
        for (j = 0; j < len; j++)
            buf[j] = (uint8_t)xorshift32(&state);
        if (parse_exact(&msg, buf, len) == OGS_OK) {
            parsed++;
            ABTS_TRUE(tc,
                    ogs_dhcpv6_build(&msg, rebuilt, sizeof(rebuilt)) >= 0);
        }
    }

    /* A valid Reply with a few bytes mutated: often valid, never a crash */
    fill_reply(&msg);
    valid_len = build_exact(&msg, valid, sizeof(valid));
    for (i = 0; i < 2000; i++) {
        int flips = 1 + xorshift32(&state) % 4;
        memcpy(buf, valid, valid_len);
        for (j = 0; j < flips; j++)
            buf[xorshift32(&state) % valid_len] = (uint8_t)xorshift32(&state);
        len = valid_len;
        if (parse_exact(&out, buf, len) == OGS_OK) {
            int n = ogs_dhcpv6_build(&out, rebuilt, sizeof(rebuilt));
            int n2;
            ABTS_TRUE(tc, n > 0);
            /* build(parse(build(x))) must equal build(x) */
            ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, rebuilt, n));
            n2 = ogs_dhcpv6_build(&msg, rebuilt2, sizeof(rebuilt2));
            ABTS_INT_EQUAL(tc, n, n2);
            ABTS_TRUE(tc, memcmp(rebuilt, rebuilt2, n) == 0);
        }
    }

    /* Header-only random messages always parse */
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 4; j++)
            buf[j] = (uint8_t)xorshift32(&state);
        ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&msg, buf, 4));
        ABTS_INT_EQUAL(tc, buf[0], msg.msg_type);
        ABTS_INT_EQUAL(tc, (buf[1] << 16) | (buf[2] << 8) | buf[3],
                msg.transaction_id);
    }
}

/*****************************************************************************
 * Build into undersized buffers
 *****************************************************************************/

static void test_build_undersized(abts_case *tc, void *data)
{
    ogs_dhcpv6_message_t msg;
    uint8_t buf[512];
    int len, s;

    fill_reply(&msg);
    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, REPLY_WIRE_LEN, len);

    for (s = 0; s < len; s++)
        ABTS_INT_EQUAL(tc, -1, build_exact(&msg, NULL, s));
    ABTS_INT_EQUAL(tc, len, build_exact(&msg, NULL, len));
    ABTS_INT_EQUAL(tc, len, build_exact(&msg, NULL, len + 1));

    fill_solicit(&msg);
    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, SOLICIT_WIRE_LEN, len);
    for (s = 0; s < len; s++)
        ABTS_INT_EQUAL(tc, -1, build_exact(&msg, NULL, s));
    ABTS_INT_EQUAL(tc, len, build_exact(&msg, NULL, len));

    /* Inconsistent messages are refused rather than truncated */
    fill_reply(&msg);
    msg.num_of_ia_pd = OGS_DHCPV6_MAX_NUM_OF_IA_PD + 1;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.ia_pd[0].num_of_prefix = OGS_DHCPV6_MAX_NUM_OF_IAPREFIX + 1;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.num_of_oro = OGS_DHCPV6_MAX_NUM_OF_ORO + 1;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.num_of_dns = OGS_DHCPV6_MAX_NUM_OF_DNS + 1;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.client_id.len = OGS_DHCPV6_MAX_DUID_LEN + 1;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.client_id.len = 2;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.ia_pd[0].prefix[0].prefixlen = 129;
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    msg.ia_pd[0].prefix[0].pd_exclude.prefixlen = 56;   /* not > /56 */
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    fill_reply(&msg);
    ip6(msg.ia_pd[0].prefix[0].pd_exclude.prefix, "2001:db8:cafe:1300::");
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));

    /* Everything optional off: header only */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = OGS_DHCPV6_INFORMATION_REQUEST;
    msg.transaction_id = 0xffffff;
    ABTS_INT_EQUAL(tc, 4, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    ABTS_INT_EQUAL(tc, -1, ogs_dhcpv6_build(&msg, buf, 3));
    /* Transaction-id is 24 bit: upper byte is dropped */
    msg.transaction_id = 0x12abcdef;
    ABTS_INT_EQUAL(tc, 4, ogs_dhcpv6_build(&msg, buf, sizeof(buf)));
    ABTS_INT_EQUAL(tc, 0xab, buf[1]);
    ABTS_INT_EQUAL(tc, 0xcd, buf[2]);
    ABTS_INT_EQUAL(tc, 0xef, buf[3]);

    /* Every remaining option type, with exact lengths */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = OGS_DHCPV6_REPLY;
    msg.num_of_ia_na = 1;
    msg.ia_na[0].iaid = 9;
    msg.ia_na[0].status.presence = true;
    msg.ia_na[0].status.code = OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL;
    msg.reconf_accept = true;
    msg.preference.presence = true;
    msg.preference.value = 255;
    msg.sol_max_rt = 3600;
    msg.inf_max_rt = 7200;
    /* 4 + IA_NA(4+12+STATUS(4+2)) + RECONF(4) + PREF(5) + SOL(8) + INF(8) */
    len = build_exact(&msg, buf, sizeof(buf));
    ABTS_INT_EQUAL(tc, 4 + 22 + 4 + 5 + 8 + 8, len);
    for (s = 0; s < len; s++)
        ABTS_INT_EQUAL(tc, -1, build_exact(&msg, NULL, s));
    {
        ogs_dhcpv6_message_t out;
        ABTS_INT_EQUAL(tc, OGS_OK, parse_exact(&out, buf, len));
        ABTS_INT_EQUAL(tc, 1, out.num_of_ia_na);
        ABTS_INT_EQUAL(tc, 9, out.ia_na[0].iaid);
        ABTS_TRUE(tc, out.ia_na[0].status.presence == true);
        ABTS_INT_EQUAL(tc, OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL,
                out.ia_na[0].status.code);
        ABTS_TRUE(tc, out.reconf_accept == true);
        ABTS_TRUE(tc, out.preference.presence == true);
        ABTS_INT_EQUAL(tc, 255, out.preference.value);
        ABTS_INT_EQUAL(tc, 3600, out.sol_max_rt);
        ABTS_INT_EQUAL(tc, 7200, out.inf_max_rt);
        ABTS_TRUE(tc, memcmp(&msg, &out, sizeof(msg)) == 0);
    }
}

/*****************************************************************************
 * Names
 *****************************************************************************/

static void test_names(abts_case *tc, void *data)
{
    int i;

    ABTS_STR_EQUAL(tc, "Solicit", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_SOLICIT));
    ABTS_STR_EQUAL(tc, "Advertise",
            ogs_dhcpv6_msg_type_name(OGS_DHCPV6_ADVERTISE));
    ABTS_STR_EQUAL(tc, "Request", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_REQUEST));
    ABTS_STR_EQUAL(tc, "Renew", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_RENEW));
    ABTS_STR_EQUAL(tc, "Rebind", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_REBIND));
    ABTS_STR_EQUAL(tc, "Reply", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_REPLY));
    ABTS_STR_EQUAL(tc, "Release", ogs_dhcpv6_msg_type_name(OGS_DHCPV6_RELEASE));
    ABTS_STR_EQUAL(tc, "Information-request",
            ogs_dhcpv6_msg_type_name(OGS_DHCPV6_INFORMATION_REQUEST));
    ABTS_STR_EQUAL(tc, "Unknown", ogs_dhcpv6_msg_type_name(0));
    ABTS_STR_EQUAL(tc, "Unknown", ogs_dhcpv6_msg_type_name(200));
    ABTS_STR_EQUAL(tc, "Unknown", ogs_dhcpv6_msg_type_name(255));

    ABTS_STR_EQUAL(tc, "Success", ogs_dhcpv6_status_name(0));
    ABTS_STR_EQUAL(tc, "NoAddrsAvail", ogs_dhcpv6_status_name(2));
    ABTS_STR_EQUAL(tc, "NoBinding", ogs_dhcpv6_status_name(3));
    ABTS_STR_EQUAL(tc, "UseMulticast", ogs_dhcpv6_status_name(5));
    ABTS_STR_EQUAL(tc, "NoPrefixAvail", ogs_dhcpv6_status_name(6));
    ABTS_STR_EQUAL(tc, "Unknown", ogs_dhcpv6_status_name(7));
    ABTS_STR_EQUAL(tc, "Unknown", ogs_dhcpv6_status_name(0xffff));

    for (i = 0; i < 256; i++)
        ABTS_PTR_NOTNULL(tc, ogs_dhcpv6_msg_type_name((uint8_t)i));
    for (i = 0; i < 65536; i++)
        ABTS_PTR_NOTNULL(tc, ogs_dhcpv6_status_name((uint16_t)i));
}

/*****************************************************************************
 * IPv6 pseudo-header checksum
 *****************************************************************************/

static uint16_t reference_in6_cksum(const uint8_t *src, const uint8_t *dst,
        uint8_t nxt, const uint8_t *payload, size_t len)
{
    /* Materialise pseudo-header + payload and use ogs_in_cksum() on it */
    uint8_t tmp[40 + 1024];
    size_t pos = 0;

    ogs_assert(len <= 1024);
    memcpy(tmp + pos, src, 16); pos += 16;
    memcpy(tmp + pos, dst, 16); pos += 16;
    tmp[pos++] = (uint8_t)(len >> 24);
    tmp[pos++] = (uint8_t)(len >> 16);
    tmp[pos++] = (uint8_t)(len >> 8);
    tmp[pos++] = (uint8_t)len;
    tmp[pos++] = 0; tmp[pos++] = 0; tmp[pos++] = 0;
    tmp[pos++] = nxt;
    memcpy(tmp + pos, payload, len); pos += len;
    if (pos & 1)
        tmp[pos++] = 0;

    return ogs_in_cksum((uint16_t *)tmp, (int)pos);
}

static void test_in6_cksum(abts_case *tc, void *data)
{
    uint8_t src[OGS_IPV6_LEN], dst[OGS_IPV6_LEN];
    uint8_t pkt[512], *udph, *payload;
    ogs_dhcpv6_message_t msg;
    uint16_t sum;
    int len, udp_len;

    /* ICMPv6 echo request, even length payload (reference: Python) */
    {
        static const uint8_t icmp[] = {
            128, 0, 0, 0, 0, 1, 0, 1, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'
        };
        ip6(src, "fe80::1");
        ip6(dst, "fe80::2");
        sum = ogs_in6_cksum(src, dst, IPPROTO_ICMPV6, icmp, sizeof(icmp));
        ABTS_INT_EQUAL(tc, 0xf118, be16toh(sum));
        ABTS_INT_EQUAL(tc, reference_in6_cksum(
                    src, dst, IPPROTO_ICMPV6, icmp, sizeof(icmp)), sum);
    }

    /* ICMPv6 echo request, odd length payload */
    {
        static const uint8_t icmp[] = {
            128, 0, 0, 0, 0, 1, 0, 1,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'
        };
        sum = ogs_in6_cksum(src, dst, IPPROTO_ICMPV6, icmp, sizeof(icmp));
        ABTS_INT_EQUAL(tc, 0x8817, be16toh(sum));
        ABTS_INT_EQUAL(tc, reference_in6_cksum(
                    src, dst, IPPROTO_ICMPV6, icmp, sizeof(icmp)), sum);

        /* Storing it in the packet makes the checksum verify to zero */
        memcpy(pkt, icmp, sizeof(icmp));
        memcpy(pkt + 2, &sum, 2);
        ABTS_INT_EQUAL(tc, 0, ogs_in6_cksum(
                    src, dst, IPPROTO_ICMPV6, pkt, sizeof(icmp)));
    }

    /* UDP 546 -> 547 with a 3-byte payload (odd total length) */
    {
        static const uint8_t udp[] = {
            0x02, 0x22, 0x02, 0x23, 0x00, 0x0b, 0x00, 0x00, 1, 2, 3
        };
        ip6(src, "fe80::200:ff:fe00:1");
        ip6(dst, "ff02::1:2");
        sum = ogs_in6_cksum(src, dst, IPPROTO_UDP, udp, sizeof(udp));
        ABTS_INT_EQUAL(tc, 0xf909, be16toh(sum));
        ABTS_INT_EQUAL(tc, reference_in6_cksum(
                    src, dst, IPPROTO_UDP, udp, sizeof(udp)), sum);
    }

    /* Empty payload */
    ip6(src, "2001:db8::1");
    ip6(dst, "2001:db8::2");
    sum = ogs_in6_cksum(src, dst, IPPROTO_NONE, pkt, 0);
    ABTS_INT_EQUAL(tc, 0xa44f, be16toh(sum));
    ABTS_INT_EQUAL(tc, reference_in6_cksum(
                src, dst, IPPROTO_NONE, pkt, 0), sum);
    sum = ogs_in6_cksum(src, dst, IPPROTO_NONE, NULL, 0);
    ABTS_INT_EQUAL(tc, 0xa44f, be16toh(sum));

    /*
     * A real DHCPv6 Solicit in UDP: compute, compare with ogs_in_cksum()
     * over a materialised pseudo-header, then verify in place.
     */
    fill_solicit(&msg);
    memset(pkt, 0, sizeof(pkt));
    udph = pkt;
    payload = pkt + 8;
    len = ogs_dhcpv6_build(&msg, payload, sizeof(pkt) - 8);
    ABTS_INT_EQUAL(tc, SOLICIT_WIRE_LEN, len);
    udp_len = 8 + len;
    udph[0] = 0x02; udph[1] = 0x22;             /* sport 546 */
    udph[2] = 0x02; udph[3] = 0x23;             /* dport 547 */
    udph[4] = (uint8_t)(udp_len >> 8); udph[5] = (uint8_t)udp_len;
    ip6(src, "fe80::1");
    ip6(dst, "ff02::1:2");

    sum = ogs_in6_cksum(src, dst, IPPROTO_UDP, pkt, udp_len);
    ABTS_INT_NEQUAL(tc, 0, sum);
    ABTS_INT_EQUAL(tc, reference_in6_cksum(
                src, dst, IPPROTO_UDP, pkt, udp_len), sum);

    memcpy(udph + 6, &sum, 2);
    ABTS_INT_EQUAL(tc, 0, ogs_in6_cksum(src, dst, IPPROTO_UDP, pkt, udp_len));

    /* Unaligned payload pointer must work as well */
    memmove(pkt + 1, pkt, udp_len);
    udph = pkt + 1;
    udph[6] = 0; udph[7] = 0;
    ABTS_INT_EQUAL(tc, sum,
            ogs_in6_cksum(src, dst, IPPROTO_UDP, udph, udp_len));

    /* Corrupting one byte changes the checksum */
    udph[9] ^= 0x01;
    ABTS_INT_NEQUAL(tc, sum,
            ogs_in6_cksum(src, dst, IPPROTO_UDP, udph, udp_len));
}

abts_suite *test_dhcpv6(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_solicit_round_trip, NULL);
    abts_run_test(suite, test_reply_round_trip, NULL);
    abts_run_test(suite, test_reply_no_prefix_avail, NULL);
    abts_run_test(suite, test_rfc6603_example, NULL);
    abts_run_test(suite, test_parse_captured_solicit, NULL);
    abts_run_test(suite, test_reject_malformed, NULL);
    abts_run_test(suite, test_limits, NULL);
    abts_run_test(suite, test_truncation, NULL);
    abts_run_test(suite, test_garbage, NULL);
    abts_run_test(suite, test_build_undersized, NULL);
    abts_run_test(suite, test_names, NULL);
    abts_run_test(suite, test_in6_cksum, NULL);

    return suite;
}
