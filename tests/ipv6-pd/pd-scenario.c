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

#include "pd-scenario.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

/* smf.router_advertisement.link_layer_address */
const uint8_t pd_router_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x01 };

static const uint8_t unspecified_addr[OGS_IPV6_LEN];

/*
 * Address helpers
 */

static const char *addr6_str(const uint8_t *addr6, char *buf)
{
    const char *s = inet_ntop(AF_INET6, addr6, buf, INET6_ADDRSTRLEN);
    return s ? s : "?";
}

void pd_addr_from_string(const char *str, uint8_t *addr6)
{
    ogs_assert(str);
    ogs_assert(addr6);
    ogs_assert(inet_pton(AF_INET6, str, addr6) == 1);
}

static void mask_prefix(uint8_t *out, const uint8_t *in, int prefixlen)
{
    int i;

    for (i = 0; i < OGS_IPV6_LEN; i++) {
        int bits = prefixlen - 8*i;
        if (bits >= 8)
            out[i] = in[i];
        else if (bits > 0)
            out[i] = in[i] & (uint8_t)(0xff << (8 - bits));
        else
            out[i] = 0;
    }
}

/*
 * An address inside prefix/prefixlen but outside the link /64: all the
 * subnet bits after prefixlen are set (e.g. block/56 -> <block>ff::1).
 */
static void addr_inside(uint8_t *out, const uint8_t *prefix, int prefixlen)
{
    int bit;

    mask_prefix(out, prefix, prefixlen);
    for (bit = prefixlen; bit < 64; bit++)
        out[bit / 8] |= 0x80 >> (bit % 8);
    out[OGS_IPV6_LEN-1] = 1;
}

/* The UE's SLAAC address: RA prefix + interface identifier */
static void ue_global_addr(const pd_ctx_t *ctx, uint8_t *out)
{
    memcpy(out, ctx->link, 8);
    memcpy(out + 8, ctx->sess->ue_ip.addr6 + 8, 8);
}

/*
 * RFC 3633 fallback when the client does not support PD_EXCLUDE: the half
 * of the block (/(L+1)) that does NOT contain the link /64.
 */
static void expected_fallback(const pd_ctx_t *ctx, uint8_t *out)
{
    int bit = PD_BLOCK_PREFIXLEN;
    uint8_t m = 0x80 >> (bit % 8);

    memcpy(out, ctx->block, OGS_IPV6_LEN);
    if (!(ctx->link[bit / 8] & m))
        out[bit / 8] |= m;
}

static void addr_equal(abts_case *tc, const char *what,
        const uint8_t *expected, const uint8_t *actual, int lineno)
{
    char e[INET6_ADDRSTRLEN], a[INET6_ADDRSTRLEN];

    addr6_str(expected, e);
    addr6_str(actual, a);
    if (memcmp(expected, actual, OGS_IPV6_LEN) != 0)
        ogs_error("%s: expected %s, got %s", what, e, a);
    abts_str_equal(tc, e, a, lineno);
}
#define PD_ADDR_EQUAL(tc, what, expected, actual) \
    addr_equal(tc, what, expected, actual, __LINE__)

static const char *mac_str(const uint8_t *mac, char *buf)
{
    ogs_snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static void mac_equal(abts_case *tc, const char *what,
        const uint8_t *expected, const uint8_t *actual, int lineno)
{
    char e[18], a[18];

    mac_str(expected, e);
    mac_str(actual, a);
    if (memcmp(expected, actual, 6) != 0)
        ogs_error("%s: expected %s, got %s", what, e, a);
    abts_str_equal(tc, e, a, lineno);
}
#define PD_MAC_EQUAL(tc, what, expected, actual) \
    mac_equal(tc, what, expected, actual, __LINE__)

/*
 * Context
 */

void pd_ctx_init(pd_ctx_t *ctx, abts_case *tc, ogs_socknode_t *gtpu,
        test_ue_t *test_ue, test_sess_t *sess, test_bearer_t *bearer)
{
    ogs_assert(ctx);
    ogs_assert(tc);
    ogs_assert(gtpu);
    ogs_assert(test_ue);
    ogs_assert(sess);

    memset(ctx, 0, sizeof *ctx);
    ctx->tc = tc;
    ctx->gtpu = gtpu;
    ctx->test_ue = test_ue;
    ctx->sess = sess;
    ctx->bearer = bearer;
    ctx->iaid = PD_IAID;

    test_dhcpv6_duid_ll(&ctx->client_id, sess->ue_ip.addr6 + 8);
}

void pd_ctx_set_client_id(pd_ctx_t *ctx, const test_dhcpv6_duid_t *duid)
{
    ogs_assert(ctx);
    ogs_assert(duid);
    ogs_assert(duid->len);

    ctx->client_id = *duid;
}

/*
 * Router discovery
 */

static bool pd_recv_ra(pd_ctx_t *ctx, test_gtpu_ra_t *ra,
        bool merge_prefix, const char *what)
{
    abts_case *tc = ctx->tc;
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    char msg[128];

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_REPLY_TIMEOUT);
    if (!recvbuf) {
        ogs_snprintf(msg, sizeof msg, "No Router Advertisement (%s)", what);
        ABTS_FAIL(tc, msg);
        return false;
    }

    rv = test_gtpu_parse_ra(recvbuf, ra);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    if (merge_prefix)
        /* Merges the /64 into sess->ue_ip.addr6 and frees the pkbuf */
        testgtpu_recv(ctx->test_ue, recvbuf);
    else
        ogs_pkbuf_free(recvbuf);

    return rv == OGS_OK;
}

bool pd_router_discovery(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    int rv;
    uint8_t dns6[OGS_IPV6_LEN], link_local[OGS_IPV6_LEN];

    ABTS_TRUE(tc, ctx->sess->ue_ip.ipv6);
    ABTS_PTR_NOTNULL(tc, ctx->bearer);
    if (!ctx->bearer)
        return false;

    rv = test_gtpu_send_slacc_rs(ctx->gtpu, ctx->bearer);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    if (!pd_recv_ra(ctx, &ctx->ra, true, "RS from link-local"))
        return false;

    /* Addressed to this UE's link-local address from a link-local router */
    test_gtpu_link_local(ctx->sess, link_local);
    PD_ADDR_EQUAL(tc, "RA destination", link_local, ctx->ra.dst);
    ABTS_INT_EQUAL(tc, 0xfe, ctx->ra.src[0]);
    ABTS_INT_EQUAL(tc, 0x80, ctx->ra.src[1] & 0xc0);
    ABTS_INT_EQUAL(tc, 255, ctx->ra.hlim);

    /* RFC 4861 flags: M clear, O set (TS 29.061 section 11.2.1.3.4) */
    ABTS_INT_EQUAL(tc, 0, ctx->ra.flags & ND_RA_FLAG_MANAGED);
    ABTS_INT_EQUAL(tc, ND_RA_FLAG_OTHER, ctx->ra.flags & ND_RA_FLAG_OTHER);

    /* Prefix Information: /64, A set, L clear */
    ABTS_TRUE(tc, ctx->ra.has_prefix);
    ABTS_INT_EQUAL(tc, 64, ctx->ra.prefixlen);
    ABTS_INT_EQUAL(tc, ND_OPT_PI_FLAG_AUTO,
            ctx->ra.pi_flags & ND_OPT_PI_FLAG_AUTO);
    ABTS_INT_EQUAL(tc, 0, ctx->ra.pi_flags & ND_OPT_PI_FLAG_ONLINK);

    /* RDNSS (RFC 8106) carries the configured IPv6 DNS server */
    ABTS_TRUE(tc, ctx->ra.has_rdnss);
    if (ctx->ra.has_rdnss) {
        pd_addr_from_string(PD_DNS6, dns6);
        ABTS_TRUE(tc, ctx->ra.num_of_rdnss >= 1);
        PD_ADDR_EQUAL(tc, "RDNSS", dns6, ctx->ra.rdnss[0]);
    }

    /* The advertised prefix must be a clean /64 inside the pool */
    mask_prefix(ctx->link, ctx->ra.prefix, 64);
    PD_ADDR_EQUAL(tc, "RA prefix (/64 aligned)", ctx->link, ctx->ra.prefix);
    mask_prefix(ctx->block, ctx->link, PD_BLOCK_PREFIXLEN);

    return ctx->ra.has_prefix && ctx->ra.prefixlen == 64;
}

/*
 * DESIGN 5.6: the knobs cannot be toggled at runtime, so the defaults are
 * pinned down exactly: other_config auto (=1 with a block), on_link false,
 * A set, rdnss true, source_link_layer_address true with the configured
 * MAC, router_lifetime 64800.
 */
void pd_check_ra_defaults(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    const test_gtpu_ra_t *ra = &ctx->ra;

    ABTS_INT_EQUAL(tc, 255, ra->hlim);
    ABTS_INT_EQUAL(tc, 0, ra->flags & ND_RA_FLAG_MANAGED);
    ABTS_INT_EQUAL(tc, ND_RA_FLAG_OTHER, ra->flags & ND_RA_FLAG_OTHER);
    ABTS_INT_EQUAL(tc, PD_ROUTER_LIFETIME, ra->router_lifetime);

    ABTS_TRUE(tc, ra->has_prefix);
    ABTS_INT_EQUAL(tc, ND_OPT_PI_FLAG_AUTO, ra->pi_flags & ND_OPT_PI_FLAG_AUTO);
    ABTS_INT_EQUAL(tc, 0, ra->pi_flags & ND_OPT_PI_FLAG_ONLINK);

    ABTS_TRUE(tc, ra->has_rdnss);

    ABTS_TRUE(tc, ra->has_slla);
    if (ra->has_slla)
        PD_MAC_EQUAL(tc, "RA Source Link-Layer Address",
                pd_router_mac, ra->slla);
}

/*
 * DHCPv6 message helpers
 */

static void msg_init(pd_ctx_t *ctx, test_dhcpv6_msg_t *msg,
        uint8_t type, bool with_server_id)
{
    memset(msg, 0, sizeof *msg);
    msg->msg_type = type;
    ctx->xid = (uint32_t)rand() & 0xffffff;
    msg->transaction_id = ctx->xid;
    msg->client_id = ctx->client_id;
    if (with_server_id)
        msg->server_id = ctx->server_id;
    msg->elapsed_time.presence = true;
    msg->elapsed_time.value = 0;
}

static void msg_add_oro(test_dhcpv6_msg_t *msg, bool pd_exclude)
{
    msg->num_of_oro = 0;
    msg->oro[msg->num_of_oro++] = TEST_DHCPV6_OPTION_DNS_SERVERS;
    if (pd_exclude)
        msg->oro[msg->num_of_oro++] = TEST_DHCPV6_OPTION_PD_EXCLUDE;
}

/* IA_PD with a ::/56 length hint (RFC 8168) */
static void msg_add_ia_pd_hint(pd_ctx_t *ctx, test_dhcpv6_msg_t *msg)
{
    test_dhcpv6_ia_pd_t *ia_pd = &msg->ia_pd[0];

    memset(ia_pd, 0, sizeof *ia_pd);
    ia_pd->iaid = ctx->iaid;
    ia_pd->num_of_prefix = 1;
    ia_pd->prefix[0].prefixlen = PD_BLOCK_PREFIXLEN;
    msg->num_of_ia_pd = 1;
}

/* IA_PD echoing the prefix we currently hold (Request/Renew/Rebind/Release) */
static void msg_add_ia_pd_bound(pd_ctx_t *ctx, test_dhcpv6_msg_t *msg)
{
    test_dhcpv6_ia_pd_t *ia_pd = &msg->ia_pd[0];

    memset(ia_pd, 0, sizeof *ia_pd);
    ia_pd->iaid = ctx->iaid;
    if (ctx->ia_pd.num_of_prefix) {
        ia_pd->num_of_prefix = 1;
        ia_pd->prefix[0] = ctx->ia_pd.prefix[0];
        ia_pd->prefix[0].pd_exclude.presence = false;
    }
    msg->num_of_ia_pd = 1;
}

static bool pd_send_raw(pd_ctx_t *ctx, const uint8_t *dst6,
        const void *data, size_t len)
{
    int rv;

    rv = test_gtpu_send_dhcpv6(ctx->gtpu, ctx->bearer, NULL, dst6, data, len);
    ABTS_INT_EQUAL(ctx->tc, OGS_OK, rv);
    return rv == OGS_OK;
}

static bool pd_send(pd_ctx_t *ctx, const test_dhcpv6_msg_t *msg,
        const uint8_t *dst6)
{
    uint8_t buf[TEST_DHCPV6_MAX_MESSAGE_LEN];
    int len;

    len = test_dhcpv6_build(msg, buf, sizeof buf);
    ABTS_TRUE(ctx->tc, len > 0);
    if (len <= 0)
        return false;

    return pd_send_raw(ctx, dst6, buf, len);
}

static bool pd_recv(pd_ctx_t *ctx, test_dhcpv6_msg_t *reply,
        const char *what)
{
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    char msg[128];

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_REPLY_TIMEOUT);
    if (!recvbuf) {
        ogs_snprintf(msg, sizeof msg, "No %s received", what);
        ABTS_FAIL(ctx->tc, msg);
        return false;
    }

    rv = test_gtpu_parse_dhcpv6_reply(recvbuf, ctx->bearer, NULL, reply);
    ogs_pkbuf_free(recvbuf);
    ABTS_INT_EQUAL(ctx->tc, OGS_OK, rv);
    return rv == OGS_OK;
}

/* Nothing at all may arrive on the tunnel for PD_NO_REPLY_TIMEOUT */
static void pd_expect_silence(pd_ctx_t *ctx, const char *what)
{
    ogs_pkbuf_t *recvbuf = NULL;
    test_dhcpv6_msg_t reply;
    char msg[128];

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_NO_REPLY_TIMEOUT);
    if (!recvbuf)
        return;

    if (test_gtpu_parse_dhcpv6_reply(recvbuf, ctx->bearer, NULL, &reply)
            == OGS_OK)
        ogs_error("%s: unexpected %s (xid 0x%06x)", what,
                test_dhcpv6_msg_type_name(reply.msg_type),
                reply.transaction_id);
    else
        ogs_error("%s: unexpected packet [%d bytes]", what, recvbuf->len);
    ogs_pkbuf_free(recvbuf);

    ogs_snprintf(msg, sizeof msg, "%s: expected no reply", what);
    ABTS_FAIL(ctx->tc, msg);
}

static bool pd_ping(pd_ctx_t *ctx, const uint8_t *src6, bool expect_reply)
{
    abts_case *tc = ctx->tc;
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    char buf[INET6_ADDRSTRLEN], msg[128];

    rv = test_gtpu_send_ping_from(ctx->gtpu, ctx->bearer, src6, TEST_PING_IPV6);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    if (!expect_reply) {
        recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_NO_REPLY_TIMEOUT);
        if (recvbuf) {
            ogs_error("Unexpected reply to ping from %s [%d bytes]",
                    addr6_str(src6, buf), recvbuf->len);
            ogs_pkbuf_free(recvbuf);
            ogs_snprintf(msg, sizeof msg,
                    "Ping from %s was answered", addr6_str(src6, buf));
            ABTS_FAIL(tc, msg);
            return false;
        }
        return true;
    }

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_REPLY_TIMEOUT);
    if (!recvbuf) {
        ogs_snprintf(msg, sizeof msg, "No echo reply to %s",
                addr6_str(src6, buf));
        ABTS_FAIL(tc, msg);
        return false;
    }

    rv = test_gtpu_parse_ping_reply(recvbuf, src6);
    ogs_pkbuf_free(recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    return rv == OGS_OK;
}

/* Ping from inside the delegated prefix (outside the link /64) */
static bool pd_ping_from_delegated(pd_ctx_t *ctx)
{
    uint8_t src6[OGS_IPV6_LEN];

    if (!ctx->ia_pd.num_of_prefix) {
        ABTS_FAIL(ctx->tc, "No delegated prefix to ping from");
        return false;
    }
    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    return pd_ping(ctx, src6, true);
}

/*
 * Assertions on a delegating Advertise/Reply
 */

static bool check_header(pd_ctx_t *ctx, const test_dhcpv6_msg_t *reply,
        uint8_t expected_type, const char *what)
{
    abts_case *tc = ctx->tc;

    ogs_debug("%s: %s xid 0x%06x", what,
            test_dhcpv6_msg_type_name(reply->msg_type),
            reply->transaction_id);

    ABTS_INT_EQUAL(tc, expected_type, reply->msg_type);
    ABTS_INT_EQUAL(tc, ctx->xid, reply->transaction_id);

    ABTS_TRUE(tc, reply->server_id.len > 0);
    if (!ctx->server_id.len)
        ctx->server_id = reply->server_id;
    else
        ABTS_TRUE(tc, test_dhcpv6_duid_equal(
                    &ctx->server_id, &reply->server_id));
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->client_id, &reply->client_id));

    return reply->msg_type == expected_type;
}

static bool check_delegation(pd_ctx_t *ctx, const test_dhcpv6_msg_t *reply,
        uint8_t expected_type, bool pd_exclude, const char *what)
{
    abts_case *tc = ctx->tc;
    const test_dhcpv6_ia_pd_t *ia_pd = NULL;
    const test_dhcpv6_iaprefix_t *prefix = NULL;
    uint8_t expected[OGS_IPV6_LEN], dns6[OGS_IPV6_LEN];
    char msg[128];

    check_header(ctx, reply, expected_type, what);

    /* no top-level failure */
    ABTS_TRUE(tc, !reply->status.presence ||
            reply->status.code == TEST_DHCPV6_STATUS_SUCCESS);

    ABTS_INT_EQUAL(tc, 1, reply->num_of_ia_pd);
    if (reply->num_of_ia_pd < 1) {
        ogs_snprintf(msg, sizeof msg, "%s: no IA_PD", what);
        ABTS_FAIL(tc, msg);
        return false;
    }

    ia_pd = &reply->ia_pd[0];
    ABTS_INT_EQUAL(tc, ctx->iaid, ia_pd->iaid);
    ABTS_INT_EQUAL(tc, PD_EXPECTED_T1, ia_pd->t1);
    ABTS_INT_EQUAL(tc, PD_EXPECTED_T2, ia_pd->t2);
    if (ia_pd->status.presence) {
        ogs_error("%s: IA_PD status %s [%s]", what,
                test_dhcpv6_status_name(ia_pd->status.code),
                ia_pd->status.message);
        ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_SUCCESS, ia_pd->status.code);
    }

    ABTS_INT_EQUAL(tc, 1, ia_pd->num_of_prefix);
    if (ia_pd->num_of_prefix < 1) {
        ogs_snprintf(msg, sizeof msg, "%s: no IAPREFIX", what);
        ABTS_FAIL(tc, msg);
        return false;
    }

    prefix = &ia_pd->prefix[0];
    ABTS_INT_EQUAL(tc, PD_EXPECTED_PREFERRED, prefix->preferred_lifetime);
    ABTS_INT_EQUAL(tc, PD_EXPECTED_VALID, prefix->valid_lifetime);

    if (pd_exclude) {
        /* RFC 6603: the whole block, excluding the link /64 */
        ABTS_INT_EQUAL(tc, PD_BLOCK_PREFIXLEN, prefix->prefixlen);
        PD_ADDR_EQUAL(tc, "IAPREFIX", ctx->block, prefix->prefix);
        ABTS_TRUE(tc, prefix->pd_exclude.presence);
        if (prefix->pd_exclude.presence) {
            ABTS_INT_EQUAL(tc, 64, prefix->pd_exclude.prefixlen);
            PD_ADDR_EQUAL(tc, "PD_EXCLUDE", ctx->link,
                    prefix->pd_exclude.prefix);
        }
    } else {
        /* RFC 3633 fallback: the half of the block without the link */
        expected_fallback(ctx, expected);
        ABTS_INT_EQUAL(tc, PD_BLOCK_PREFIXLEN + 1, prefix->prefixlen);
        PD_ADDR_EQUAL(tc, "IAPREFIX (fallback)", expected, prefix->prefix);
        ABTS_TRUE(tc, !prefix->pd_exclude.presence);
    }

    /* DNS_SERVERS was requested in the ORO */
    pd_addr_from_string(PD_DNS6, dns6);
    ABTS_TRUE(tc, reply->num_of_dns >= 1);
    if (reply->num_of_dns >= 1)
        PD_ADDR_EQUAL(tc, "DNS_SERVERS", dns6, reply->dns[0]);

    ctx->ia_pd = *ia_pd;

    return reply->msg_type == expected_type && ia_pd->num_of_prefix == 1;
}

/* Advertise/Reply whose single IA_PD carries a Status Code and no prefix */
static bool check_ia_pd_status(pd_ctx_t *ctx, const test_dhcpv6_msg_t *reply,
        uint8_t expected_type, uint16_t expected_status, const char *what)
{
    abts_case *tc = ctx->tc;
    const test_dhcpv6_ia_pd_t *ia_pd = NULL;
    char msg[128];

    check_header(ctx, reply, expected_type, what);

    ABTS_INT_EQUAL(tc, 1, reply->num_of_ia_pd);
    if (reply->num_of_ia_pd < 1) {
        ogs_snprintf(msg, sizeof msg, "%s: no IA_PD", what);
        ABTS_FAIL(tc, msg);
        return false;
    }

    ia_pd = &reply->ia_pd[0];
    ABTS_INT_EQUAL(tc, ctx->iaid, ia_pd->iaid);
    ABTS_TRUE(tc, ia_pd->status.presence);
    if (!ia_pd->status.presence) {
        ogs_snprintf(msg, sizeof msg, "%s: IA_PD without Status Code", what);
        ABTS_FAIL(tc, msg);
        return false;
    }
    if (ia_pd->status.code != expected_status)
        ogs_error("%s: IA_PD status %s [%s], expected %s", what,
                test_dhcpv6_status_name(ia_pd->status.code),
                ia_pd->status.message,
                test_dhcpv6_status_name(expected_status));
    ABTS_INT_EQUAL(tc, expected_status, ia_pd->status.code);
    ABTS_INT_EQUAL(tc, 0, ia_pd->num_of_prefix);

    return reply->msg_type == expected_type &&
        ia_pd->status.code == expected_status;
}

/* Reply to a Release: top-level Status Success */
static void check_release_reply(pd_ctx_t *ctx, const test_dhcpv6_msg_t *reply)
{
    abts_case *tc = ctx->tc;

    check_header(ctx, reply, TEST_DHCPV6_REPLY, "Reply to Release");
    ABTS_TRUE(tc, reply->status.presence);
    if (reply->status.presence)
        ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_SUCCESS, reply->status.code);
}

/*
 * Exchanges
 */

static bool pd_solicit(pd_ctx_t *ctx, bool pd_exclude, bool rapid_commit,
        test_dhcpv6_msg_t *reply)
{
    test_dhcpv6_msg_t msg;

    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, pd_exclude);
    msg_add_ia_pd_hint(ctx, &msg);
    msg.rapid_commit = rapid_commit;

    if (!pd_send(ctx, &msg, NULL))
        return false;
    return pd_recv(ctx, reply, rapid_commit ? "Reply" : "Advertise");
}

static bool pd_request(pd_ctx_t *ctx, bool pd_exclude,
        test_dhcpv6_msg_t *reply)
{
    test_dhcpv6_msg_t msg;

    msg_init(ctx, &msg, TEST_DHCPV6_REQUEST, true);
    msg_add_oro(&msg, pd_exclude);
    msg_add_ia_pd_bound(ctx, &msg);

    if (!pd_send(ctx, &msg, NULL))
        return false;
    return pd_recv(ctx, reply, "Reply to Request");
}

static bool pd_renew_rebind(pd_ctx_t *ctx, uint8_t type, bool pd_exclude,
        test_dhcpv6_msg_t *reply)
{
    test_dhcpv6_msg_t msg;

    msg_init(ctx, &msg, type, type == TEST_DHCPV6_RENEW);
    msg_add_oro(&msg, pd_exclude);
    msg_add_ia_pd_bound(ctx, &msg);

    if (!pd_send(ctx, &msg, NULL))
        return false;
    return pd_recv(ctx, reply,
            type == TEST_DHCPV6_RENEW ? "Reply to Renew" : "Reply to Rebind");
}

static bool pd_release(pd_ctx_t *ctx, test_dhcpv6_msg_t *reply)
{
    test_dhcpv6_msg_t msg;

    msg_init(ctx, &msg, TEST_DHCPV6_RELEASE, true);
    msg_add_ia_pd_bound(ctx, &msg);

    if (!pd_send(ctx, &msg, NULL))
        return false;
    return pd_recv(ctx, reply, "Reply to Release");
}

bool pd_solicit_request(pd_ctx_t *ctx, bool pd_exclude)
{
    test_dhcpv6_msg_t reply;

    if (!pd_solicit(ctx, pd_exclude, false, &reply))
        return false;
    if (!check_delegation(ctx, &reply,
                TEST_DHCPV6_ADVERTISE, pd_exclude, "Advertise"))
        return false;

    if (!pd_request(ctx, pd_exclude, &reply))
        return false;
    return check_delegation(ctx, &reply,
                TEST_DHCPV6_REPLY, pd_exclude, "Reply to Request");
}

/*
 * Neighbour Discovery helpers (5.1)
 */

static bool pd_send_ns(pd_ctx_t *ctx,
        const uint8_t *src6, const uint8_t *dst6, const uint8_t *target6)
{
    int rv;

    rv = test_gtpu_send_ns(ctx->gtpu, ctx->bearer, src6, dst6, target6);
    ABTS_INT_EQUAL(ctx->tc, OGS_OK, rv);
    return rv == OGS_OK;
}

/* Unicast NA for the gateway: R|S|O, TLLA = virtual MAC, to expected_dst */
static bool pd_expect_na(pd_ctx_t *ctx, const uint8_t *expected_dst,
        const char *what)
{
    abts_case *tc = ctx->tc;
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    test_gtpu_na_t na;
    char msg[128];

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_REPLY_TIMEOUT);
    if (!recvbuf) {
        ogs_snprintf(msg, sizeof msg,
                "No Neighbour Advertisement (%s)", what);
        ABTS_FAIL(tc, msg);
        return false;
    }

    rv = test_gtpu_parse_na(recvbuf, &na);
    ogs_pkbuf_free(recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    if (rv != OGS_OK)
        return false;

    ABTS_INT_EQUAL(tc, 255, na.hlim);
    PD_ADDR_EQUAL(tc, "NA source", ctx->ra.src, na.src);
    PD_ADDR_EQUAL(tc, "NA destination", expected_dst, na.dst);
    PD_ADDR_EQUAL(tc, "NA target", ctx->ra.src, na.target);
    ABTS_INT_EQUAL(tc, TEST_ND_NA_FLAG_ROUTER | TEST_ND_NA_FLAG_SOLICITED |
            TEST_ND_NA_FLAG_OVERRIDE, na.flags);
    ABTS_TRUE(tc, na.has_tlla);
    if (na.has_tlla)
        PD_MAC_EQUAL(tc, "NA Target Link-Layer Address",
                pd_router_mac, na.tlla);

    return true;
}

/*
 * Scenarios
 */

void pd_scenario_basic(pd_ctx_t *ctx)
{
    pd_check_ra_defaults(ctx);

    if (!pd_solicit_request(ctx, true))
        return;

    /* Uplink from inside the delegated block, outside the link /64 */
    pd_ping_from_delegated(ctx);
}

void pd_scenario_lifecycle(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t reply;

    if (!pd_solicit_request(ctx, true))
        return;

    /* Renew -> Reply with refreshed lifetimes */
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    check_delegation(ctx, &reply, TEST_DHCPV6_REPLY, true, "Reply to Renew");

    /* Rebind (no Server-ID) -> Reply */
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_REBIND, true, &reply))
        return;
    check_delegation(ctx, &reply, TEST_DHCPV6_REPLY, true, "Reply to Rebind");

    /* Release -> Reply with Status Success */
    if (!pd_release(ctx, &reply))
        return;
    check_release_reply(ctx, &reply);

    /* Renew after Release -> IA_PD with Status NoBinding */
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_REPLY, reply.msg_type);
    ABTS_INT_EQUAL(tc, ctx->xid, reply.transaction_id);
    ABTS_INT_EQUAL(tc, 1, reply.num_of_ia_pd);
    if (reply.num_of_ia_pd == 1) {
        ABTS_INT_EQUAL(tc, ctx->iaid, reply.ia_pd[0].iaid);
        ABTS_TRUE(tc, reply.ia_pd[0].status.presence);
        if (reply.ia_pd[0].status.presence)
            ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_NO_BINDING,
                    reply.ia_pd[0].status.code);
    }
}

void pd_scenario_no_exclude(pd_ctx_t *ctx)
{
    if (!pd_solicit_request(ctx, false))
        return;

    pd_ping_from_delegated(ctx);
}

void pd_scenario_rapid_commit(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t reply;

    if (!pd_solicit(ctx, true, true, &reply))
        return;
    ABTS_TRUE(tc, reply.rapid_commit);
    if (!check_delegation(ctx, &reply,
                TEST_DHCPV6_REPLY, true, "Reply (rapid commit)"))
        return;

    pd_ping_from_delegated(ctx);
}

void pd_scenario_negative(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t msg, reply;
    uint8_t buf[TEST_DHCPV6_MAX_MESSAGE_LEN];
    uint8_t src6[OGS_IPV6_LEN];
    int len, i;

    /* Solicit sent unicast to the router -> Advertise with UseMulticast
     * (RFC 8415 section 18.4: Advertise for a Solicit, Reply otherwise) */
    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, true);
    msg_add_ia_pd_hint(ctx, &msg);
    if (!pd_send(ctx, &msg, ctx->ra.src))
        return;
    if (!pd_recv(ctx, &reply, "Advertise (UseMulticast)"))
        return;
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_ADVERTISE, reply.msg_type);
    ABTS_INT_EQUAL(tc, ctx->xid, reply.transaction_id);
    ABTS_TRUE(tc, reply.server_id.len > 0);
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->client_id, &reply.client_id));
    ABTS_TRUE(tc, reply.status.presence);
    if (reply.status.presence)
        ABTS_INT_EQUAL(tc,
                TEST_DHCPV6_STATUS_USE_MULTICAST, reply.status.code);
    ABTS_INT_EQUAL(tc, 0, reply.num_of_ia_pd);

    /* Learn the server DUID with a proper Solicit */
    if (!pd_solicit(ctx, true, false, &reply))
        return;
    if (!check_delegation(ctx, &reply,
                TEST_DHCPV6_ADVERTISE, true, "Advertise"))
        return;

    /* Request with a foreign Server-ID -> silently discarded */
    msg_init(ctx, &msg, TEST_DHCPV6_REQUEST, true);
    if (!msg.server_id.len)
        return;
    msg.server_id.data[msg.server_id.len-1] ^= 0xff;
    msg_add_oro(&msg, true);
    msg_add_ia_pd_bound(ctx, &msg);
    if (!pd_send(ctx, &msg, NULL))
        return;
    pd_expect_silence(ctx, "Request with wrong Server-ID");

    /* Solicit carrying a Server-ID -> silently discarded */
    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, true);
    msg_add_oro(&msg, true);
    msg_add_ia_pd_hint(ctx, &msg);
    if (!pd_send(ctx, &msg, NULL))
        return;
    pd_expect_silence(ctx, "Solicit with Server-ID");

    /* Information-request -> Reply with DNS only */
    msg_init(ctx, &msg, TEST_DHCPV6_INFORMATION_REQUEST, false);
    msg_add_oro(&msg, false);
    if (!pd_send(ctx, &msg, NULL))
        return;
    if (!pd_recv(ctx, &reply, "Reply to Information-request"))
        return;
    check_header(ctx, &reply, TEST_DHCPV6_REPLY,
            "Reply to Information-request");
    ABTS_TRUE(tc, reply.num_of_dns >= 1);
    ABTS_INT_EQUAL(tc, 0, reply.num_of_ia_pd);

    /* Garbage and a truncated Solicit -> no reply, NFs stay alive */
    for (i = 0; i < 40; i++)
        buf[i] = rand() & 0xff;
    buf[0] = TEST_DHCPV6_SOLICIT;
    if (!pd_send_raw(ctx, NULL, buf, 40))
        return;

    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, true);
    msg_add_ia_pd_hint(ctx, &msg);
    len = test_dhcpv6_build(&msg, buf, sizeof buf);
    ABTS_TRUE(tc, len > 8);
    if (len <= 8)
        return;
    if (!pd_send_raw(ctx, NULL, buf, len - 5))  /* cut inside the IA_PD */
        return;
    pd_expect_silence(ctx, "Garbage / truncated Solicit");

    /* ... and a normal exchange still works afterwards */
    if (!pd_solicit_request(ctx, true))
        return;

    /* Ping from outside the block is dropped, from inside it is answered */
    memcpy(src6, ctx->block, OGS_IPV6_LEN);
    src6[6] ^= 0x80;    /* another /56, never allocated by the pool */
    addr_inside(src6, src6, PD_BLOCK_PREFIXLEN);
    pd_ping(ctx, src6, false);

    pd_ping_from_delegated(ctx);
}

void pd_scenario_static(pd_ctx_t *ctx, bool pd_exclude)
{
    abts_case *tc = ctx->tc;
    uint8_t expected[OGS_IPV6_LEN];

    pd_addr_from_string(PD_STATIC_LINK, expected);
    PD_ADDR_EQUAL(tc, "static link /64", expected, ctx->link);
    pd_addr_from_string(PD_STATIC_BLOCK, expected);
    PD_ADDR_EQUAL(tc, "static block /56", expected, ctx->block);

    if (!pd_solicit_request(ctx, pd_exclude))
        return;

    pd_ping_from_delegated(ctx);
}

/*
 * 5.1: the gateway answers Neighbour Solicitations for its own link-local
 * address (from link-local or global sources, multicast or unicast) and
 * stays silent for DAD probes and for foreign targets.
 */
void pd_scenario_neighbour_discovery(pd_ctx_t *ctx)
{
    uint8_t link_local[OGS_IPV6_LEN], global[OGS_IPV6_LEN];
    uint8_t other[OGS_IPV6_LEN];

    /* The RA already carries the virtual MAC (Source Link-Layer Address) */
    pd_check_ra_defaults(ctx);

    test_gtpu_link_local(ctx->sess, link_local);
    ue_global_addr(ctx, global);

    /* Multicast NS from the link-local address -> unicast NA */
    if (!pd_send_ns(ctx, link_local, NULL, ctx->ra.src))
        return;
    pd_expect_na(ctx, link_local, "multicast NS from link-local");

    /* Multicast NS from the global (SLAAC) address -> NA to that address */
    if (!pd_send_ns(ctx, global, NULL, ctx->ra.src))
        return;
    pd_expect_na(ctx, global, "multicast NS from the global address");

    /* NUD re-probe: unicast NS to the gateway itself -> NA */
    if (!pd_send_ns(ctx, link_local, ctx->ra.src, ctx->ra.src))
        return;
    pd_expect_na(ctx, link_local, "unicast NUD probe");

    /* DAD for the UE's own address (source ::, target = UE address) */
    if (!pd_send_ns(ctx, unspecified_addr, NULL, global))
        return;
    pd_expect_silence(ctx, "DAD probe for the UE address");

    /* DAD-style probe for the gateway address (source ::, target = gw) */
    if (!pd_send_ns(ctx, unspecified_addr, NULL, ctx->ra.src))
        return;
    pd_expect_silence(ctx, "DAD-style probe for the gateway address");

    /* NS for a different target on the link */
    pd_addr_from_string("fe80::2", other);
    if (!pd_send_ns(ctx, link_local, NULL, other))
        return;
    pd_expect_silence(ctx, "NS for a foreign target");

    /* ... and the gateway still answers afterwards */
    if (!pd_send_ns(ctx, link_local, NULL, ctx->ra.src))
        return;
    pd_expect_na(ctx, link_local, "multicast NS after the negative cases");
}

/*
 * 5.7: an RS from the unspecified address gets an RA to ff02::1 with the
 * same prefix; an RS from link-local keeps getting a unicast RA.
 */
void pd_scenario_rs_unspecified(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    int rv;
    test_gtpu_ra_t ra;
    uint8_t all_nodes[OGS_IPV6_LEN], link_local[OGS_IPV6_LEN];

    pd_addr_from_string("ff02::1", all_nodes);
    test_gtpu_link_local(ctx->sess, link_local);

    rv = test_gtpu_send_rs_from(ctx->gtpu, ctx->bearer, unspecified_addr);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    if (rv != OGS_OK)
        return;

    if (!pd_recv_ra(ctx, &ra, false, "RS from ::"))
        return;
    PD_ADDR_EQUAL(tc, "RA destination (all-nodes)", all_nodes, ra.dst);
    PD_ADDR_EQUAL(tc, "RA source", ctx->ra.src, ra.src);
    ABTS_INT_EQUAL(tc, 255, ra.hlim);
    ABTS_TRUE(tc, ra.has_prefix);
    ABTS_INT_EQUAL(tc, 64, ra.prefixlen);
    PD_ADDR_EQUAL(tc, "RA prefix (unchanged)", ctx->link, ra.prefix);
    ABTS_INT_EQUAL(tc, ND_RA_FLAG_OTHER, ra.flags & ND_RA_FLAG_OTHER);
    ABTS_TRUE(tc, ra.has_slla);

    /* A unicast RS afterwards still gets a unicast RA */
    rv = test_gtpu_send_rs_from(ctx->gtpu, ctx->bearer, NULL);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    if (rv != OGS_OK)
        return;
    if (!pd_recv_ra(ctx, &ra, false, "RS from link-local"))
        return;
    PD_ADDR_EQUAL(tc, "RA destination (unicast)", link_local, ra.dst);
    PD_ADDR_EQUAL(tc, "RA prefix (unchanged)", ctx->link, ra.prefix);
}

/*
 * 5.2 (UPF): link-local sources are only accepted towards the control
 * plane. Leaked LAN traffic (mDNS, pings from fe80::) is dropped in the
 * UPF without disturbing the session.
 */
void pd_scenario_leaky_cpe(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    int rv;
    test_dhcpv6_msg_t reply;
    test_gtpu_ra_t ra;
    uint8_t link_local[OGS_IPV6_LEN], gateway[OGS_IPV6_LEN];
    /* mDNS-like query: _http._tcp.local PTR */
    static const uint8_t mdns_query[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        5, '_', 'h', 't', 't', 'p', 4, '_', 't', 'c', 'p',
        5, 'l', 'o', 'c', 'a', 'l', 0,
        0x00, 0x0c, 0x00, 0x01
    };

    if (!pd_solicit_request(ctx, true))
        return;

    test_gtpu_link_local(ctx->sess, link_local);
    pd_addr_from_string(TEST_PING_IPV6, gateway);

    /* (1) UDP from link-local to a global address: dropped in the UPF */
    rv = test_gtpu_send_udp(ctx->gtpu, ctx->bearer, link_local, gateway,
            5353, 5353, mdns_query, sizeof mdns_query);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pd_expect_silence(ctx, "UDP from link-local to a global address");

    /* the NFs are alive: forwarding from the delegated prefix still works */
    if (!pd_ping_from_delegated(ctx))
        return;

    /* (2) echo request from link-local to a global address: dropped */
    pd_ping(ctx, link_local, false);
    if (!pd_ping_from_delegated(ctx))
        return;

    /* Control-plane traffic from link-local is unaffected: RS and DHCPv6 */
    rv = test_gtpu_send_rs_from(ctx->gtpu, ctx->bearer, NULL);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    if (!pd_recv_ra(ctx, &ra, false, "RS after the dropped packets"))
        return;
    PD_ADDR_EQUAL(tc, "RA destination", link_local, ra.dst);

    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    check_delegation(ctx, &reply, TEST_DHCPV6_REPLY, true,
            "Reply to Renew after the dropped packets");
}

/*
 * 5.2 (SMF): while a binding is live, a second DUID on the same session
 * gets NoPrefixAvail (Solicit/Request) or NoBinding (Renew); the bound
 * client keeps working and its Release frees the block for the other.
 */
void pd_scenario_sticky_binding(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t reply;
    test_dhcpv6_duid_t duid_a, duid_b;
    uint8_t bound_prefix[OGS_IPV6_LEN];
    static const uint8_t mac_b[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    duid_a = ctx->client_id;

    memset(&duid_b, 0, sizeof duid_b);
    duid_b.len = 10;
    duid_b.data[1] = 0x03;      /* DUID-LL */
    duid_b.data[3] = 0x01;      /* Ethernet */
    memcpy(duid_b.data + 4, mac_b, 6);

    /* Client A binds */
    if (!pd_solicit_request(ctx, true))
        return;
    memcpy(bound_prefix, ctx->ia_pd.prefix[0].prefix, OGS_IPV6_LEN);

    /* Client B: Solicit -> Advertise with IA_PD NoPrefixAvail, no prefix */
    pd_ctx_set_client_id(ctx, &duid_b);
    if (!pd_solicit(ctx, true, false, &reply))
        return;
    check_ia_pd_status(ctx, &reply, TEST_DHCPV6_ADVERTISE,
            TEST_DHCPV6_STATUS_NO_PREFIX_AVAIL,
            "Advertise for the second DUID");

    /* Client B: Request (for A's prefix) -> Reply IA_PD NoPrefixAvail */
    if (!pd_request(ctx, true, &reply))
        return;
    check_ia_pd_status(ctx, &reply, TEST_DHCPV6_REPLY,
            TEST_DHCPV6_STATUS_NO_PREFIX_AVAIL,
            "Reply to Request for the second DUID");

    /* Client B: Renew -> Reply IA_PD NoBinding */
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    check_ia_pd_status(ctx, &reply, TEST_DHCPV6_REPLY,
            TEST_DHCPV6_STATUS_NO_BINDING,
            "Reply to Renew for the second DUID");

    /* Client A: Renew still refreshes the same prefix */
    pd_ctx_set_client_id(ctx, &duid_a);
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    if (!check_delegation(ctx, &reply, TEST_DHCPV6_REPLY, true,
                "Reply to Renew for the bound DUID"))
        return;
    PD_ADDR_EQUAL(tc, "prefix of the bound client",
            bound_prefix, ctx->ia_pd.prefix[0].prefix);

    /* Client A: Release -> Success */
    if (!pd_release(ctx, &reply))
        return;
    check_release_reply(ctx, &reply);

    /* Client B: now delegated, same block */
    pd_ctx_set_client_id(ctx, &duid_b);
    if (!pd_solicit_request(ctx, true))
        return;
    PD_ADDR_EQUAL(tc, "prefix delegated to the second DUID",
            bound_prefix, ctx->ia_pd.prefix[0].prefix);
    pd_ping_from_delegated(ctx);
}

/*
 * 5.3 + 5.5: a static address in the static-only subnet lands there, the
 * block is routed by the UPF (nothing else knows 2001:db8:5a7c::/48) and
 * traffic from the delegated prefix is forwarded.
 */
void pd_scenario_static_only(pd_ctx_t *ctx, bool pd_exclude)
{
    abts_case *tc = ctx->tc;
    uint8_t expected[OGS_IPV6_LEN];

    pd_addr_from_string(PD_STATIC_ONLY_LINK, expected);
    PD_ADDR_EQUAL(tc, "static-only link /64", expected, ctx->link);
    pd_addr_from_string(PD_STATIC_ONLY_BLOCK, expected);
    PD_ADDR_EQUAL(tc, "static-only block /56", expected, ctx->block);

    /* The per-session kernel route exists while the session is up */
    pd_check_kernel_route(tc, PD_STATIC_ONLY_ROUTE, true);

    if (!pd_solicit_request(ctx, pd_exclude))
        return;

    /* Only reachable through the route the UPF installed */
    pd_ping_from_delegated(ctx);
}

/* 5.4: block in the expected pool, delegation and forwarding work */
void pd_scenario_in_pool(pd_ctx_t *ctx, const char *pool)
{
    pd_check_block_in_pool(ctx, pool);

    if (!pd_solicit_request(ctx, true))
        return;

    pd_check_block_in_pool(ctx, pool);
    pd_ping_from_delegated(ctx);
}

/*
 * 5.8: byte-exact replays of the TP-Link HX220 capture.
 */

/* Information-request: Client-ID DUID-LL 2e:2f:d0:b8:f1:9d, Elapsed-Time,
 * Vendor-Class (enterprise 11863 "TP-Link Technology Co.,Ltd"),
 * ORO [32, 23, 16] */
static const char hx220_information_request_hex[] =
    "0bb8e5d90001000a000300012e2fd0b8f19d0008000200000010002000002e57001a"
    "54502d4c696e6b20546563686e6f6c6f677920436f2e2c4c746400060006002000170010";
#define HX220_INFORMATION_REQUEST_XID   0xb8e5d9

/* Solicit: IA_PD IAID 0xd0b8f19d, T1 = T2 = 0xffffffff, no IAPREFIX hint,
 * no PD_EXCLUDE, no Rapid Commit, ORO [23, 16] */
static const char hx220_solicit_hex[] =
    "01c0fa970001000a000300012e2fd0b8f19d0019000cd0b8f19dffffffffffffffff"
    "0008000200000010002000002e57001a54502d4c696e6b20546563686e6f6c6f6779"
    "20436f2e2c4c74640006000400170010";
#define HX220_SOLICIT_XID               0xc0fa97
#define HX220_IAID                      0xd0b8f19d

static const uint8_t hx220_duid[10] = {
    0x00, 0x03, 0x00, 0x01, 0x2e, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d
};

void pd_scenario_hx220(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t msg, reply, fixture;
    test_dhcpv6_duid_t duid;
    uint8_t buf[TEST_DHCPV6_MAX_MESSAGE_LEN], dns6[OGS_IPV6_LEN];
    int len;

    memset(&duid, 0, sizeof duid);
    duid.len = sizeof hx220_duid;
    memcpy(duid.data, hx220_duid, sizeof hx220_duid);
    pd_ctx_set_client_id(ctx, &duid);
    pd_addr_from_string(PD_DNS6, dns6);

    /*
     * Information-request -> Reply with DNS and Information Refresh Time,
     * no IA of any kind.
     */
    len = strlen(hx220_information_request_hex) / 2;
    ogs_hex_from_string(hx220_information_request_hex, buf, len);

    /* our own codec must swallow the fixture (Vendor-Class skipped) */
    ABTS_INT_EQUAL(tc, OGS_OK, test_dhcpv6_parse(&fixture, buf, len));
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_INFORMATION_REQUEST, fixture.msg_type);
    ABTS_INT_EQUAL(tc, HX220_INFORMATION_REQUEST_XID, fixture.transaction_id);
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&duid, &fixture.client_id));
    ABTS_TRUE(tc, fixture.elapsed_time.presence);
    ABTS_INT_EQUAL(tc, 3, fixture.num_of_oro);
    ABTS_TRUE(tc, test_dhcpv6_oro_contains(&fixture,
                TEST_DHCPV6_OPTION_INFORMATION_REFRESH_TIME));
    ABTS_TRUE(tc, test_dhcpv6_oro_contains(&fixture,
                TEST_DHCPV6_OPTION_DNS_SERVERS));
    ABTS_TRUE(tc, test_dhcpv6_oro_contains(&fixture,
                TEST_DHCPV6_OPTION_VENDOR_CLASS));

    ctx->xid = HX220_INFORMATION_REQUEST_XID;
    if (!pd_send_raw(ctx, NULL, buf, len))
        return;
    if (!pd_recv(ctx, &reply, "Reply to the HX220 Information-request"))
        return;
    check_header(ctx, &reply, TEST_DHCPV6_REPLY,
            "Reply to the HX220 Information-request");
    ABTS_TRUE(tc, !reply.status.presence ||
            reply.status.code == TEST_DHCPV6_STATUS_SUCCESS);
    ABTS_TRUE(tc, reply.num_of_dns >= 1);
    if (reply.num_of_dns >= 1)
        PD_ADDR_EQUAL(tc, "DNS_SERVERS", dns6, reply.dns[0]);
    ABTS_TRUE(tc, reply.information_refresh_time.presence);
    if (reply.information_refresh_time.presence)
        ABTS_INT_EQUAL(tc, PD_INFORMATION_REFRESH_TIME,
                reply.information_refresh_time.value);
    ABTS_INT_EQUAL(tc, 0, reply.num_of_ia_pd);
    ABTS_INT_EQUAL(tc, 0, reply.num_of_ia_na);
    ABTS_TRUE(tc, !reply.ia_na_presence);

    /*
     * Solicit -> Advertise: IAID from the fixture, RFC 3633 fallback /57
     * (no PD_EXCLUDE in the ORO), T1/T2 from the server policy.
     */
    len = strlen(hx220_solicit_hex) / 2;
    ogs_hex_from_string(hx220_solicit_hex, buf, len);

    ABTS_INT_EQUAL(tc, OGS_OK, test_dhcpv6_parse(&fixture, buf, len));
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_SOLICIT, fixture.msg_type);
    ABTS_INT_EQUAL(tc, 1, fixture.num_of_ia_pd);
    if (fixture.num_of_ia_pd == 1) {
        ABTS_INT_EQUAL(tc, HX220_IAID, fixture.ia_pd[0].iaid);
        ABTS_INT_EQUAL(tc, 0xffffffff, fixture.ia_pd[0].t1);
        ABTS_INT_EQUAL(tc, 0xffffffff, fixture.ia_pd[0].t2);
        ABTS_INT_EQUAL(tc, 0, fixture.ia_pd[0].num_of_prefix);
    }
    ABTS_TRUE(tc, !test_dhcpv6_oro_contains(&fixture,
                TEST_DHCPV6_OPTION_PD_EXCLUDE));
    ABTS_TRUE(tc, !fixture.rapid_commit);

    ctx->iaid = HX220_IAID;
    ctx->xid = HX220_SOLICIT_XID;
    if (!pd_send_raw(ctx, NULL, buf, len))
        return;
    if (!pd_recv(ctx, &reply, "Advertise to the HX220 Solicit"))
        return;
    if (!check_delegation(ctx, &reply, TEST_DHCPV6_ADVERTISE, false,
                "Advertise to the HX220 Solicit"))
        return;

    /* Request built here with the same DUID/IAID -> Reply */
    if (!pd_request(ctx, false, &reply))
        return;
    if (!check_delegation(ctx, &reply, TEST_DHCPV6_REPLY, false,
                "Reply to the HX220 Request"))
        return;
    pd_ping_from_delegated(ctx);

    /*
     * Solicit that also carries an IA_NA -> Advertise with the delegation
     * and a Status Code NoAddrsAvail INSIDE the IA_NA (RFC 7550 clients
     * would otherwise abandon the exchange).
     */
    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, true);
    msg_add_ia_pd_hint(ctx, &msg);
    msg.num_of_ia_na = 1;
    memset(&msg.ia_na[0], 0, sizeof msg.ia_na[0]);
    msg.ia_na[0].iaid = 1;
    if (!pd_send(ctx, &msg, NULL))
        return;
    if (!pd_recv(ctx, &reply, "Advertise to Solicit with IA_NA"))
        return;
    check_delegation(ctx, &reply, TEST_DHCPV6_ADVERTISE, true,
            "Advertise to Solicit with IA_NA");
    ABTS_INT_EQUAL(tc, 1, reply.num_of_ia_na);
    if (reply.num_of_ia_na == 1) {
        ABTS_INT_EQUAL(tc, 1, reply.ia_na[0].iaid);
        ABTS_TRUE(tc, reply.ia_na[0].status.presence);
        if (reply.ia_na[0].status.presence)
            ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_NO_ADDRS_AVAIL,
                    reply.ia_na[0].status.code);
    }
    /* the failure is scoped to the IA_NA, not the whole message */
    ABTS_TRUE(tc, !reply.status.presence ||
            reply.status.code == TEST_DHCPV6_STATUS_SUCCESS);
}

/*
 * Cross-UE checks
 */

void pd_check_distinct_blocks(pd_ctx_t *a, pd_ctx_t *b)
{
    abts_case *tc = a->tc;
    char sa[INET6_ADDRSTRLEN], sb[INET6_ADDRSTRLEN];

    ABTS_TRUE(tc, memcmp(a->link, b->link, OGS_IPV6_LEN) != 0);
    ABTS_TRUE(tc, memcmp(a->block, b->block, OGS_IPV6_LEN) != 0);

    if (a->ia_pd.num_of_prefix && b->ia_pd.num_of_prefix) {
        addr6_str(a->ia_pd.prefix[0].prefix, sa);
        addr6_str(b->ia_pd.prefix[0].prefix, sb);
        /* ABTS_STR_NEQUAL is strncmp-based (asserts equal); the two
         * delegated prefixes must differ, so compare explicitly */
        ABTS_TRUE(tc, strncmp(sa, sb, INET6_ADDRSTRLEN) != 0);
    } else {
        ABTS_FAIL(tc, "Both UEs need a delegated prefix");
    }
}

void pd_check_same_prefixes(pd_ctx_t *ctx,
        const uint8_t *link, const uint8_t *block)
{
    PD_ADDR_EQUAL(ctx->tc, "link /64 after re-attach", link, ctx->link);
    PD_ADDR_EQUAL(ctx->tc, "block after re-attach", block, ctx->block);
    if (ctx->ia_pd.num_of_prefix) {
        uint8_t expected[OGS_IPV6_LEN];
        mask_prefix(expected,
                ctx->ia_pd.prefix[0].prefix, PD_BLOCK_PREFIXLEN);
        PD_ADDR_EQUAL(ctx->tc, "IAPREFIX block after re-attach",
                block, expected);
    }
}

void pd_check_block_in_pool(pd_ctx_t *ctx, const char *pool)
{
    uint8_t expected[OGS_IPV6_LEN], actual[OGS_IPV6_LEN];

    pd_addr_from_string(pool, expected);

    mask_prefix(actual, ctx->block, PD_POOL_PREFIXLEN);
    PD_ADDR_EQUAL(ctx->tc, "pool of the session block", expected, actual);

    if (ctx->ia_pd.num_of_prefix) {
        mask_prefix(actual, ctx->ia_pd.prefix[0].prefix, PD_POOL_PREFIXLEN);
        PD_ADDR_EQUAL(ctx->tc, "pool of the delegated prefix",
                expected, actual);
    }
}

/*
 * The NFs run in the network namespace of the test binary, so the
 * per-session routes the UPF installs (rtm_protocol 250) are visible with
 * iproute2. A line starts with "<prefix>/<len> dev ...".
 */
void pd_check_kernel_route(abts_case *tc, const char *route, bool expected)
{
    FILE *fp = NULL;
    char cmd[128], line[512];
    size_t n;
    bool found = false;
    int status;

    ogs_assert(route);
    n = strlen(route);

    ogs_snprintf(cmd, sizeof cmd,
            "ip -6 route show proto %d 2>&1", PD_KERNEL_ROUTE_PROTO);
    fp = popen(cmd, "r");
    if (!fp) {
        ogs_error("popen(%s) failed", cmd);
        ABTS_FAIL(tc, "Cannot list kernel routes");
        return;
    }

    while (fgets(line, sizeof line, fp)) {
        ogs_debug("proto %d route: %s", PD_KERNEL_ROUTE_PROTO, line);
        if (strncmp(line, route, n) == 0 &&
            (line[n] == ' ' || line[n] == '\n' || line[n] == '\0'))
            found = true;
    }

    status = pclose(fp);
    if (status != 0)
        ogs_warn("`%s` exited with status %d", cmd, status);

    if (found != expected)
        ogs_error("Kernel route %s is %s, expected %s", route,
                found ? "present" : "absent",
                expected ? "present" : "absent");
    ABTS_INT_EQUAL(tc, expected, found);
}
