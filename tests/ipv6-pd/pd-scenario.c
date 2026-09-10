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

#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

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
    ogs_assert(bearer);

    memset(ctx, 0, sizeof *ctx);
    ctx->tc = tc;
    ctx->gtpu = gtpu;
    ctx->test_ue = test_ue;
    ctx->sess = sess;
    ctx->bearer = bearer;

    test_dhcpv6_duid_ll(&ctx->client_id, sess->ue_ip.addr6 + 8);
}

/*
 * Router discovery
 */

bool pd_router_discovery(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    uint8_t dns6[OGS_IPV6_LEN], link_local[OGS_IPV6_LEN];

    ABTS_TRUE(tc, ctx->sess->ue_ip.ipv6);

    rv = test_gtpu_send_slacc_rs(ctx->gtpu, ctx->bearer);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = test_gtpu_read_timeout(ctx->gtpu, PD_REPLY_TIMEOUT);
    if (!recvbuf) {
        ABTS_FAIL(tc, "No Router Advertisement received");
        return false;
    }

    rv = test_gtpu_parse_ra(recvbuf, &ctx->ra);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    /* Merges the /64 into sess->ue_ip.addr6 and frees the pkbuf */
    testgtpu_recv(ctx->test_ue, recvbuf);
    if (rv != OGS_OK)
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
static void msg_add_ia_pd_hint(test_dhcpv6_msg_t *msg)
{
    test_dhcpv6_ia_pd_t *ia_pd = &msg->ia_pd[0];

    memset(ia_pd, 0, sizeof *ia_pd);
    ia_pd->iaid = PD_IAID;
    ia_pd->num_of_prefix = 1;
    ia_pd->prefix[0].prefixlen = PD_BLOCK_PREFIXLEN;
    msg->num_of_ia_pd = 1;
}

/* IA_PD echoing the prefix we currently hold (Request/Renew/Rebind/Release) */
static void msg_add_ia_pd_bound(pd_ctx_t *ctx, test_dhcpv6_msg_t *msg)
{
    test_dhcpv6_ia_pd_t *ia_pd = &msg->ia_pd[0];

    memset(ia_pd, 0, sizeof *ia_pd);
    ia_pd->iaid = PD_IAID;
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
            ABTS_FAIL(tc, "Ping from outside the block was answered");
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

/*
 * Assertions on a delegating Advertise/Reply
 */

static bool check_delegation(pd_ctx_t *ctx, const test_dhcpv6_msg_t *reply,
        uint8_t expected_type, bool pd_exclude, const char *what)
{
    abts_case *tc = ctx->tc;
    const test_dhcpv6_ia_pd_t *ia_pd = NULL;
    const test_dhcpv6_iaprefix_t *prefix = NULL;
    uint8_t expected[OGS_IPV6_LEN], dns6[OGS_IPV6_LEN];
    char msg[128];

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
    ABTS_INT_EQUAL(tc, PD_IAID, ia_pd->iaid);
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

/*
 * Exchanges
 */

static bool pd_solicit(pd_ctx_t *ctx, bool pd_exclude, bool rapid_commit,
        test_dhcpv6_msg_t *reply)
{
    test_dhcpv6_msg_t msg;

    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, pd_exclude);
    msg_add_ia_pd_hint(&msg);
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
 * Scenarios
 */

void pd_scenario_basic(pd_ctx_t *ctx)
{
    uint8_t src6[OGS_IPV6_LEN];

    if (!pd_solicit_request(ctx, true))
        return;

    /* Uplink from inside the delegated block, outside the link /64 */
    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    pd_ping(ctx, src6, true);
}

void pd_scenario_lifecycle(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t reply;
    uint32_t xid;

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
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_REPLY, reply.msg_type);
    ABTS_INT_EQUAL(tc, ctx->xid, reply.transaction_id);
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->server_id, &reply.server_id));
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->client_id, &reply.client_id));
    ABTS_TRUE(tc, reply.status.presence);
    if (reply.status.presence)
        ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_SUCCESS, reply.status.code);

    /* Renew after Release -> IA_PD with Status NoBinding */
    if (!pd_renew_rebind(ctx, TEST_DHCPV6_RENEW, true, &reply))
        return;
    xid = ctx->xid;
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_REPLY, reply.msg_type);
    ABTS_INT_EQUAL(tc, xid, reply.transaction_id);
    ABTS_INT_EQUAL(tc, 1, reply.num_of_ia_pd);
    if (reply.num_of_ia_pd == 1) {
        ABTS_INT_EQUAL(tc, PD_IAID, reply.ia_pd[0].iaid);
        ABTS_TRUE(tc, reply.ia_pd[0].status.presence);
        if (reply.ia_pd[0].status.presence)
            ABTS_INT_EQUAL(tc, TEST_DHCPV6_STATUS_NO_BINDING,
                    reply.ia_pd[0].status.code);
    }
}

void pd_scenario_no_exclude(pd_ctx_t *ctx)
{
    uint8_t src6[OGS_IPV6_LEN];

    if (!pd_solicit_request(ctx, false))
        return;

    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    pd_ping(ctx, src6, true);
}

void pd_scenario_rapid_commit(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t reply;
    uint8_t src6[OGS_IPV6_LEN];

    if (!pd_solicit(ctx, true, true, &reply))
        return;
    ABTS_TRUE(tc, reply.rapid_commit);
    if (!check_delegation(ctx, &reply,
                TEST_DHCPV6_REPLY, true, "Reply (rapid commit)"))
        return;

    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    pd_ping(ctx, src6, true);
}

void pd_scenario_negative(pd_ctx_t *ctx)
{
    abts_case *tc = ctx->tc;
    test_dhcpv6_msg_t msg, reply;
    uint8_t buf[TEST_DHCPV6_MAX_MESSAGE_LEN];
    uint8_t src6[OGS_IPV6_LEN];
    int len, i;

    /* Solicit sent unicast to the router -> Reply with UseMulticast */
    msg_init(ctx, &msg, TEST_DHCPV6_SOLICIT, false);
    msg_add_oro(&msg, true);
    msg_add_ia_pd_hint(&msg);
    if (!pd_send(ctx, &msg, ctx->ra.src))
        return;
    if (!pd_recv(ctx, &reply, "Reply (UseMulticast)"))
        return;
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_REPLY, reply.msg_type);
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
    msg_add_ia_pd_hint(&msg);
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
    ABTS_INT_EQUAL(tc, TEST_DHCPV6_REPLY, reply.msg_type);
    ABTS_INT_EQUAL(tc, ctx->xid, reply.transaction_id);
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->server_id, &reply.server_id));
    ABTS_TRUE(tc, test_dhcpv6_duid_equal(&ctx->client_id, &reply.client_id));
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
    msg_add_ia_pd_hint(&msg);
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

    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    pd_ping(ctx, src6, true);
}

void pd_scenario_static(pd_ctx_t *ctx, bool pd_exclude)
{
    abts_case *tc = ctx->tc;
    uint8_t expected[OGS_IPV6_LEN];
    uint8_t src6[OGS_IPV6_LEN];

    pd_addr_from_string(PD_STATIC_LINK, expected);
    PD_ADDR_EQUAL(tc, "static link /64", expected, ctx->link);
    pd_addr_from_string(PD_STATIC_BLOCK, expected);
    PD_ADDR_EQUAL(tc, "static block /56", expected, ctx->block);

    if (!pd_solicit_request(ctx, pd_exclude))
        return;

    addr_inside(src6,
            ctx->ia_pd.prefix[0].prefix, ctx->ia_pd.prefix[0].prefixlen);
    pd_ping(ctx, src6, true);
}

void pd_check_distinct_blocks(pd_ctx_t *a, pd_ctx_t *b)
{
    abts_case *tc = a->tc;
    char sa[INET6_ADDRSTRLEN], sb[INET6_ADDRSTRLEN];

    ABTS_TRUE(tc, memcmp(a->link, b->link, OGS_IPV6_LEN) != 0);
    ABTS_TRUE(tc, memcmp(a->block, b->block, OGS_IPV6_LEN) != 0);

    if (a->ia_pd.num_of_prefix && b->ia_pd.num_of_prefix) {
        addr6_str(a->ia_pd.prefix[0].prefix, sa);
        addr6_str(b->ia_pd.prefix[0].prefix, sb);
        ABTS_STR_NEQUAL(tc, sa, sb, INET6_ADDRSTRLEN);
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
