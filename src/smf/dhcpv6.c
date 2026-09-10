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

#include "context.h"

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
#include <netinet/udp.h>

#include "dhcpv6.h"
#include "gtp-path.h"
#include "metrics.h"

/* Number of client DUID octets shown in log lines */
#define SMF_DHCPV6_LOG_DUID_LEN             16

/*
 * Prefix arithmetic. All functions are pure and work on the 16-octet
 * network byte order representation used on the wire.
 */
static void ipv6_prefix_mask(
        uint8_t *out, const uint8_t *addr, uint8_t prefixlen)
{
    int full = prefixlen >> 3, rem = prefixlen & 7;

    ogs_assert(out);
    ogs_assert(addr);
    ogs_assert(prefixlen <= 128);

    memset(out, 0, OGS_IPV6_LEN);
    memcpy(out, addr, full);
    if (rem)
        out[full] = addr[full] & (uint8_t)(0xff << (8 - rem));
}

static bool ipv6_prefix_equal(
        const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen)
{
    uint8_t ma[OGS_IPV6_LEN], mb[OGS_IPV6_LEN];

    if (alen != blen || alen > 128)
        return false;

    ipv6_prefix_mask(ma, a, alen);
    ipv6_prefix_mask(mb, b, blen);

    return memcmp(ma, mb, OGS_IPV6_LEN) == 0;
}

/*
 * Delegated prefix for a link /64 (`link`) that lives inside a block of
 * length `blocklen` (1..63):
 *   pd_exclude : block/blocklen with OPTION_PD_EXCLUDE = link/64
 *   otherwise  : the /(blocklen+1) half of the block that does not contain
 *                the link /64, i.e. the half with bit `blocklen` flipped.
 * Works for any position of the link /64 inside the block (static UE
 * addresses), see docs/ipv6-prefix-delegation/DESIGN.md section 2.1.
 */
static void delegated_prefix(ogs_dhcpv6_iaprefix_t *out,
        const uint8_t *link, uint8_t blocklen, bool pd_exclude)
{
    ogs_assert(out);
    ogs_assert(link);
    ogs_assert(blocklen >= 1 && blocklen < OGS_IPV6_DEFAULT_PREFIX_LEN);

    memset(out, 0, sizeof(*out));

    if (pd_exclude) {
        out->prefixlen = blocklen;
        ipv6_prefix_mask(out->prefix, link, blocklen);
        out->pd_exclude.presence = true;
        out->pd_exclude.prefixlen = OGS_IPV6_DEFAULT_PREFIX_LEN;
        ipv6_prefix_mask(
                out->pd_exclude.prefix, link, OGS_IPV6_DEFAULT_PREFIX_LEN);
    } else {
        out->prefixlen = blocklen + 1;
        ipv6_prefix_mask(out->prefix, link, blocklen + 1);
        out->prefix[blocklen >> 3] ^= (uint8_t)(0x80 >> (blocklen & 7));
    }
}

bool smf_dhcpv6_delegated_prefix(
        smf_sess_t *sess, bool pd_exclude, ogs_dhcpv6_iaprefix_t *prefix)
{
    uint8_t blocklen;

    ogs_assert(sess);
    ogs_assert(prefix);

    blocklen = smf_sess_ipv6_prefixlen(sess);
    if (!blocklen || blocklen >= OGS_IPV6_DEFAULT_PREFIX_LEN)
        return false;

    delegated_prefix(prefix,
            (const uint8_t *)sess->ipv6->addr, blocklen, pd_exclude);
    prefix->preferred_lifetime = smf_self()->dhcpv6.preferred_lifetime;
    prefix->valid_lifetime = smf_self()->dhcpv6.valid_lifetime;

    return true;
}

int smf_dhcpv6_dns_servers(uint8_t (*addr6)[OGS_IPV6_LEN], int max)
{
    int i, n = 0;

    ogs_assert(addr6);

    for (i = 0; i < MAX_NUM_OF_DNS && n < max; i++) {
        const char *dns6 = smf_self()->dns6[i];
        if (!dns6)
            continue;
        /* Validated by smf_context_parse_config(), so this cannot fail */
        if (inet_pton(AF_INET6, dns6, addr6[n]) == 1)
            n++;
    }

    return n;
}

/*
 * Packet validation
 */
bool smf_dhcpv6_is_request(ogs_pkbuf_t *pkbuf)
{
    struct ip6_hdr *ip6_h = NULL;
    struct udphdr *udp_h = NULL;
    size_t plen, ulen;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);

    if (pkbuf->len < sizeof(struct ip6_hdr) + sizeof(struct udphdr))
        return false;

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    if ((ip6_h->ip6_vfc >> 4) != 6 || ip6_h->ip6_nxt != IPPROTO_UDP)
        return false;

    plen = be16toh(ip6_h->ip6_plen);
    if (plen < sizeof(struct udphdr) ||
        plen > pkbuf->len - sizeof(struct ip6_hdr))
        return false;

    udp_h = (struct udphdr *)(pkbuf->data + sizeof(struct ip6_hdr));
    if (be16toh(udp_h->uh_dport) != OGS_DHCPV6_SERVER_PORT)
        return false;

    /* From here on the packet claims to be DHCPv6: say why it is dropped */
    ulen = be16toh(udp_h->uh_ulen);
    if (ulen != plen) {
        ogs_warn("[DROP] DHCPv6: UDP length[%zu] differs from "
                "IPv6 payload length[%zu]", ulen, plen);
        return false;
    }
    if (ulen < sizeof(struct udphdr) + OGS_DHCPV6_HEADER_LEN) {
        ogs_warn("[DROP] DHCPv6: UDP length[%zu] too short", ulen);
        return false;
    }

    /* RFC 8415 section 7.1: clients send from a link-local address */
    if (!IN6_IS_ADDR_LINKLOCAL(&ip6_h->ip6_src)) {
        ogs_warn("[DROP] DHCPv6 from non link-local source [%s]",
                OGS_INET6_NTOP(&ip6_h->ip6_src, buf));
        return false;
    }

    /* RFC 8200 section 8.1: the UDP checksum is mandatory over IPv6 */
    if (udp_h->uh_sum == 0) {
        ogs_warn("[DROP] DHCPv6: missing UDP checksum");
        return false;
    }
    if (ogs_in6_cksum(ip6_h->ip6_src.s6_addr, ip6_h->ip6_dst.s6_addr,
                IPPROTO_UDP, udp_h, ulen) != 0) {
        ogs_warn("[DROP] DHCPv6: bad UDP checksum");
        return false;
    }

    return true;
}

/*
 * Reply construction helpers
 */
static const char *sess_id_str(smf_sess_t *sess)
{
    smf_ue_t *smf_ue = NULL;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    return smf_ue->supi ? smf_ue->supi : smf_ue->imsi_bcd;
}

/* Client DUID as hex, truncated to SMF_DHCPV6_LOG_DUID_LEN octets */
static const char *duid_str(const ogs_dhcpv6_duid_t *duid, char *buf)
{
    int len;

    ogs_assert(duid);
    ogs_assert(buf);

    len = ogs_min(duid->len, SMF_DHCPV6_LOG_DUID_LEN);
    ogs_hex_to_ascii(duid->data, len, buf, SMF_DHCPV6_LOG_DUID_LEN * 2 + 3);
    if (duid->len > len)
        strcpy(buf + len * 2, "..");

    return buf;
}

static bool duid_equal(const ogs_dhcpv6_duid_t *a, const ogs_dhcpv6_duid_t *b)
{
    ogs_assert(a);
    ogs_assert(b);

    return a->len && a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

static bool server_id_is_ours(const ogs_dhcpv6_message_t *req)
{
    return duid_equal(&req->server_id, &smf_self()->dhcpv6.duid);
}

static void status_set(ogs_dhcpv6_status_t *status,
        uint16_t code, const char *message)
{
    ogs_assert(status);

    status->presence = true;
    status->code = code;
    ogs_cpystrn(status->message, message ? message : "",
            sizeof(status->message));
}

/* Every reply carries the transaction-id, our Server-ID and the
 * Client-ID as received (absent in an Information-request is fine) */
static void reply_init(ogs_dhcpv6_message_t *rsp,
        const ogs_dhcpv6_message_t *req, uint8_t msg_type)
{
    ogs_assert(rsp);
    ogs_assert(req);

    memset(rsp, 0, sizeof(*rsp));
    rsp->msg_type = msg_type;
    rsp->transaction_id = req->transaction_id;
    rsp->server_id = smf_self()->dhcpv6.duid;
    rsp->client_id = req->client_id;
}

static void reply_add_dns(ogs_dhcpv6_message_t *rsp)
{
    ogs_assert(rsp);

    rsp->num_of_dns = smf_dhcpv6_dns_servers(
            rsp->dns, OGS_DHCPV6_MAX_NUM_OF_DNS);
}

/* RFC 8415 section 21.24/21.25: only when the client asks, SOL_MAX_RT in
 * Advertise/Reply and INF_MAX_RT in the Reply to an Information-request */
static void reply_add_max_rt(
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    ogs_assert(rsp);
    ogs_assert(req);

    if (req->msg_type == OGS_DHCPV6_INFORMATION_REQUEST) {
        if (ogs_dhcpv6_oro_contains(req, OGS_DHCPV6_OPTION_INF_MAX_RT))
            rsp->inf_max_rt = SMF_DHCPV6_INF_MAX_RT;
    } else {
        if (ogs_dhcpv6_oro_contains(req, OGS_DHCPV6_OPTION_SOL_MAX_RT))
            rsp->sol_max_rt = SMF_DHCPV6_SOL_MAX_RT;
    }
}

/* Every IA_NA is answered with the same status: we never assign addresses */
static void reply_fill_ia_na(ogs_dhcpv6_message_t *rsp,
        const ogs_dhcpv6_message_t *req, uint16_t code, const char *message)
{
    int i;

    ogs_assert(rsp);
    ogs_assert(req);

    for (i = 0; i < req->num_of_ia_na; i++) {
        ogs_dhcpv6_ia_na_t *ia = &rsp->ia_na[rsp->num_of_ia_na++];
        ia->iaid = req->ia_na[i].iaid;
        status_set(&ia->status, code, message);
    }
}

/* Every IA_PD is echoed with the same status and no prefix */
static void reply_fill_ia_pd_status(ogs_dhcpv6_message_t *rsp,
        const ogs_dhcpv6_message_t *req, uint16_t code, const char *message)
{
    int i;

    ogs_assert(rsp);
    ogs_assert(req);

    for (i = 0; i < req->num_of_ia_pd; i++) {
        ogs_dhcpv6_ia_pd_t *ia = &rsp->ia_pd[rsp->num_of_ia_pd++];
        ia->iaid = req->ia_pd[i].iaid;
        status_set(&ia->status, code, message);
    }
}

/*
 * The first IA_PD of the request gets the session prefix (or NoPrefixAvail
 * when `prefix` is NULL), any further IA_PD gets NoPrefixAvail. With
 * `zero_foreign` (Request/Renew/Rebind, RFC 8415 section 18.3.2/4/5) the
 * prefixes of the request that are not ours are echoed with zero lifetimes
 * so the client stops using them.
 */
static void reply_fill_ia_pd(ogs_dhcpv6_message_t *rsp,
        const ogs_dhcpv6_message_t *req,
        const ogs_dhcpv6_iaprefix_t *prefix, bool zero_foreign)
{
    int i, j;

    ogs_assert(rsp);
    ogs_assert(req);

    for (i = 0; i < req->num_of_ia_pd; i++) {
        const ogs_dhcpv6_ia_pd_t *req_ia = &req->ia_pd[i];
        ogs_dhcpv6_ia_pd_t *ia = &rsp->ia_pd[rsp->num_of_ia_pd++];

        ia->iaid = req_ia->iaid;

        if (i > 0) {
            status_set(&ia->status, OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL,
                    "one IA_PD per session");
            continue;
        }
        if (!prefix) {
            status_set(&ia->status, OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL,
                    "no prefix delegation on this session");
            continue;
        }

        ia->t1 = smf_self()->dhcpv6.t1;
        ia->t2 = smf_self()->dhcpv6.t2;
        ia->prefix[ia->num_of_prefix++] = *prefix;

        if (!zero_foreign)
            continue;

        for (j = 0; j < req_ia->num_of_prefix &&
                ia->num_of_prefix < OGS_DHCPV6_MAX_NUM_OF_IAPREFIX; j++) {
            const ogs_dhcpv6_iaprefix_t *hint = &req_ia->prefix[j];
            ogs_dhcpv6_iaprefix_t *foreign = NULL;

            if (ipv6_prefix_equal(hint->prefix, hint->prefixlen,
                        prefix->prefix, prefix->prefixlen))
                continue;

            foreign = &ia->prefix[ia->num_of_prefix++];
            memset(foreign, 0, sizeof(*foreign));
            foreign->prefixlen = hint->prefixlen;
            memcpy(foreign->prefix, hint->prefix, OGS_IPV6_LEN);
        }
    }
}

/*
 * Binding policy
 */
static void binding_commit(smf_sess_t *sess,
        const ogs_dhcpv6_message_t *req, const ogs_dhcpv6_iaprefix_t *prefix,
        bool pd_exclude, bool refresh)
{
    smf_dhcpv6_binding_t *binding = NULL;
    char duid[SMF_DHCPV6_LOG_DUID_LEN * 2 + 3];
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(sess);
    ogs_assert(req);
    ogs_assert(prefix);
    ogs_assert(req->num_of_ia_pd > 0);

    binding = &sess->dhcpv6;

    if (binding->active && !duid_equal(&binding->client_id, &req->client_id))
        ogs_info("[%s] DHCPv6-PD binding taken over by another client "
                "DUID[%s] (%s)", sess_id_str(sess),
                duid_str(&req->client_id, duid),
                ogs_dhcpv6_msg_type_name(req->msg_type));

    binding->active = true;
    binding->client_id = req->client_id;
    binding->iaid = req->ia_pd[0].iaid;
    binding->pd_exclude = pd_exclude;
    binding->bound_at = ogs_time_now();

    if (refresh)
        ogs_debug("[%s] DHCPv6-PD refreshed %s/%d IAID[0x%x] (%s)",
                sess_id_str(sess), OGS_INET6_NTOP(prefix->prefix, buf),
                prefix->prefixlen, binding->iaid,
                ogs_dhcpv6_msg_type_name(req->msg_type));
    else
        ogs_info("[%s] DHCPv6-PD delegated %s/%d%s IAID[0x%x] to client "
                "DUID[%s] (%s)", sess_id_str(sess),
                OGS_INET6_NTOP(prefix->prefix, buf), prefix->prefixlen,
                pd_exclude ? " (link /64 excluded)" : "",
                binding->iaid, duid_str(&req->client_id, duid),
                ogs_dhcpv6_msg_type_name(req->msg_type));
}

static void binding_release(smf_sess_t *sess)
{
    char duid[SMF_DHCPV6_LOG_DUID_LEN * 2 + 3];

    ogs_assert(sess);

    ogs_info("[%s] DHCPv6-PD released IAID[0x%x] by client DUID[%s]",
            sess_id_str(sess), sess->dhcpv6.iaid,
            duid_str(&sess->dhcpv6.client_id, duid));

    memset(&sess->dhcpv6, 0, sizeof(sess->dhcpv6));
}

/*
 * Message handlers. Each fills `rsp` and returns true, or returns false
 * when the message is to be discarded (RFC 8415 section 16).
 */

/* RFC 8415 section 18.4: a unicast message is answered with UseMulticast,
 * Server-ID, Client-ID and nothing else - in an Advertise when the
 * message was a Solicit, in a Reply for any other message type */
static bool handle_unicast(
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    reply_init(rsp, req, req->msg_type == OGS_DHCPV6_SOLICIT ?
            OGS_DHCPV6_ADVERTISE : OGS_DHCPV6_REPLY);
    status_set(&rsp->status, OGS_DHCPV6_STATUS_USE_MULTICAST, NULL);

    return true;
}

static bool handle_solicit(smf_sess_t *sess,
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    ogs_dhcpv6_iaprefix_t prefix;
    bool pd_exclude, have_prefix, commit;

    pd_exclude = ogs_dhcpv6_oro_contains(req, OGS_DHCPV6_OPTION_PD_EXCLUDE);
    have_prefix = smf_dhcpv6_delegated_prefix(sess, pd_exclude, &prefix);

    /* RFC 8415 section 18.3.1: Rapid Commit turns the Solicit into a
     * Request when we can satisfy it and the operator allows it */
    commit = req->rapid_commit && smf_self()->dhcpv6.rapid_commit &&
        have_prefix && req->num_of_ia_pd > 0;

    reply_init(rsp, req, commit ? OGS_DHCPV6_REPLY : OGS_DHCPV6_ADVERTISE);
    if (commit)
        rsp->rapid_commit = true;
    else if (smf_self()->dhcpv6.preference) {
        rsp->preference.presence = true;
        rsp->preference.value = smf_self()->dhcpv6.preference;
    }

    reply_fill_ia_pd(rsp, req, have_prefix ? &prefix : NULL, false);
    reply_fill_ia_na(rsp, req, OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL,
            "addresses are assigned by SLAAC");
    reply_add_dns(rsp);
    reply_add_max_rt(rsp, req);

    if (commit)
        binding_commit(sess, req, &prefix, pd_exclude, false);

    return true;
}

static bool handle_request(smf_sess_t *sess,
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    ogs_dhcpv6_iaprefix_t prefix;
    bool pd_exclude, have_prefix;

    pd_exclude = ogs_dhcpv6_oro_contains(req, OGS_DHCPV6_OPTION_PD_EXCLUDE);
    have_prefix = smf_dhcpv6_delegated_prefix(sess, pd_exclude, &prefix);

    reply_init(rsp, req, OGS_DHCPV6_REPLY);
    reply_fill_ia_pd(rsp, req, have_prefix ? &prefix : NULL, true);
    reply_fill_ia_na(rsp, req, OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL,
            "addresses are assigned by SLAAC");
    reply_add_dns(rsp);
    reply_add_max_rt(rsp, req);

    if (have_prefix && req->num_of_ia_pd > 0)
        binding_commit(sess, req, &prefix, pd_exclude, false);

    return true;
}

/*
 * Renew: the binding must be active and belong to this client (any IAID).
 * Rebind: like Renew, but a client that is not the bound one is only
 * refused while a binding is active; without one the session prefix is
 * (re)delegated, the UE being the only requesting router on its link.
 */
static bool handle_renew_rebind(smf_sess_t *sess,
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    smf_dhcpv6_binding_t *binding = NULL;
    ogs_dhcpv6_iaprefix_t prefix;
    bool pd_exclude, have_prefix, same_client;

    binding = &sess->dhcpv6;
    same_client = binding->active &&
        duid_equal(&binding->client_id, &req->client_id);

    reply_init(rsp, req, OGS_DHCPV6_REPLY);

    if (!same_client &&
        (req->msg_type == OGS_DHCPV6_RENEW || binding->active)) {
        reply_fill_ia_pd_status(rsp, req, OGS_DHCPV6_STATUS_NO_BINDING,
                "no binding for this client");
        reply_fill_ia_na(rsp, req, OGS_DHCPV6_STATUS_NO_BINDING,
                "no binding for this client");
        reply_add_dns(rsp);
        reply_add_max_rt(rsp, req);
        return true;
    }

    pd_exclude = ogs_dhcpv6_oro_contains(req, OGS_DHCPV6_OPTION_PD_EXCLUDE);
    have_prefix = smf_dhcpv6_delegated_prefix(sess, pd_exclude, &prefix);

    reply_fill_ia_pd(rsp, req, have_prefix ? &prefix : NULL, true);
    reply_fill_ia_na(rsp, req, OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL,
            "addresses are assigned by SLAAC");
    reply_add_dns(rsp);
    reply_add_max_rt(rsp, req);

    if (have_prefix && req->num_of_ia_pd > 0)
        binding_commit(sess, req, &prefix, pd_exclude, same_client);

    return true;
}

/* RFC 8415 section 18.3.7 */
static bool handle_release(smf_sess_t *sess,
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    smf_dhcpv6_binding_t *binding = NULL;
    bool released = false;
    int i;

    binding = &sess->dhcpv6;

    reply_init(rsp, req, OGS_DHCPV6_REPLY);
    status_set(&rsp->status, OGS_DHCPV6_STATUS_SUCCESS, "release received");

    for (i = 0; i < req->num_of_ia_pd; i++) {
        ogs_dhcpv6_ia_pd_t *ia = NULL;

        if (binding->active && !released &&
            binding->iaid == req->ia_pd[i].iaid &&
            duid_equal(&binding->client_id, &req->client_id)) {
            released = true;
            continue;
        }

        ia = &rsp->ia_pd[rsp->num_of_ia_pd++];
        ia->iaid = req->ia_pd[i].iaid;
        status_set(&ia->status, OGS_DHCPV6_STATUS_NO_BINDING,
                "no binding for this IA_PD");
    }
    reply_fill_ia_na(rsp, req, OGS_DHCPV6_STATUS_NO_BINDING,
            "no binding for this IA_NA");

    if (released)
        binding_release(sess);

    return true;
}

static bool handle_information_request(
        ogs_dhcpv6_message_t *rsp, const ogs_dhcpv6_message_t *req)
{
    reply_init(rsp, req, OGS_DHCPV6_REPLY);
    reply_add_dns(rsp);
    reply_add_max_rt(rsp, req);

    return true;
}

/*
 * RFC 8415 section 16 validation and dispatch. `multicast` tells whether
 * the message was sent to a multicast address (All_DHCP_Relay_Agents_and_
 * Servers); anything else is unicast and handled per section 18.4.
 */
static bool build_reply(smf_sess_t *sess, ogs_dhcpv6_message_t *rsp,
        const ogs_dhcpv6_message_t *req, bool multicast)
{
    const char *reason = NULL;

    ogs_assert(sess);
    ogs_assert(rsp);
    ogs_assert(req);

    switch (req->msg_type) {
    case OGS_DHCPV6_SOLICIT:
    case OGS_DHCPV6_REBIND:
        if (!req->client_id.len)
            reason = "no Client-ID";
        else if (req->server_id.len)
            reason = "unexpected Server-ID";
        break;
    case OGS_DHCPV6_REQUEST:
    case OGS_DHCPV6_RENEW:
    case OGS_DHCPV6_RELEASE:
        if (!req->client_id.len)
            reason = "no Client-ID";
        else if (!req->server_id.len)
            reason = "no Server-ID";
        else if (!server_id_is_ours(req))
            reason = "Server-ID is not ours";
        break;
    case OGS_DHCPV6_INFORMATION_REQUEST:
        if (req->num_of_ia_pd || req->num_of_ia_na || req->ia_ta_presence)
            reason = "IA option in Information-request";
        else if (req->server_id.len && !server_id_is_ours(req))
            reason = "Server-ID is not ours";
        break;
    default:
        /* Confirm, Decline and server-side message types: we never
         * delegate addresses, so there is nothing to confirm or decline */
        reason = "unsupported message type";
        break;
    }

    if (reason) {
        ogs_debug("[%s] DHCPv6 %s discarded: %s", sess_id_str(sess),
                ogs_dhcpv6_msg_type_name(req->msg_type), reason);
        return false;
    }

    if (!multicast && req->msg_type != OGS_DHCPV6_INFORMATION_REQUEST)
        return handle_unicast(rsp, req);

    switch (req->msg_type) {
    case OGS_DHCPV6_SOLICIT:
        return handle_solicit(sess, rsp, req);
    case OGS_DHCPV6_REQUEST:
        return handle_request(sess, rsp, req);
    case OGS_DHCPV6_RENEW:
    case OGS_DHCPV6_REBIND:
        return handle_renew_rebind(sess, rsp, req);
    case OGS_DHCPV6_RELEASE:
        return handle_release(sess, rsp, req);
    case OGS_DHCPV6_INFORMATION_REQUEST:
        return handle_information_request(rsp, req);
    default:
        ogs_assert_if_reached();
        return false;
    }
}

/*
 * Metrics
 */
static void metrics_rx(uint8_t msg_type)
{
    switch (msg_type) {
    case OGS_DHCPV6_SOLICIT:
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_SOLICIT);
        break;
    case OGS_DHCPV6_REQUEST:
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_REQUEST);
        break;
    case OGS_DHCPV6_RENEW:
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_RENEW);
        break;
    case OGS_DHCPV6_REBIND:
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_REBIND);
        break;
    case OGS_DHCPV6_RELEASE:
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_RELEASE);
        break;
    case OGS_DHCPV6_INFORMATION_REQUEST:
        smf_metrics_inst_global_inc(
                SMF_METR_GLOB_CTR_DHCPV6_RX_INFORMATION_REQUEST);
        break;
    default:
        break;
    }
}

static void metrics_tx(uint8_t msg_type)
{
    if (msg_type == OGS_DHCPV6_ADVERTISE)
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_TX_ADVERTISE);
    else
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_TX_REPLY);
}

/*
 * IPv6 + UDP encapsulation of the reply, allocated like the Router
 * Advertisement so that smf_gtp_send_to_ue() can prepend the GTP-U header.
 */
static ogs_pkbuf_t *reply_packet(const uint8_t *src, const uint8_t *dst,
        const uint8_t *payload, size_t len)
{
    ogs_pkbuf_t *pkbuf = NULL;
    struct ip6_hdr *ip6_h = NULL;
    struct udphdr *udp_h = NULL;
    size_t ulen = sizeof(struct udphdr) + len;
    uint16_t sum;

    ogs_assert(src);
    ogs_assert(dst);
    ogs_assert(payload);
    ogs_assert(ulen <= UINT16_MAX);

    pkbuf = ogs_pkbuf_alloc(NULL,
            OGS_GTPV1U_5GC_HEADER_LEN + sizeof(struct ip6_hdr) + ulen);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_GTPV1U_5GC_HEADER_LEN);
    ogs_pkbuf_put(pkbuf, sizeof(struct ip6_hdr) + ulen);
    memset(pkbuf->data, 0, pkbuf->len);

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    udp_h = (struct udphdr *)(pkbuf->data + sizeof(struct ip6_hdr));

    ip6_h->ip6_flow = htobe32(0x60000000);
    ip6_h->ip6_plen = htobe16(ulen);
    ip6_h->ip6_nxt = IPPROTO_UDP;
    ip6_h->ip6_hlim = 0xff;
    memcpy(ip6_h->ip6_src.s6_addr, src, OGS_IPV6_LEN);
    memcpy(ip6_h->ip6_dst.s6_addr, dst, OGS_IPV6_LEN);

    udp_h->uh_sport = htobe16(OGS_DHCPV6_SERVER_PORT);
    udp_h->uh_dport = htobe16(OGS_DHCPV6_CLIENT_PORT);
    udp_h->uh_ulen = htobe16(ulen);
    udp_h->uh_sum = 0;
    memcpy((uint8_t *)udp_h + sizeof(struct udphdr), payload, len);

    /* RFC 8200 section 8.1: a computed checksum of zero is sent as all ones */
    sum = ogs_in6_cksum(src, dst, IPPROTO_UDP, udp_h, ulen);
    udp_h->uh_sum = sum ? sum : 0xffff;

    return pkbuf;
}

ogs_pkbuf_t *smf_dhcpv6_handle(smf_sess_t *sess, ogs_pkbuf_t *pkbuf)
{
    ogs_dhcpv6_message_t req, rsp;
    uint8_t payload[SMF_DHCPV6_MAX_MESSAGE_LEN];
    uint8_t src[OGS_IPV6_LEN];
    struct ip6_hdr *ip6_h = NULL;
    struct udphdr *udp_h = NULL;
    const uint8_t *data = NULL;
    size_t len;
    int n;

    ogs_assert(sess);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    /* Lengths were validated by smf_dhcpv6_is_request() */
    ogs_assert(pkbuf->len >= sizeof(struct ip6_hdr) + sizeof(struct udphdr));

    ip6_h = (struct ip6_hdr *)pkbuf->data;
    udp_h = (struct udphdr *)(pkbuf->data + sizeof(struct ip6_hdr));
    data = (const uint8_t *)udp_h + sizeof(struct udphdr);
    len = be16toh(udp_h->uh_ulen) - sizeof(struct udphdr);

    if (ogs_dhcpv6_parse(&req, data, len) != OGS_OK) {
        ogs_warn("[%s] DHCPv6 %s[%d] len[%zu] cannot be parsed, dropped",
                sess_id_str(sess),
                ogs_dhcpv6_msg_type_name(len ? data[0] : 0),
                len ? data[0] : 0, len);
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_DROPPED);
        return NULL;
    }

    ogs_debug("[%s] DHCPv6 %s xid[0x%06x] ia_pd[%d] ia_na[%d] oro[%d] "
            "rapid_commit[%d]", sess_id_str(sess),
            ogs_dhcpv6_msg_type_name(req.msg_type), req.transaction_id,
            req.num_of_ia_pd, req.num_of_ia_na, req.num_of_oro,
            req.rapid_commit);
    metrics_rx(req.msg_type);

    if (!build_reply(sess, &rsp, &req,
                IN6_IS_ADDR_MULTICAST(&ip6_h->ip6_dst))) {
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_DROPPED);
        return NULL;
    }

    n = ogs_dhcpv6_build(&rsp, payload, sizeof(payload));
    if (n < 0) {
        ogs_warn("[%s] DHCPv6 %s to %s does not fit in %d octets, dropped",
                sess_id_str(sess), ogs_dhcpv6_msg_type_name(rsp.msg_type),
                ogs_dhcpv6_msg_type_name(req.msg_type),
                SMF_DHCPV6_MAX_MESSAGE_LEN);
        smf_metrics_inst_global_inc(SMF_METR_GLOB_CTR_DHCPV6_RX_DROPPED);
        return NULL;
    }

    ogs_debug("[%s] DHCPv6 %s xid[0x%06x] len[%d]", sess_id_str(sess),
            ogs_dhcpv6_msg_type_name(rsp.msg_type), rsp.transaction_id, n);
    metrics_tx(rsp.msg_type);

    smf_gtp_link_local_addr(src);

    return reply_packet(src, ip6_h->ip6_src.s6_addr, payload, n);
}
