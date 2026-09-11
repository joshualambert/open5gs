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

#include "ogs-proto.h"

/*
 * DHCPv6 (RFC 8415) codec with Prefix Delegation (IA_PD, IA Prefix) and
 * Prefix Exclude (RFC 6603). No allocation; every length is checked
 * against the enclosing buffer before it is used.
 */

/*****************************************************************************
 * Wire helpers
 *****************************************************************************/

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static bool bit_get(const uint8_t *p, unsigned i)
{
    return (p[i >> 3] >> (7 - (i & 7))) & 1;
}

static void bit_set(uint8_t *p, unsigned i)
{
    p[i >> 3] |= (uint8_t)(0x80 >> (i & 7));
}

/* Copy the first `bits` bits of `src` into `dst`, zero the rest */
static void prefix_copy(uint8_t dst[OGS_IPV6_LEN],
        const uint8_t *src, unsigned bits)
{
    unsigned bytes = bits >> 3;

    memset(dst, 0, OGS_IPV6_LEN);
    if (bytes)
        memcpy(dst, src, bytes);
    if (bits & 7)
        dst[bytes] = src[bytes] & (uint8_t)(0xff << (8 - (bits & 7)));
}

static bool prefix_match(const uint8_t *a, const uint8_t *b, unsigned bits)
{
    unsigned bytes = bits >> 3;

    if (bytes && memcmp(a, b, bytes) != 0)
        return false;
    if (bits & 7) {
        uint8_t mask = (uint8_t)(0xff << (8 - (bits & 7)));
        if ((a[bytes] & mask) != (b[bytes] & mask))
            return false;
    }
    return true;
}

/*****************************************************************************
 * RFC 6603 section 4.2 IPv6 subnet ID
 *****************************************************************************/

int ogs_dhcpv6_pd_exclude_encode(uint8_t out[16], uint8_t *out_len,
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *excluded, uint8_t excluded_len)
{
    unsigned a = delegated_len, b = excluded_len, i;

    if (!out || !out_len || !delegated || !excluded)
        return OGS_ERROR;
    /* b must be at least a+1 and at most 128 */
    if (a > OGS_IPV6_128_PREFIX_LEN - 1 || b <= a ||
            b > OGS_IPV6_128_PREFIX_LEN)
        return OGS_ERROR;
    /* p1 and p2 must share a common prefix of 'a' bits */
    if (!prefix_match(delegated, excluded, a))
        return OGS_ERROR;

    /*
     * p = p2 << a, emitted MSB first; trailing bits are zeroed.
     * d = ((b-a-1)/8)+1 octets.
     */
    memset(out, 0, OGS_IPV6_LEN);
    for (i = 0; i < b - a; i++)
        if (bit_get(excluded, a + i))
            bit_set(out, i);
    *out_len = (uint8_t)(((b - a - 1) / 8) + 1);

    return OGS_OK;
}

int ogs_dhcpv6_pd_exclude_decode(uint8_t excluded[16],
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *subnet_id, uint8_t subnet_id_len, uint8_t excluded_len)
{
    unsigned a = delegated_len, b = excluded_len, i;

    if (!excluded || !delegated || !subnet_id)
        return OGS_ERROR;
    if (a > OGS_IPV6_128_PREFIX_LEN - 1 || b <= a ||
            b > OGS_IPV6_128_PREFIX_LEN)
        return OGS_ERROR;
    if (subnet_id_len != ((b - a - 1) / 8) + 1)
        return OGS_ERROR;

    prefix_copy(excluded, delegated, a);
    for (i = 0; i < b - a; i++)
        if (bit_get(subnet_id, i))
            bit_set(excluded, a + i);

    return OGS_OK;
}

/*****************************************************************************
 * Parser
 *****************************************************************************/

typedef int (*option_handler_f)(
        void *ctx, uint16_t code, const uint8_t *p, uint16_t len);

/*
 * Walk a sequence of options; every option is checked to fit in [p, p+len)
 * before the handler sees it.
 */
static int parse_options(const uint8_t *p, size_t len,
        option_handler_f handler, void *ctx)
{
    size_t off = 0;

    while (off < len) {
        uint16_t code, olen;
        int rv;

        if (len - off < OGS_DHCPV6_OPTION_HEADER_LEN) {
            ogs_debug("DHCPv6: truncated option header [%u:%u]",
                    (unsigned)off, (unsigned)len);
            return OGS_ERROR;
        }
        code = get16(p + off);
        olen = get16(p + off + 2);
        off += OGS_DHCPV6_OPTION_HEADER_LEN;

        if (olen > len - off) {
            ogs_debug("DHCPv6: option[%u] len[%u] exceeds remaining[%u]",
                    code, olen, (unsigned)(len - off));
            return OGS_ERROR;
        }

        rv = handler(ctx, code, p + off, olen);
        if (rv != OGS_OK)
            return rv;

        off += olen;
    }

    return OGS_OK;
}

static int parse_duid(ogs_dhcpv6_duid_t *duid,
        uint16_t code, const uint8_t *p, uint16_t len)
{
    if (duid->len) {
        ogs_debug("DHCPv6: duplicated option[%u]", code);
        return OGS_ERROR;
    }
    if (len < OGS_DHCPV6_MIN_DUID_LEN || len > OGS_DHCPV6_MAX_DUID_LEN) {
        ogs_debug("DHCPv6: invalid DUID length[%u] in option[%u]", len, code);
        return OGS_ERROR;
    }
    duid->len = len;
    memcpy(duid->data, p, len);
    return OGS_OK;
}

static int parse_status(ogs_dhcpv6_status_t *status,
        const uint8_t *p, uint16_t len)
{
    size_t mlen;

    if (status->presence) {
        ogs_debug("DHCPv6: duplicated STATUS_CODE");
        return OGS_ERROR;
    }
    if (len < OGS_DHCPV6_STATUS_CODE_FIXED_LEN) {
        ogs_debug("DHCPv6: STATUS_CODE too short[%u]", len);
        return OGS_ERROR;
    }
    status->presence = true;
    status->code = get16(p);
    mlen = len - OGS_DHCPV6_STATUS_CODE_FIXED_LEN;
    if (mlen > OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN)
        mlen = OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN;
    memcpy(status->message, p + OGS_DHCPV6_STATUS_CODE_FIXED_LEN, mlen);
    status->message[mlen] = '\0';
    return OGS_OK;
}

/* Structural check only, used where we do not keep the content */
static int skip_option(void *ctx, uint16_t code, const uint8_t *p, uint16_t len)
{
    ogs_dhcpv6_status_t status;

    if (code == OGS_DHCPV6_OPTION_STATUS_CODE) {
        memset(&status, 0, sizeof(status));
        return parse_status(&status, p, len);
    }
    return OGS_OK;
}

static int iaprefix_option(void *ctx,
        uint16_t code, const uint8_t *p, uint16_t len)
{
    ogs_dhcpv6_iaprefix_t *iaprefix = ctx;
    uint8_t excluded_len;

    switch (code) {
    case OGS_DHCPV6_OPTION_PD_EXCLUDE:
        if (iaprefix->pd_exclude.presence) {
            ogs_debug("DHCPv6: duplicated PD_EXCLUDE");
            return OGS_ERROR;
        }
        if (len < OGS_DHCPV6_PD_EXCLUDE_MIN_LEN ||
                len > OGS_DHCPV6_PD_EXCLUDE_MAX_LEN) {
            ogs_debug("DHCPv6: invalid PD_EXCLUDE length[%u]", len);
            return OGS_ERROR;
        }
        excluded_len = p[0];
        if (excluded_len <= iaprefix->prefixlen ||
                excluded_len > OGS_IPV6_128_PREFIX_LEN) {
            ogs_debug("DHCPv6: invalid PD_EXCLUDE prefix-len[%u] for /%u",
                    excluded_len, iaprefix->prefixlen);
            return OGS_ERROR;
        }
        if (ogs_dhcpv6_pd_exclude_decode(iaprefix->pd_exclude.prefix,
                    iaprefix->prefix, iaprefix->prefixlen,
                    p + 1, (uint8_t)(len - 1), excluded_len) != OGS_OK) {
            ogs_debug("DHCPv6: invalid PD_EXCLUDE subnet-id[%u] for /%u../%u",
                    len - 1, iaprefix->prefixlen, excluded_len);
            return OGS_ERROR;
        }
        iaprefix->pd_exclude.presence = true;
        iaprefix->pd_exclude.prefixlen = excluded_len;
        return OGS_OK;
    case OGS_DHCPV6_OPTION_STATUS_CODE:
        /* Allowed by RFC 8415 section 21.22 but of no use to us */
        return skip_option(ctx, code, p, len);
    default:
        ogs_debug("DHCPv6: skip option[%u] in IAPREFIX", code);
        return OGS_OK;
    }
}

static int parse_iaprefix(ogs_dhcpv6_iaprefix_t *iaprefix,
        const uint8_t *p, uint16_t len)
{
    if (len < OGS_DHCPV6_IAPREFIX_FIXED_LEN) {
        ogs_debug("DHCPv6: IAPREFIX too short[%u]", len);
        return OGS_ERROR;
    }

    memset(iaprefix, 0, sizeof(*iaprefix));
    iaprefix->preferred_lifetime = get32(p);
    iaprefix->valid_lifetime = get32(p + 4);
    iaprefix->prefixlen = p[8];
    if (iaprefix->prefixlen > OGS_IPV6_128_PREFIX_LEN) {
        ogs_debug("DHCPv6: invalid IAPREFIX prefix-length[%u]",
                iaprefix->prefixlen);
        return OGS_ERROR;
    }
    memcpy(iaprefix->prefix, p + 9, OGS_IPV6_LEN);

    return parse_options(p + OGS_DHCPV6_IAPREFIX_FIXED_LEN,
            len - OGS_DHCPV6_IAPREFIX_FIXED_LEN, iaprefix_option, iaprefix);
}

static int ia_pd_option(void *ctx,
        uint16_t code, const uint8_t *p, uint16_t len)
{
    ogs_dhcpv6_ia_pd_t *ia_pd = ctx;
    ogs_dhcpv6_iaprefix_t scratch, *iaprefix;
    int rv;

    switch (code) {
    case OGS_DHCPV6_OPTION_IAPREFIX:
        iaprefix = ia_pd->num_of_prefix < OGS_DHCPV6_MAX_NUM_OF_IAPREFIX ?
            &ia_pd->prefix[ia_pd->num_of_prefix] : &scratch;
        rv = parse_iaprefix(iaprefix, p, len);
        if (rv != OGS_OK)
            return rv;
        if (iaprefix == &scratch)
            ogs_debug("DHCPv6: ignore IAPREFIX beyond [%d]",
                    OGS_DHCPV6_MAX_NUM_OF_IAPREFIX);
        else
            ia_pd->num_of_prefix++;
        return OGS_OK;
    case OGS_DHCPV6_OPTION_STATUS_CODE:
        return parse_status(&ia_pd->status, p, len);
    default:
        ogs_debug("DHCPv6: skip option[%u] in IA_PD", code);
        return OGS_OK;
    }
}

static int parse_ia_pd(ogs_dhcpv6_ia_pd_t *ia_pd,
        const uint8_t *p, uint16_t len)
{
    if (len < OGS_DHCPV6_IA_PD_FIXED_LEN) {
        ogs_debug("DHCPv6: IA_PD too short[%u]", len);
        return OGS_ERROR;
    }

    memset(ia_pd, 0, sizeof(*ia_pd));
    ia_pd->iaid = get32(p);
    ia_pd->t1 = get32(p + 4);
    ia_pd->t2 = get32(p + 8);

    return parse_options(p + OGS_DHCPV6_IA_PD_FIXED_LEN,
            len - OGS_DHCPV6_IA_PD_FIXED_LEN, ia_pd_option, ia_pd);
}

static int ia_na_option(void *ctx,
        uint16_t code, const uint8_t *p, uint16_t len)
{
    ogs_dhcpv6_ia_na_t *ia_na = ctx;

    switch (code) {
    case OGS_DHCPV6_OPTION_IAADDR:
        /* address(16) + preferred(4) + valid(4) + IAaddr-options */
        if (len < 24) {
            ogs_debug("DHCPv6: IAADDR too short[%u]", len);
            return OGS_ERROR;
        }
        return parse_options(p + 24, len - 24, skip_option, NULL);
    case OGS_DHCPV6_OPTION_STATUS_CODE:
        return parse_status(&ia_na->status, p, len);
    default:
        ogs_debug("DHCPv6: skip option[%u] in IA_NA", code);
        return OGS_OK;
    }
}

static int parse_ia_na(ogs_dhcpv6_ia_na_t *ia_na,
        const uint8_t *p, uint16_t len)
{
    if (len < OGS_DHCPV6_IA_NA_FIXED_LEN) {
        ogs_debug("DHCPv6: IA_NA too short[%u]", len);
        return OGS_ERROR;
    }

    memset(ia_na, 0, sizeof(*ia_na));
    ia_na->iaid = get32(p);
    ia_na->t1 = get32(p + 4);
    ia_na->t2 = get32(p + 8);

    return parse_options(p + OGS_DHCPV6_IA_NA_FIXED_LEN,
            len - OGS_DHCPV6_IA_NA_FIXED_LEN, ia_na_option, ia_na);
}

typedef struct parse_ctx_s {
    ogs_dhcpv6_message_t *msg;
    bool oro;
    bool dns;
    bool sol_max_rt;
    bool inf_max_rt;
    bool information_refresh_time;
} parse_ctx_t;

static int check_singleton(bool *seen, uint16_t code)
{
    if (*seen) {
        ogs_debug("DHCPv6: duplicated option[%u]", code);
        return OGS_ERROR;
    }
    *seen = true;
    return OGS_OK;
}

static int check_fixed_len(uint16_t code, uint16_t len, uint16_t expected)
{
    if (len != expected) {
        ogs_debug("DHCPv6: option[%u] len[%u] != %u", code, len, expected);
        return OGS_ERROR;
    }
    return OGS_OK;
}

static int message_option(void *ctx,
        uint16_t code, const uint8_t *p, uint16_t len)
{
    parse_ctx_t *pc = ctx;
    ogs_dhcpv6_message_t *msg = pc->msg;
    int rv, i, n;

    switch (code) {
    case OGS_DHCPV6_OPTION_CLIENTID:
        return parse_duid(&msg->client_id, code, p, len);

    case OGS_DHCPV6_OPTION_SERVERID:
        return parse_duid(&msg->server_id, code, p, len);

    case OGS_DHCPV6_OPTION_IA_NA: {
        ogs_dhcpv6_ia_na_t scratch, *ia_na;

        ia_na = msg->num_of_ia_na < OGS_DHCPV6_MAX_NUM_OF_IA_NA ?
            &msg->ia_na[msg->num_of_ia_na] : &scratch;
        rv = parse_ia_na(ia_na, p, len);
        if (rv != OGS_OK)
            return rv;
        if (ia_na == &scratch)
            ogs_debug("DHCPv6: ignore IA_NA beyond [%d]",
                    OGS_DHCPV6_MAX_NUM_OF_IA_NA);
        else
            msg->num_of_ia_na++;
        return OGS_OK;
    }

    case OGS_DHCPV6_OPTION_IA_TA:
        if (len < OGS_DHCPV6_IA_TA_FIXED_LEN) {
            ogs_debug("DHCPv6: IA_TA too short[%u]", len);
            return OGS_ERROR;
        }
        msg->ia_ta_presence = true;
        return parse_options(p + OGS_DHCPV6_IA_TA_FIXED_LEN,
                len - OGS_DHCPV6_IA_TA_FIXED_LEN, skip_option, NULL);

    case OGS_DHCPV6_OPTION_IA_PD: {
        ogs_dhcpv6_ia_pd_t scratch, *ia_pd;

        ia_pd = msg->num_of_ia_pd < OGS_DHCPV6_MAX_NUM_OF_IA_PD ?
            &msg->ia_pd[msg->num_of_ia_pd] : &scratch;
        rv = parse_ia_pd(ia_pd, p, len);
        if (rv != OGS_OK)
            return rv;
        if (ia_pd == &scratch)
            ogs_debug("DHCPv6: ignore IA_PD beyond [%d]",
                    OGS_DHCPV6_MAX_NUM_OF_IA_PD);
        else
            msg->num_of_ia_pd++;
        return OGS_OK;
    }

    case OGS_DHCPV6_OPTION_ORO:
        if (check_singleton(&pc->oro, code) != OGS_OK)
            return OGS_ERROR;
        if (len & 1) {
            ogs_debug("DHCPv6: odd ORO length[%u]", len);
            return OGS_ERROR;
        }
        n = len / 2;
        if (n > OGS_DHCPV6_MAX_NUM_OF_ORO) {
            ogs_debug("DHCPv6: ignore ORO entries beyond [%d]",
                    OGS_DHCPV6_MAX_NUM_OF_ORO);
            n = OGS_DHCPV6_MAX_NUM_OF_ORO;
        }
        for (i = 0; i < n; i++)
            msg->oro[i] = get16(p + 2 * i);
        msg->num_of_oro = n;
        return OGS_OK;

    case OGS_DHCPV6_OPTION_PREFERENCE:
        if (msg->preference.presence) {
            ogs_debug("DHCPv6: duplicated PREFERENCE");
            return OGS_ERROR;
        }
        if (check_fixed_len(code, len, 1) != OGS_OK)
            return OGS_ERROR;
        msg->preference.presence = true;
        msg->preference.value = p[0];
        return OGS_OK;

    case OGS_DHCPV6_OPTION_ELAPSED_TIME:
        if (msg->elapsed_time.presence) {
            ogs_debug("DHCPv6: duplicated ELAPSED_TIME");
            return OGS_ERROR;
        }
        if (check_fixed_len(code, len, 2) != OGS_OK)
            return OGS_ERROR;
        msg->elapsed_time.presence = true;
        msg->elapsed_time.value = get16(p);
        return OGS_OK;

    case OGS_DHCPV6_OPTION_STATUS_CODE:
        return parse_status(&msg->status, p, len);

    case OGS_DHCPV6_OPTION_RAPID_COMMIT:
        if (check_singleton(&msg->rapid_commit, code) != OGS_OK)
            return OGS_ERROR;
        return check_fixed_len(code, len, 0);

    case OGS_DHCPV6_OPTION_RECONF_ACCEPT:
        if (check_singleton(&msg->reconf_accept, code) != OGS_OK)
            return OGS_ERROR;
        return check_fixed_len(code, len, 0);

    case OGS_DHCPV6_OPTION_DNS_SERVERS:
        if (check_singleton(&pc->dns, code) != OGS_OK)
            return OGS_ERROR;
        if (len % OGS_IPV6_LEN) {
            ogs_debug("DHCPv6: DNS_SERVERS length[%u] not a multiple of 16",
                    len);
            return OGS_ERROR;
        }
        n = len / OGS_IPV6_LEN;
        if (n > OGS_DHCPV6_MAX_NUM_OF_DNS) {
            ogs_debug("DHCPv6: ignore DNS servers beyond [%d]",
                    OGS_DHCPV6_MAX_NUM_OF_DNS);
            n = OGS_DHCPV6_MAX_NUM_OF_DNS;
        }
        for (i = 0; i < n; i++)
            memcpy(msg->dns[i], p + OGS_IPV6_LEN * i, OGS_IPV6_LEN);
        msg->num_of_dns = n;
        return OGS_OK;

    case OGS_DHCPV6_OPTION_SOL_MAX_RT:
        if (check_singleton(&pc->sol_max_rt, code) != OGS_OK)
            return OGS_ERROR;
        if (check_fixed_len(code, len, 4) != OGS_OK)
            return OGS_ERROR;
        msg->sol_max_rt = get32(p);
        return OGS_OK;

    case OGS_DHCPV6_OPTION_INF_MAX_RT:
        if (check_singleton(&pc->inf_max_rt, code) != OGS_OK)
            return OGS_ERROR;
        if (check_fixed_len(code, len, 4) != OGS_OK)
            return OGS_ERROR;
        msg->inf_max_rt = get32(p);
        return OGS_OK;

    case OGS_DHCPV6_OPTION_INFORMATION_REFRESH_TIME:
        if (check_singleton(&pc->information_refresh_time, code) != OGS_OK)
            return OGS_ERROR;
        if (check_fixed_len(code, len, 4) != OGS_OK)
            return OGS_ERROR;
        msg->information_refresh_time = get32(p);
        return OGS_OK;

    default:
        ogs_debug("DHCPv6: skip unknown option[%u] len[%u]", code, len);
        return OGS_OK;
    }
}

int ogs_dhcpv6_parse(ogs_dhcpv6_message_t *msg, const uint8_t *data, size_t len)
{
    parse_ctx_t pc;

    ogs_assert(msg);
    memset(msg, 0, sizeof(*msg));

    if (!data || len < OGS_DHCPV6_HEADER_LEN) {
        ogs_debug("DHCPv6: message too short[%u]", (unsigned)len);
        return OGS_ERROR;
    }

    msg->msg_type = data[0];
    msg->transaction_id =
        ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];

    memset(&pc, 0, sizeof(pc));
    pc.msg = msg;

    return parse_options(data + OGS_DHCPV6_HEADER_LEN,
            len - OGS_DHCPV6_HEADER_LEN, message_option, &pc);
}

/*****************************************************************************
 * Builder
 *****************************************************************************/

typedef struct writer_s {
    uint8_t *buf;
    size_t len;
    size_t pos;
} writer_t;

static bool put_bytes(writer_t *w, const void *p, size_t n)
{
    if (n > w->len - w->pos)
        return false;
    if (n)
        memcpy(w->buf + w->pos, p, n);
    w->pos += n;
    return true;
}

static bool put8(writer_t *w, uint8_t v)
{
    return put_bytes(w, &v, 1);
}

static bool put16(writer_t *w, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return put_bytes(w, b, 2);
}

static bool put32(writer_t *w, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8), (uint8_t)v };
    return put_bytes(w, b, 4);
}

/* Emit an option header with a placeholder length; `*hdr` marks its start */
static bool option_begin(writer_t *w, uint16_t code, size_t *hdr)
{
    *hdr = w->pos;
    return put16(w, code) && put16(w, 0);
}

/* Patch the option-len of the option started at `hdr` */
static bool option_end(writer_t *w, size_t hdr)
{
    size_t olen = w->pos - hdr - OGS_DHCPV6_OPTION_HEADER_LEN;

    if (olen > UINT16_MAX)
        return false;
    w->buf[hdr + 2] = (uint8_t)(olen >> 8);
    w->buf[hdr + 3] = (uint8_t)olen;
    return true;
}

static bool build_duid(
        writer_t *w, uint16_t code, const ogs_dhcpv6_duid_t *duid)
{
    if (duid->len == 0)
        return true;
    if (duid->len < OGS_DHCPV6_MIN_DUID_LEN ||
            duid->len > OGS_DHCPV6_MAX_DUID_LEN)
        return false;
    return put16(w, code) && put16(w, duid->len) &&
        put_bytes(w, duid->data, duid->len);
}

static bool build_status(writer_t *w, const ogs_dhcpv6_status_t *status)
{
    size_t hdr, mlen;

    if (!status->presence)
        return true;

    mlen = strnlen(status->message, OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN);
    return option_begin(w, OGS_DHCPV6_OPTION_STATUS_CODE, &hdr) &&
        put16(w, status->code) &&
        put_bytes(w, status->message, mlen) &&
        option_end(w, hdr);
}

static bool build_iaprefix(writer_t *w, const ogs_dhcpv6_iaprefix_t *iaprefix)
{
    size_t hdr, sub;
    uint8_t subnet_id[OGS_IPV6_LEN], subnet_id_len;

    if (iaprefix->prefixlen > OGS_IPV6_128_PREFIX_LEN)
        return false;

    if (!option_begin(w, OGS_DHCPV6_OPTION_IAPREFIX, &hdr) ||
            !put32(w, iaprefix->preferred_lifetime) ||
            !put32(w, iaprefix->valid_lifetime) ||
            !put8(w, iaprefix->prefixlen) ||
            !put_bytes(w, iaprefix->prefix, OGS_IPV6_LEN))
        return false;

    if (iaprefix->pd_exclude.presence) {
        if (ogs_dhcpv6_pd_exclude_encode(subnet_id, &subnet_id_len,
                    iaprefix->prefix, iaprefix->prefixlen,
                    iaprefix->pd_exclude.prefix,
                    iaprefix->pd_exclude.prefixlen) != OGS_OK)
            return false;
        if (!option_begin(w, OGS_DHCPV6_OPTION_PD_EXCLUDE, &sub) ||
                !put8(w, iaprefix->pd_exclude.prefixlen) ||
                !put_bytes(w, subnet_id, subnet_id_len) ||
                !option_end(w, sub))
            return false;
    }

    return option_end(w, hdr);
}

static bool build_ia_pd(writer_t *w, const ogs_dhcpv6_ia_pd_t *ia_pd)
{
    size_t hdr;
    int i;

    if (ia_pd->num_of_prefix < 0 ||
            ia_pd->num_of_prefix > OGS_DHCPV6_MAX_NUM_OF_IAPREFIX)
        return false;

    if (!option_begin(w, OGS_DHCPV6_OPTION_IA_PD, &hdr) ||
            !put32(w, ia_pd->iaid) ||
            !put32(w, ia_pd->t1) ||
            !put32(w, ia_pd->t2))
        return false;

    for (i = 0; i < ia_pd->num_of_prefix; i++)
        if (!build_iaprefix(w, &ia_pd->prefix[i]))
            return false;

    return build_status(w, &ia_pd->status) && option_end(w, hdr);
}

static bool build_ia_na(writer_t *w, const ogs_dhcpv6_ia_na_t *ia_na)
{
    size_t hdr;

    return option_begin(w, OGS_DHCPV6_OPTION_IA_NA, &hdr) &&
        put32(w, ia_na->iaid) &&
        put32(w, ia_na->t1) &&
        put32(w, ia_na->t2) &&
        build_status(w, &ia_na->status) &&
        option_end(w, hdr);
}

static bool build_message(writer_t *w, const ogs_dhcpv6_message_t *msg)
{
    size_t hdr;
    int i;

    if (msg->num_of_ia_pd < 0 ||
            msg->num_of_ia_pd > OGS_DHCPV6_MAX_NUM_OF_IA_PD ||
            msg->num_of_ia_na < 0 ||
            msg->num_of_ia_na > OGS_DHCPV6_MAX_NUM_OF_IA_NA ||
            msg->num_of_oro < 0 ||
            msg->num_of_oro > OGS_DHCPV6_MAX_NUM_OF_ORO ||
            msg->num_of_dns < 0 ||
            msg->num_of_dns > OGS_DHCPV6_MAX_NUM_OF_DNS)
        return false;

    if (!put8(w, msg->msg_type) ||
            !put8(w, (uint8_t)(msg->transaction_id >> 16)) ||
            !put8(w, (uint8_t)(msg->transaction_id >> 8)) ||
            !put8(w, (uint8_t)msg->transaction_id))
        return false;

    if (!build_duid(w, OGS_DHCPV6_OPTION_CLIENTID, &msg->client_id) ||
            !build_duid(w, OGS_DHCPV6_OPTION_SERVERID, &msg->server_id))
        return false;

    for (i = 0; i < msg->num_of_ia_na; i++)
        if (!build_ia_na(w, &msg->ia_na[i]))
            return false;

    for (i = 0; i < msg->num_of_ia_pd; i++)
        if (!build_ia_pd(w, &msg->ia_pd[i]))
            return false;

    if (msg->num_of_oro) {
        if (!option_begin(w, OGS_DHCPV6_OPTION_ORO, &hdr))
            return false;
        for (i = 0; i < msg->num_of_oro; i++)
            if (!put16(w, msg->oro[i]))
                return false;
        if (!option_end(w, hdr))
            return false;
    }

    if (msg->elapsed_time.presence &&
            (!put16(w, OGS_DHCPV6_OPTION_ELAPSED_TIME) || !put16(w, 2) ||
             !put16(w, msg->elapsed_time.value)))
        return false;

    if (msg->rapid_commit &&
            (!put16(w, OGS_DHCPV6_OPTION_RAPID_COMMIT) || !put16(w, 0)))
        return false;

    if (msg->reconf_accept &&
            (!put16(w, OGS_DHCPV6_OPTION_RECONF_ACCEPT) || !put16(w, 0)))
        return false;

    if (msg->preference.presence &&
            (!put16(w, OGS_DHCPV6_OPTION_PREFERENCE) || !put16(w, 1) ||
             !put8(w, msg->preference.value)))
        return false;

    if (!build_status(w, &msg->status))
        return false;

    if (msg->num_of_dns) {
        if (!option_begin(w, OGS_DHCPV6_OPTION_DNS_SERVERS, &hdr))
            return false;
        for (i = 0; i < msg->num_of_dns; i++)
            if (!put_bytes(w, msg->dns[i], OGS_IPV6_LEN))
                return false;
        if (!option_end(w, hdr))
            return false;
    }

    if (msg->sol_max_rt &&
            (!put16(w, OGS_DHCPV6_OPTION_SOL_MAX_RT) || !put16(w, 4) ||
             !put32(w, msg->sol_max_rt)))
        return false;

    if (msg->inf_max_rt &&
            (!put16(w, OGS_DHCPV6_OPTION_INF_MAX_RT) || !put16(w, 4) ||
             !put32(w, msg->inf_max_rt)))
        return false;

    if (msg->information_refresh_time &&
            (!put16(w, OGS_DHCPV6_OPTION_INFORMATION_REFRESH_TIME) ||
             !put16(w, 4) || !put32(w, msg->information_refresh_time)))
        return false;

    return true;
}

int ogs_dhcpv6_build(
        const ogs_dhcpv6_message_t *msg, uint8_t *buf, size_t buflen)
{
    writer_t w;

    ogs_assert(msg);
    if (!buf && buflen)
        return -1;

    w.buf = buf;
    w.len = buflen;
    w.pos = 0;

    if (!build_message(&w, msg))
        return -1;

    return (int)w.pos;
}

/*****************************************************************************
 * Helpers
 *****************************************************************************/

bool ogs_dhcpv6_oro_contains(const ogs_dhcpv6_message_t *msg, uint16_t code)
{
    int i, n;

    ogs_assert(msg);
    n = msg->num_of_oro;
    if (n > OGS_DHCPV6_MAX_NUM_OF_ORO)
        n = OGS_DHCPV6_MAX_NUM_OF_ORO;
    for (i = 0; i < n; i++)
        if (msg->oro[i] == code)
            return true;
    return false;
}

const char *ogs_dhcpv6_msg_type_name(uint8_t type)
{
    switch (type) {
    case OGS_DHCPV6_SOLICIT:                return "Solicit";
    case OGS_DHCPV6_ADVERTISE:              return "Advertise";
    case OGS_DHCPV6_REQUEST:                return "Request";
    case OGS_DHCPV6_CONFIRM:                return "Confirm";
    case OGS_DHCPV6_RENEW:                  return "Renew";
    case OGS_DHCPV6_REBIND:                 return "Rebind";
    case OGS_DHCPV6_REPLY:                  return "Reply";
    case OGS_DHCPV6_RELEASE:                return "Release";
    case OGS_DHCPV6_DECLINE:                return "Decline";
    case OGS_DHCPV6_RECONFIGURE:            return "Reconfigure";
    case OGS_DHCPV6_INFORMATION_REQUEST:    return "Information-request";
    default:                                return "Unknown";
    }
}

const char *ogs_dhcpv6_status_name(uint16_t code)
{
    switch (code) {
    case OGS_DHCPV6_STATUS_SUCCESS:         return "Success";
    case OGS_DHCPV6_STATUS_UNSPEC_FAIL:     return "UnspecFail";
    case OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL:  return "NoAddrsAvail";
    case OGS_DHCPV6_STATUS_NO_BINDING:      return "NoBinding";
    case OGS_DHCPV6_STATUS_NOT_ON_LINK:     return "NotOnLink";
    case OGS_DHCPV6_STATUS_USE_MULTICAST:   return "UseMulticast";
    case OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL: return "NoPrefixAvail";
    default:                                return "Unknown";
    }
}
