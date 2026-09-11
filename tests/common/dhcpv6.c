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

#include "test-common.h"

const uint8_t test_dhcpv6_all_servers_addr[OGS_IPV6_LEN] = {
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02
};

/*
 * Builder
 */

typedef struct cursor_s {
    uint8_t *buf;
    size_t len;
    size_t pos;
    bool overflow;
} cursor_t;

static void put_bytes(cursor_t *c, const void *data, size_t n)
{
    if (c->overflow || n > c->len - c->pos) {
        c->overflow = true;
        return;
    }
    if (n)
        memcpy(c->buf + c->pos, data, n);
    c->pos += n;
}

static void put8(cursor_t *c, uint8_t v)
{
    put_bytes(c, &v, 1);
}

static void put16(cursor_t *c, uint16_t v)
{
    uint8_t b[2] = { v >> 8, v & 0xff };
    put_bytes(c, b, 2);
}

static void put32(cursor_t *c, uint32_t v)
{
    uint8_t b[4] = { v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff };
    put_bytes(c, b, 4);
}

/* Writes the option header; returns the offset of the option-data */
static size_t begin_option(cursor_t *c, uint16_t code)
{
    put16(c, code);
    put16(c, 0);
    return c->pos;
}

static void end_option(cursor_t *c, size_t start)
{
    size_t n;

    if (c->overflow)
        return;
    n = c->pos - start;
    c->buf[start-2] = n >> 8;
    c->buf[start-1] = n & 0xff;
}

static void put_duid(cursor_t *c, uint16_t code, const test_dhcpv6_duid_t *duid)
{
    size_t start;

    if (!duid->len)
        return;
    start = begin_option(c, code);
    put_bytes(c, duid->data, duid->len);
    end_option(c, start);
}

static void put_status(cursor_t *c, const test_dhcpv6_status_t *status)
{
    size_t start;

    if (!status->presence)
        return;
    start = begin_option(c, TEST_DHCPV6_OPTION_STATUS_CODE);
    put16(c, status->code);
    put_bytes(c, status->message, strlen(status->message));
    end_option(c, start);
}

static void put_iaprefix(cursor_t *c, const test_dhcpv6_iaprefix_t *iaprefix)
{
    size_t start, sub;
    uint8_t exclude[1+OGS_IPV6_LEN];
    int n;

    start = begin_option(c, TEST_DHCPV6_OPTION_IAPREFIX);
    put32(c, iaprefix->preferred_lifetime);
    put32(c, iaprefix->valid_lifetime);
    put8(c, iaprefix->prefixlen);
    put_bytes(c, iaprefix->prefix, OGS_IPV6_LEN);
    if (iaprefix->pd_exclude.presence) {
        n = test_dhcpv6_pd_exclude_encode(
                iaprefix->prefix, iaprefix->prefixlen,
                iaprefix->pd_exclude.prefix, iaprefix->pd_exclude.prefixlen,
                exclude, sizeof exclude);
        if (n < 0) {
            c->overflow = true;
            return;
        }
        sub = begin_option(c, TEST_DHCPV6_OPTION_PD_EXCLUDE);
        put_bytes(c, exclude, n);
        end_option(c, sub);
    }
    end_option(c, start);
}

static void put_ia_pd(cursor_t *c, const test_dhcpv6_ia_pd_t *ia_pd)
{
    size_t start;
    int i;

    start = begin_option(c, TEST_DHCPV6_OPTION_IA_PD);
    put32(c, ia_pd->iaid);
    put32(c, ia_pd->t1);
    put32(c, ia_pd->t2);
    for (i = 0; i < ia_pd->num_of_prefix &&
            i < TEST_DHCPV6_MAX_NUM_OF_IAPREFIX; i++)
        put_iaprefix(c, &ia_pd->prefix[i]);
    put_status(c, &ia_pd->status);
    end_option(c, start);
}

static void put_ia_na(cursor_t *c, const test_dhcpv6_ia_na_t *ia_na)
{
    size_t start;

    start = begin_option(c, TEST_DHCPV6_OPTION_IA_NA);
    put32(c, ia_na->iaid);
    put32(c, ia_na->t1);
    put32(c, ia_na->t2);
    put_status(c, &ia_na->status);
    end_option(c, start);
}

int test_dhcpv6_build(
        const test_dhcpv6_msg_t *msg, uint8_t *buf, size_t buflen)
{
    cursor_t c;
    size_t start;
    int i;

    ogs_assert(msg);
    ogs_assert(buf);

    memset(&c, 0, sizeof c);
    c.buf = buf;
    c.len = buflen;

    put8(&c, msg->msg_type);
    put8(&c, (msg->transaction_id >> 16) & 0xff);
    put8(&c, (msg->transaction_id >> 8) & 0xff);
    put8(&c, msg->transaction_id & 0xff);

    put_duid(&c, TEST_DHCPV6_OPTION_CLIENTID, &msg->client_id);
    put_duid(&c, TEST_DHCPV6_OPTION_SERVERID, &msg->server_id);

    if (msg->elapsed_time.presence) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_ELAPSED_TIME);
        put16(&c, msg->elapsed_time.value);
        end_option(&c, start);
    }

    if (msg->num_of_oro) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_ORO);
        for (i = 0; i < msg->num_of_oro && i < TEST_DHCPV6_MAX_NUM_OF_ORO; i++)
            put16(&c, msg->oro[i]);
        end_option(&c, start);
    }

    if (msg->rapid_commit) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_RAPID_COMMIT);
        end_option(&c, start);
    }

    if (msg->preference.presence) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_PREFERENCE);
        put8(&c, msg->preference.value);
        end_option(&c, start);
    }

    for (i = 0; i < msg->num_of_ia_na && i < TEST_DHCPV6_MAX_NUM_OF_IA_NA; i++)
        put_ia_na(&c, &msg->ia_na[i]);

    for (i = 0; i < msg->num_of_ia_pd && i < TEST_DHCPV6_MAX_NUM_OF_IA_PD; i++)
        put_ia_pd(&c, &msg->ia_pd[i]);

    put_status(&c, &msg->status);

    if (msg->information_refresh_time.presence) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_INFORMATION_REFRESH_TIME);
        put32(&c, msg->information_refresh_time.value);
        end_option(&c, start);
    }

    if (msg->num_of_dns) {
        start = begin_option(&c, TEST_DHCPV6_OPTION_DNS_SERVERS);
        for (i = 0; i < msg->num_of_dns && i < TEST_DHCPV6_MAX_NUM_OF_DNS; i++)
            put_bytes(&c, msg->dns[i], OGS_IPV6_LEN);
        end_option(&c, start);
    }

    if (c.overflow)
        return -1;

    return (int)c.pos;
}

/*
 * Parser
 */

static uint16_t get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int parse_duid(test_dhcpv6_duid_t *duid, const uint8_t *p, size_t n)
{
    if (duid->len)
        return OGS_ERROR;   /* duplicated singleton option */
    if (n == 0 || n > TEST_DHCPV6_MAX_DUID_LEN)
        return OGS_ERROR;
    duid->len = n;
    memcpy(duid->data, p, n);
    return OGS_OK;
}

static int parse_status(test_dhcpv6_status_t *status,
        const uint8_t *p, size_t n)
{
    if (status->presence)
        return OGS_ERROR;
    if (n < 2)
        return OGS_ERROR;
    status->presence = true;
    status->code = get16(p);
    n -= 2;
    p += 2;
    if (n > TEST_DHCPV6_MAX_STATUS_MESSAGE_LEN)
        n = TEST_DHCPV6_MAX_STATUS_MESSAGE_LEN;
    memcpy(status->message, p, n);
    status->message[n] = 0;
    return OGS_OK;
}

static int parse_iaprefix(test_dhcpv6_ia_pd_t *ia_pd,
        const uint8_t *p, size_t n)
{
    test_dhcpv6_iaprefix_t *iaprefix = NULL;
    size_t pos = 0;

    if (n < 25)
        return OGS_ERROR;
    if (ia_pd->num_of_prefix >= TEST_DHCPV6_MAX_NUM_OF_IAPREFIX)
        return OGS_OK;  /* beyond our limits: ignored */

    iaprefix = &ia_pd->prefix[ia_pd->num_of_prefix];
    memset(iaprefix, 0, sizeof *iaprefix);
    iaprefix->preferred_lifetime = get32(p);
    iaprefix->valid_lifetime = get32(p+4);
    iaprefix->prefixlen = p[8];
    if (iaprefix->prefixlen > 128)
        return OGS_ERROR;
    memcpy(iaprefix->prefix, p+9, OGS_IPV6_LEN);
    pos = 25;

    while (pos < n) {
        uint16_t code, olen;

        if (n - pos < 4)
            return OGS_ERROR;
        code = get16(p+pos);
        olen = get16(p+pos+2);
        pos += 4;
        if (olen > n - pos)
            return OGS_ERROR;

        if (code == TEST_DHCPV6_OPTION_PD_EXCLUDE) {
            if (iaprefix->pd_exclude.presence)
                return OGS_ERROR;
            if (test_dhcpv6_pd_exclude_decode(
                        iaprefix->prefix, iaprefix->prefixlen,
                        p+pos, olen,
                        iaprefix->pd_exclude.prefix,
                        &iaprefix->pd_exclude.prefixlen) != OGS_OK)
                return OGS_ERROR;
            iaprefix->pd_exclude.presence = true;
        }
        /* other IAPREFIX sub-options (e.g. STATUS_CODE) are skipped */
        pos += olen;
    }

    ia_pd->num_of_prefix++;
    return OGS_OK;
}

static int parse_ia_pd(test_dhcpv6_msg_t *msg, const uint8_t *p, size_t n)
{
    test_dhcpv6_ia_pd_t *ia_pd = NULL;
    size_t pos = 0;

    if (n < 12)
        return OGS_ERROR;
    if (msg->num_of_ia_pd >= TEST_DHCPV6_MAX_NUM_OF_IA_PD)
        return OGS_OK;  /* beyond our limits: ignored */

    ia_pd = &msg->ia_pd[msg->num_of_ia_pd];
    memset(ia_pd, 0, sizeof *ia_pd);
    ia_pd->iaid = get32(p);
    ia_pd->t1 = get32(p+4);
    ia_pd->t2 = get32(p+8);
    pos = 12;

    while (pos < n) {
        uint16_t code, olen;

        if (n - pos < 4)
            return OGS_ERROR;
        code = get16(p+pos);
        olen = get16(p+pos+2);
        pos += 4;
        if (olen > n - pos)
            return OGS_ERROR;

        switch (code) {
        case TEST_DHCPV6_OPTION_IAPREFIX:
            if (parse_iaprefix(ia_pd, p+pos, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        case TEST_DHCPV6_OPTION_STATUS_CODE:
            if (parse_status(&ia_pd->status, p+pos, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        default:
            break;
        }
        pos += olen;
    }

    msg->num_of_ia_pd++;
    return OGS_OK;
}

static int parse_ia_na(test_dhcpv6_msg_t *msg, const uint8_t *p, size_t n)
{
    test_dhcpv6_ia_na_t *ia_na = NULL;
    size_t pos = 0;

    if (n < 12)
        return OGS_ERROR;
    msg->ia_na_presence = true;
    if (msg->num_of_ia_na >= TEST_DHCPV6_MAX_NUM_OF_IA_NA)
        return OGS_OK;  /* beyond our limits: ignored */

    ia_na = &msg->ia_na[msg->num_of_ia_na];
    memset(ia_na, 0, sizeof *ia_na);
    ia_na->iaid = get32(p);
    ia_na->t1 = get32(p+4);
    ia_na->t2 = get32(p+8);
    pos = 12;

    while (pos < n) {
        uint16_t code, olen;

        if (n - pos < 4)
            return OGS_ERROR;
        code = get16(p+pos);
        olen = get16(p+pos+2);
        pos += 4;
        if (olen > n - pos)
            return OGS_ERROR;

        switch (code) {
        case TEST_DHCPV6_OPTION_STATUS_CODE:
            if (parse_status(&ia_na->status, p+pos, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        default:
            /* IAADDR and anything else: we never asked for addresses */
            break;
        }
        pos += olen;
    }

    msg->num_of_ia_na++;
    return OGS_OK;
}

int test_dhcpv6_parse(
        test_dhcpv6_msg_t *msg, const uint8_t *data, size_t len)
{
    size_t pos = 0;
    bool elapsed_seen = false, rapid_seen = false;
    bool oro_seen = false, dns_seen = false, pref_seen = false;
    bool irt_seen = false;
    int i;

    ogs_assert(msg);
    memset(msg, 0, sizeof *msg);

    if (!data || len < 4 || len > TEST_DHCPV6_MAX_MESSAGE_LEN)
        return OGS_ERROR;

    msg->msg_type = data[0];
    msg->transaction_id =
        ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    pos = 4;

    while (pos < len) {
        uint16_t code, olen;
        const uint8_t *p = NULL;

        if (len - pos < 4)
            return OGS_ERROR;
        code = get16(data+pos);
        olen = get16(data+pos+2);
        pos += 4;
        if (olen > len - pos)
            return OGS_ERROR;
        p = data + pos;

        switch (code) {
        case TEST_DHCPV6_OPTION_CLIENTID:
            if (parse_duid(&msg->client_id, p, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        case TEST_DHCPV6_OPTION_SERVERID:
            if (parse_duid(&msg->server_id, p, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        case TEST_DHCPV6_OPTION_IA_NA:
            if (parse_ia_na(msg, p, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        case TEST_DHCPV6_OPTION_IA_TA:
            msg->ia_na_presence = true;
            break;
        case TEST_DHCPV6_OPTION_VENDOR_CLASS:
            /* enterprise-number + vendor-class-data: skipped like any
             * other option we do not understand (HX220 sends it) */
            break;
        case TEST_DHCPV6_OPTION_INFORMATION_REFRESH_TIME:
            if (irt_seen || olen != 4)
                return OGS_ERROR;
            irt_seen = true;
            msg->information_refresh_time.presence = true;
            msg->information_refresh_time.value = get32(p);
            break;
        case TEST_DHCPV6_OPTION_ORO:
            if (oro_seen || (olen % 2))
                return OGS_ERROR;
            oro_seen = true;
            for (i = 0; i < olen / 2; i++) {
                if (msg->num_of_oro >= TEST_DHCPV6_MAX_NUM_OF_ORO)
                    break;
                msg->oro[msg->num_of_oro++] = get16(p + 2*i);
            }
            break;
        case TEST_DHCPV6_OPTION_PREFERENCE:
            if (pref_seen || olen != 1)
                return OGS_ERROR;
            pref_seen = true;
            msg->preference.presence = true;
            msg->preference.value = p[0];
            break;
        case TEST_DHCPV6_OPTION_ELAPSED_TIME:
            if (elapsed_seen || olen != 2)
                return OGS_ERROR;
            elapsed_seen = true;
            msg->elapsed_time.presence = true;
            msg->elapsed_time.value = get16(p);
            break;
        case TEST_DHCPV6_OPTION_STATUS_CODE:
            if (parse_status(&msg->status, p, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        case TEST_DHCPV6_OPTION_RAPID_COMMIT:
            if (rapid_seen || olen != 0)
                return OGS_ERROR;
            rapid_seen = true;
            msg->rapid_commit = true;
            break;
        case TEST_DHCPV6_OPTION_DNS_SERVERS:
            if (dns_seen || (olen % OGS_IPV6_LEN))
                return OGS_ERROR;
            dns_seen = true;
            for (i = 0; i < olen / OGS_IPV6_LEN; i++) {
                if (msg->num_of_dns >= TEST_DHCPV6_MAX_NUM_OF_DNS)
                    break;
                memcpy(msg->dns[msg->num_of_dns++],
                        p + OGS_IPV6_LEN*i, OGS_IPV6_LEN);
            }
            break;
        case TEST_DHCPV6_OPTION_IA_PD:
            if (parse_ia_pd(msg, p, olen) != OGS_OK)
                return OGS_ERROR;
            break;
        default:
            /* unknown options are skipped */
            break;
        }
        pos += olen;
    }

    return OGS_OK;
}

/*
 * Helpers
 */

bool test_dhcpv6_oro_contains(const test_dhcpv6_msg_t *msg, uint16_t code)
{
    int i;

    ogs_assert(msg);
    for (i = 0; i < msg->num_of_oro; i++)
        if (msg->oro[i] == code)
            return true;
    return false;
}

bool test_dhcpv6_duid_equal(
        const test_dhcpv6_duid_t *a, const test_dhcpv6_duid_t *b)
{
    ogs_assert(a);
    ogs_assert(b);
    if (a->len != b->len || a->len == 0)
        return false;
    return memcmp(a->data, b->data, a->len) == 0;
}

void test_dhcpv6_duid_ll(test_dhcpv6_duid_t *duid, const uint8_t *iid)
{
    ogs_assert(duid);
    ogs_assert(iid);

    memset(duid, 0, sizeof *duid);
    duid->len = 10;
    duid->data[0] = 0x00; duid->data[1] = 0x03;    /* DUID-LL */
    duid->data[2] = 0x00; duid->data[3] = 0x01;    /* Ethernet */
    /* EUI-64 -> MAC-48 (drop ff:fe, clear the U/L bit) */
    duid->data[4] = iid[0] ^ 0x02;
    duid->data[5] = iid[1];
    duid->data[6] = iid[2];
    duid->data[7] = iid[5];
    duid->data[8] = iid[6];
    duid->data[9] = iid[7];
}

static bool prefix_bit(const uint8_t *prefix, int bit)
{
    return (prefix[bit / 8] >> (7 - (bit % 8))) & 1;
}

static void set_prefix_bit(uint8_t *prefix, int bit)
{
    prefix[bit / 8] |= 0x80 >> (bit % 8);
}

static void mask_prefix(uint8_t *out, const uint8_t *in, uint8_t prefixlen)
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
 * RFC 6603 section 4.2:
 *   prefix-len      length of the excluded prefix (delegated-len+1 .. 128)
 *   IPv6 subnet ID  the excluded-prefix bits following the delegated
 *                   prefix, left-aligned and zero-padded to an octet
 *                   boundary (example in the RFC: 2001:db8:dead:bee0::/59
 *                   excluding 2001:db8:dead:beef::/64 -> 0x40 0x78).
 */
int test_dhcpv6_pd_exclude_encode(
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *excluded, uint8_t excluded_len,
        uint8_t *out, size_t outlen)
{
    int nbits, nbytes, i;
    uint8_t masked[OGS_IPV6_LEN];

    ogs_assert(delegated);
    ogs_assert(excluded);
    ogs_assert(out);

    if (excluded_len > 128 || excluded_len <= delegated_len)
        return -1;
    /* the excluded prefix must lie inside the delegated prefix */
    mask_prefix(masked, excluded, delegated_len);
    if (memcmp(masked, delegated, OGS_IPV6_LEN) != 0)
        return -1;

    nbits = excluded_len - delegated_len;
    nbytes = (nbits + 7) / 8;
    if (outlen < (size_t)(1 + nbytes))
        return -1;

    memset(out, 0, 1 + nbytes);
    out[0] = excluded_len;
    for (i = 0; i < nbits; i++)
        if (prefix_bit(excluded, delegated_len + i))
            set_prefix_bit(out + 1, i);

    return 1 + nbytes;
}

int test_dhcpv6_pd_exclude_decode(
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *data, size_t len,
        uint8_t *excluded, uint8_t *excluded_len)
{
    int nbits, nbytes, i;

    ogs_assert(delegated);
    ogs_assert(data);
    ogs_assert(excluded);
    ogs_assert(excluded_len);

    if (len < 2)
        return OGS_ERROR;
    if (data[0] > 128 || data[0] <= delegated_len)
        return OGS_ERROR;
    nbits = data[0] - delegated_len;
    nbytes = (nbits + 7) / 8;
    if (len != (size_t)(1 + nbytes))
        return OGS_ERROR;

    mask_prefix(excluded, delegated, delegated_len);
    for (i = 0; i < nbits; i++)
        if (prefix_bit(data + 1, i))
            set_prefix_bit(excluded, delegated_len + i);
    *excluded_len = data[0];

    return OGS_OK;
}

const char *test_dhcpv6_msg_type_name(uint8_t type)
{
    switch (type) {
    case TEST_DHCPV6_SOLICIT: return "Solicit";
    case TEST_DHCPV6_ADVERTISE: return "Advertise";
    case TEST_DHCPV6_REQUEST: return "Request";
    case TEST_DHCPV6_CONFIRM: return "Confirm";
    case TEST_DHCPV6_RENEW: return "Renew";
    case TEST_DHCPV6_REBIND: return "Rebind";
    case TEST_DHCPV6_REPLY: return "Reply";
    case TEST_DHCPV6_RELEASE: return "Release";
    case TEST_DHCPV6_DECLINE: return "Decline";
    case TEST_DHCPV6_RECONFIGURE: return "Reconfigure";
    case TEST_DHCPV6_INFORMATION_REQUEST: return "Information-request";
    default: return "Unknown";
    }
}

const char *test_dhcpv6_status_name(uint16_t code)
{
    switch (code) {
    case TEST_DHCPV6_STATUS_SUCCESS: return "Success";
    case TEST_DHCPV6_STATUS_UNSPEC_FAIL: return "UnspecFail";
    case TEST_DHCPV6_STATUS_NO_ADDRS_AVAIL: return "NoAddrsAvail";
    case TEST_DHCPV6_STATUS_NO_BINDING: return "NoBinding";
    case TEST_DHCPV6_STATUS_NOT_ON_LINK: return "NotOnLink";
    case TEST_DHCPV6_STATUS_USE_MULTICAST: return "UseMulticast";
    case TEST_DHCPV6_STATUS_NO_PREFIX_AVAIL: return "NoPrefixAvail";
    default: return "Unknown";
    }
}
