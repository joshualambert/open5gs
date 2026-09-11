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

#if !defined(OGS_PROTO_INSIDE) && !defined(OGS_PROTO_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DHCPV6_H
#define OGS_DHCPV6_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DHCPv6 codec (RFC 8415) with Prefix Delegation (IA_PD / IA Prefix,
 * RFC 8415 section 21.21 / 21.22) and Prefix Exclude (RFC 6603).
 *
 * The codec is allocation free and bounds checked. Every option length is
 * validated against the remaining buffer, unknown options are skipped,
 * options that may only appear once (in a given scope) make the parse fail
 * when duplicated, and all array sizes are compile-time constants so a
 * hostile peer can never make the caller allocate.
 */

#define OGS_DHCPV6_CLIENT_PORT              546
#define OGS_DHCPV6_SERVER_PORT              547

/* Message header: msg-type(1) + transaction-id(3) */
#define OGS_DHCPV6_HEADER_LEN               4
/* Option header: option-code(2) + option-len(2) */
#define OGS_DHCPV6_OPTION_HEADER_LEN        4

/* Message types (RFC 8415 section 7.3) */
#define OGS_DHCPV6_SOLICIT                  1
#define OGS_DHCPV6_ADVERTISE                2
#define OGS_DHCPV6_REQUEST                  3
#define OGS_DHCPV6_CONFIRM                  4
#define OGS_DHCPV6_RENEW                    5
#define OGS_DHCPV6_REBIND                   6
#define OGS_DHCPV6_REPLY                    7
#define OGS_DHCPV6_RELEASE                  8
#define OGS_DHCPV6_DECLINE                  9
#define OGS_DHCPV6_RECONFIGURE              10
#define OGS_DHCPV6_INFORMATION_REQUEST      11

/* Option codes (RFC 8415 section 21, RFC 3646, RFC 6603, RFC 8415
 * section 21.23 Information Refresh Time) */
#define OGS_DHCPV6_OPTION_CLIENTID          1
#define OGS_DHCPV6_OPTION_SERVERID          2
#define OGS_DHCPV6_OPTION_IA_NA             3
#define OGS_DHCPV6_OPTION_IA_TA             4
#define OGS_DHCPV6_OPTION_IAADDR            5
#define OGS_DHCPV6_OPTION_ORO               6
#define OGS_DHCPV6_OPTION_PREFERENCE        7
#define OGS_DHCPV6_OPTION_ELAPSED_TIME      8
#define OGS_DHCPV6_OPTION_STATUS_CODE       13
#define OGS_DHCPV6_OPTION_RAPID_COMMIT      14
#define OGS_DHCPV6_OPTION_VENDOR_CLASS      16
#define OGS_DHCPV6_OPTION_RECONF_ACCEPT     20
#define OGS_DHCPV6_OPTION_DNS_SERVERS       23
#define OGS_DHCPV6_OPTION_DOMAIN_LIST       24
#define OGS_DHCPV6_OPTION_IA_PD             25
#define OGS_DHCPV6_OPTION_IAPREFIX          26
#define OGS_DHCPV6_OPTION_INFORMATION_REFRESH_TIME 32
#define OGS_DHCPV6_OPTION_PD_EXCLUDE        67
#define OGS_DHCPV6_OPTION_SOL_MAX_RT        82
#define OGS_DHCPV6_OPTION_INF_MAX_RT        83

/* Status codes (RFC 8415 section 21.13) */
#define OGS_DHCPV6_STATUS_SUCCESS           0
#define OGS_DHCPV6_STATUS_UNSPEC_FAIL       1
#define OGS_DHCPV6_STATUS_NO_ADDRS_AVAIL    2
#define OGS_DHCPV6_STATUS_NO_BINDING        3
#define OGS_DHCPV6_STATUS_NOT_ON_LINK       4
#define OGS_DHCPV6_STATUS_USE_MULTICAST     5
#define OGS_DHCPV6_STATUS_NO_PREFIX_AVAIL   6

/* Compile-time maxima. Anything beyond these is ignored by the parser. */
#define OGS_DHCPV6_MAX_DUID_LEN             130
#define OGS_DHCPV6_MIN_DUID_LEN             3   /* 2-byte type + 1 */
#define OGS_DHCPV6_MAX_NUM_OF_IA_PD         4
#define OGS_DHCPV6_MAX_NUM_OF_IA_NA         4
#define OGS_DHCPV6_MAX_NUM_OF_IAPREFIX      4
#define OGS_DHCPV6_MAX_NUM_OF_ORO           32
#define OGS_DHCPV6_MAX_NUM_OF_DNS           4
#define OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN   64

/* Fixed part of the options that carry nested options */
#define OGS_DHCPV6_IA_NA_FIXED_LEN          12  /* IAID, T1, T2 */
#define OGS_DHCPV6_IA_TA_FIXED_LEN          4   /* IAID */
#define OGS_DHCPV6_IA_PD_FIXED_LEN          12  /* IAID, T1, T2 */
#define OGS_DHCPV6_IAPREFIX_FIXED_LEN       25  /* lifetimes, len, prefix */
#define OGS_DHCPV6_STATUS_CODE_FIXED_LEN    2   /* status-code */
#define OGS_DHCPV6_PD_EXCLUDE_MIN_LEN       2   /* prefix-len + 1 octet */
#define OGS_DHCPV6_PD_EXCLUDE_MAX_LEN       17  /* prefix-len + 16 octets */

typedef struct ogs_dhcpv6_duid_s {
    uint16_t len;                       /* 0 = absent */
    uint8_t data[OGS_DHCPV6_MAX_DUID_LEN];
} ogs_dhcpv6_duid_t;

typedef struct ogs_dhcpv6_status_s {
    bool presence;
    uint16_t code;
    /*
     * Untrusted UTF-8 from the peer, truncated to
     * OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN and always NUL-terminated.
     */
    char message[OGS_DHCPV6_MAX_STATUS_MESSAGE_LEN+1];
} ogs_dhcpv6_status_t;

typedef struct ogs_dhcpv6_iaprefix_s {
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;
    uint8_t prefixlen;
    uint8_t prefix[OGS_IPV6_LEN];
    /*
     * RFC 6603 OPTION_PD_EXCLUDE. On parse `prefix` is the fully
     * reconstructed excluded prefix (all 16 octets) and `prefixlen` its
     * length; on build the subnet-id is derived from them and from the
     * enclosing IA Prefix.
     */
    struct {
        bool presence;
        uint8_t prefixlen;
        uint8_t prefix[OGS_IPV6_LEN];
    } pd_exclude;
} ogs_dhcpv6_iaprefix_t;

typedef struct ogs_dhcpv6_ia_pd_s {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    int num_of_prefix;
    ogs_dhcpv6_iaprefix_t prefix[OGS_DHCPV6_MAX_NUM_OF_IAPREFIX];
    ogs_dhcpv6_status_t status;
} ogs_dhcpv6_ia_pd_t;

typedef struct ogs_dhcpv6_ia_na_s {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    ogs_dhcpv6_status_t status;
} ogs_dhcpv6_ia_na_t;

typedef struct ogs_dhcpv6_message_s {
    uint8_t msg_type;
    uint32_t transaction_id;            /* 24 bit */

    ogs_dhcpv6_duid_t client_id;        /* len == 0 : absent */
    ogs_dhcpv6_duid_t server_id;        /* len == 0 : absent */

    int num_of_ia_pd;
    ogs_dhcpv6_ia_pd_t ia_pd[OGS_DHCPV6_MAX_NUM_OF_IA_PD];
    int num_of_ia_na;
    ogs_dhcpv6_ia_na_t ia_na[OGS_DHCPV6_MAX_NUM_OF_IA_NA];
    bool ia_ta_presence;                /* IA_TA seen (we only need to know) */

    int num_of_oro;
    uint16_t oro[OGS_DHCPV6_MAX_NUM_OF_ORO];

    bool rapid_commit;
    bool reconf_accept;

    struct {
        bool presence;
        uint16_t value;
    } elapsed_time;

    struct {
        bool presence;
        uint8_t value;
    } preference;

    ogs_dhcpv6_status_t status;         /* top-level */

    int num_of_dns;
    uint8_t dns[OGS_DHCPV6_MAX_NUM_OF_DNS][OGS_IPV6_LEN];

    uint32_t sol_max_rt;                /* 0 = absent */
    uint32_t inf_max_rt;                /* 0 = absent */

    /* RFC 8415 section 21.23, Reply to an Information-request only */
    uint32_t information_refresh_time;  /* seconds, 0 = absent */
} ogs_dhcpv6_message_t;

/*
 * Parse a DHCPv6 message. `msg` is zeroed first. Returns OGS_OK, or
 * OGS_ERROR on any malformed input (short message, option running past the
 * end of the buffer or of its enclosing option, wrong fixed length, DUID
 * outside [OGS_DHCPV6_MIN_DUID_LEN, OGS_DHCPV6_MAX_DUID_LEN], duplicated
 * singleton option, invalid PD_EXCLUDE). Unknown options are skipped and
 * entries beyond the compile-time maxima are validated but dropped.
 * Failures are logged with ogs_debug() only; the caller logs once.
 */
int ogs_dhcpv6_parse(
        ogs_dhcpv6_message_t *msg, const uint8_t *data, size_t len);

/*
 * Serialise `msg` into `buf`. Only what is set is emitted (DUIDs with
 * len > 0, each IA_PD with its IA Prefixes, their PD_EXCLUDE and status,
 * IA_NA with status only, ORO, flags, elapsed time, preference, status,
 * DNS servers, SOL_MAX_RT / INF_MAX_RT / INFORMATION_REFRESH_TIME when
 * non-zero). Returns the number of
 * bytes written, or -1 when `buf` is too small or `msg` is inconsistent.
 * The buffer is never written past `buflen`.
 */
int ogs_dhcpv6_build(
        const ogs_dhcpv6_message_t *msg, uint8_t *buf, size_t buflen);

bool ogs_dhcpv6_oro_contains(const ogs_dhcpv6_message_t *msg, uint16_t code);

/* Never return NULL: "Unknown" for values outside the tables. */
const char *ogs_dhcpv6_msg_type_name(uint8_t type);
const char *ogs_dhcpv6_status_name(uint16_t code);

/*
 * RFC 6603 section 4.2 IPv6 subnet ID encoding.
 *
 * encode: `delegated`/`delegated_len` is the IA Prefix, `excluded`/
 * `excluded_len` the prefix to exclude (must be inside the delegated one,
 * excluded_len in [delegated_len+1, 128]). Writes the subnet-id octets to
 * `out` and their count (1..16) to `*out_len`. Returns OGS_OK / OGS_ERROR.
 *
 * decode: reconstructs the full 16-octet excluded prefix from the delegated
 * prefix and the subnet-id carried in the option (`subnet_id_len` must be
 * exactly 1 + (excluded_len - delegated_len - 1) / 8, as the RFC computes it).
 * Returns OGS_OK / OGS_ERROR.
 */
int ogs_dhcpv6_pd_exclude_encode(uint8_t out[16], uint8_t *out_len,
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *excluded, uint8_t excluded_len);
int ogs_dhcpv6_pd_exclude_decode(uint8_t excluded[16],
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *subnet_id, uint8_t subnet_id_len, uint8_t excluded_len);

#ifdef __cplusplus
}
#endif

#endif /* OGS_DHCPV6_H */
