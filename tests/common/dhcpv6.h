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

/*
 * Minimal client-side DHCPv6 (RFC 8415) codec used by the test-suite.
 *
 * This is deliberately independent from the server-side codec in
 * lib/proto so that the tests cross-check the SMF implementation
 * instead of sharing code with it.  Only what a requesting router
 * (RFC 8415 section 6.3, RFC 6603) needs is implemented.
 */

#ifndef TEST_COMMON_DHCPV6_H
#define TEST_COMMON_DHCPV6_H

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_DHCPV6_CLIENT_PORT                 546
#define TEST_DHCPV6_SERVER_PORT                 547

/* All_DHCP_Relay_Agents_and_Servers (ff02::1:2) */
extern const uint8_t test_dhcpv6_all_servers_addr[OGS_IPV6_LEN];

/* Message types (RFC 8415 section 7.3) */
#define TEST_DHCPV6_SOLICIT                     1
#define TEST_DHCPV6_ADVERTISE                   2
#define TEST_DHCPV6_REQUEST                     3
#define TEST_DHCPV6_CONFIRM                     4
#define TEST_DHCPV6_RENEW                       5
#define TEST_DHCPV6_REBIND                      6
#define TEST_DHCPV6_REPLY                       7
#define TEST_DHCPV6_RELEASE                     8
#define TEST_DHCPV6_DECLINE                     9
#define TEST_DHCPV6_RECONFIGURE                 10
#define TEST_DHCPV6_INFORMATION_REQUEST         11

/* Option codes (RFC 8415 section 21, RFC 6603) */
#define TEST_DHCPV6_OPTION_CLIENTID             1
#define TEST_DHCPV6_OPTION_SERVERID             2
#define TEST_DHCPV6_OPTION_IA_NA                3
#define TEST_DHCPV6_OPTION_IA_TA                4
#define TEST_DHCPV6_OPTION_IAADDR               5
#define TEST_DHCPV6_OPTION_ORO                  6
#define TEST_DHCPV6_OPTION_PREFERENCE           7
#define TEST_DHCPV6_OPTION_ELAPSED_TIME         8
#define TEST_DHCPV6_OPTION_STATUS_CODE          13
#define TEST_DHCPV6_OPTION_RAPID_COMMIT         14
#define TEST_DHCPV6_OPTION_VENDOR_CLASS         16      /* skipped */
#define TEST_DHCPV6_OPTION_RECONF_ACCEPT        20
#define TEST_DHCPV6_OPTION_DNS_SERVERS          23
#define TEST_DHCPV6_OPTION_DOMAIN_LIST          24
#define TEST_DHCPV6_OPTION_IA_PD                25
#define TEST_DHCPV6_OPTION_IAPREFIX             26
#define TEST_DHCPV6_OPTION_INFORMATION_REFRESH_TIME 32  /* RFC 8415 21.23 */
#define TEST_DHCPV6_OPTION_PD_EXCLUDE           67
#define TEST_DHCPV6_OPTION_SOL_MAX_RT           82
#define TEST_DHCPV6_OPTION_INF_MAX_RT           83

/* Status codes (RFC 8415 section 21.13) */
#define TEST_DHCPV6_STATUS_SUCCESS              0
#define TEST_DHCPV6_STATUS_UNSPEC_FAIL          1
#define TEST_DHCPV6_STATUS_NO_ADDRS_AVAIL       2
#define TEST_DHCPV6_STATUS_NO_BINDING           3
#define TEST_DHCPV6_STATUS_NOT_ON_LINK          4
#define TEST_DHCPV6_STATUS_USE_MULTICAST        5
#define TEST_DHCPV6_STATUS_NO_PREFIX_AVAIL      6

#define TEST_DHCPV6_MAX_DUID_LEN                130
#define TEST_DHCPV6_MAX_NUM_OF_IA_PD            4
#define TEST_DHCPV6_MAX_NUM_OF_IA_NA            4
#define TEST_DHCPV6_MAX_NUM_OF_IAPREFIX         4
#define TEST_DHCPV6_MAX_NUM_OF_ORO              16
#define TEST_DHCPV6_MAX_NUM_OF_DNS              4
#define TEST_DHCPV6_MAX_STATUS_MESSAGE_LEN      64

/* Largest message the builder produces / the parser accepts */
#define TEST_DHCPV6_MAX_MESSAGE_LEN             1024

typedef struct test_dhcpv6_duid_s {
    uint16_t len;                       /* 0 = absent */
    uint8_t data[TEST_DHCPV6_MAX_DUID_LEN];
} test_dhcpv6_duid_t;

typedef struct test_dhcpv6_status_s {
    bool presence;
    uint16_t code;
    char message[TEST_DHCPV6_MAX_STATUS_MESSAGE_LEN+1];
} test_dhcpv6_status_t;

typedef struct test_dhcpv6_iaprefix_s {
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;
    uint8_t prefixlen;
    uint8_t prefix[OGS_IPV6_LEN];
    struct {
        bool presence;
        /* Decoded to the full excluded prefix (RFC 6603 section 4.2) */
        uint8_t prefixlen;
        uint8_t prefix[OGS_IPV6_LEN];
    } pd_exclude;
} test_dhcpv6_iaprefix_t;

typedef struct test_dhcpv6_ia_pd_s {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    int num_of_prefix;
    test_dhcpv6_iaprefix_t prefix[TEST_DHCPV6_MAX_NUM_OF_IAPREFIX];
    test_dhcpv6_status_t status;
} test_dhcpv6_ia_pd_t;

/* IA_NA (RFC 8415 section 21.4); addresses are never requested nor parsed,
 * only the Status Code the server puts inside the IA_NA matters here */
typedef struct test_dhcpv6_ia_na_s {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    test_dhcpv6_status_t status;
} test_dhcpv6_ia_na_t;

typedef struct test_dhcpv6_msg_s {
    uint8_t msg_type;
    uint32_t transaction_id;            /* 24 bit */

    test_dhcpv6_duid_t client_id;
    test_dhcpv6_duid_t server_id;

    int num_of_ia_pd;
    test_dhcpv6_ia_pd_t ia_pd[TEST_DHCPV6_MAX_NUM_OF_IA_PD];
    bool ia_na_presence;                /* parser only: IA_NA/IA_TA seen */
    int num_of_ia_na;
    test_dhcpv6_ia_na_t ia_na[TEST_DHCPV6_MAX_NUM_OF_IA_NA];

    int num_of_oro;
    uint16_t oro[TEST_DHCPV6_MAX_NUM_OF_ORO];

    bool rapid_commit;
    struct {
        bool presence;
        uint16_t value;
    } elapsed_time;
    struct {
        bool presence;
        uint8_t value;
    } preference;

    test_dhcpv6_status_t status;        /* top-level */

    int num_of_dns;
    uint8_t dns[TEST_DHCPV6_MAX_NUM_OF_DNS][OGS_IPV6_LEN];

    struct {                            /* OPTION_INFORMATION_REFRESH_TIME */
        bool presence;
        uint32_t value;
    } information_refresh_time;
} test_dhcpv6_msg_t;

/* Returns the number of bytes written, or -1 if buf is too small */
int test_dhcpv6_build(
        const test_dhcpv6_msg_t *msg, uint8_t *buf, size_t buflen);

/* Returns OGS_OK, or OGS_ERROR on a malformed message (never crashes) */
int test_dhcpv6_parse(
        test_dhcpv6_msg_t *msg, const uint8_t *data, size_t len);

bool test_dhcpv6_oro_contains(const test_dhcpv6_msg_t *msg, uint16_t code);
bool test_dhcpv6_duid_equal(
        const test_dhcpv6_duid_t *a, const test_dhcpv6_duid_t *b);

/* DUID-LL (type 3, Ethernet) derived from an EUI-64 interface identifier */
void test_dhcpv6_duid_ll(test_dhcpv6_duid_t *duid, const uint8_t *iid);

/*
 * RFC 6603 section 4.2 subnet-id encoding of the excluded prefix relative
 * to the delegated prefix.  encode() returns the option-data length
 * (1 + ceil((excluded_len - delegated_len) / 8)) or -1; decode() fills the
 * full excluded prefix and returns OGS_OK or OGS_ERROR.
 */
int test_dhcpv6_pd_exclude_encode(
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *excluded, uint8_t excluded_len,
        uint8_t *out, size_t outlen);
int test_dhcpv6_pd_exclude_decode(
        const uint8_t *delegated, uint8_t delegated_len,
        const uint8_t *data, size_t len,
        uint8_t *excluded, uint8_t *excluded_len);

const char *test_dhcpv6_msg_type_name(uint8_t type);
const char *test_dhcpv6_status_name(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* TEST_COMMON_DHCPV6_H */
