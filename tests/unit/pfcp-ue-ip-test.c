/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-pfcp.h"
#include "core/abts.h"

/*
 * UE IP Address IE (TS 29.244 8.2.62) with IPv6 prefix delegation and the
 * block-based IPv6 UE IP pool (ogs_pfcp_ue_pool_generate()).
 */

#define TEST_POOL_SESS 16

static void ipv6_addr(abts_case *tc, const char *str, uint8_t addr6[16])
{
    int rv;
    ogs_ipsubnet_t ip6;

    rv = ogs_ipsubnet(&ip6, str, NULL);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    memcpy(addr6, ip6.sub, OGS_IPV6_LEN);
}

static void test_ue_ip_addr_ipv6_only(abts_case *tc, void *data)
{
    int rv, len = 0;
    ogs_paa_t paa;
    ogs_pfcp_ue_ip_addr_t addr;
    uint8_t *raw = (uint8_t *)&addr;
    uint8_t addr6[OGS_IPV6_LEN];

    ipv6_addr(tc, "2001:db8:cafe:100::2", addr6);

    memset(&paa, 0, sizeof(paa));
    paa.session_type = OGS_PDU_SESSION_TYPE_IPV6;
    memcpy(paa.addr6, addr6, OGS_IPV6_LEN);

    /* Unchanged behaviour of the PAA conversion: no IPv6D, no trailing octet */
    rv = ogs_pfcp_paa_to_ue_ip_addr(&paa, &addr, &len);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 17, len);
    ABTS_INT_EQUAL(tc, 1, addr.ipv6);
    ABTS_INT_EQUAL(tc, 0, addr.ipv4);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    ABTS_TRUE(tc, memcmp(raw + 1, addr6, OGS_IPV6_LEN) == 0);
    ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* /56 : IPv6D=1, bits = 8 at offset 17, length 18 */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 18, len);
    ABTS_INT_EQUAL(tc, 1, addr.ipv6d);
    ABTS_INT_EQUAL(tc, 8, raw[17]);
    ABTS_INT_EQUAL(tc, 8, addr.ipv6_prefix_delegation_bits);
    ABTS_TRUE(tc, memcmp(raw + 1, addr6, OGS_IPV6_LEN) == 0);
    ABTS_INT_EQUAL(tc, 56, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Idempotent */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 18, len);
    ABTS_INT_EQUAL(tc, 8, raw[17]);

    /* /60 */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 60);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 18, len);
    ABTS_INT_EQUAL(tc, 4, raw[17]);
    ABTS_INT_EQUAL(tc, 60, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Boundaries: /1 and /63 */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 1);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 63, raw[17]);
    ABTS_INT_EQUAL(tc, 1, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 63);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 1, raw[17]);
    ABTS_INT_EQUAL(tc, 63, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Back to /64 : IPv6D cleared, trailing octet removed */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 64);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 17, len);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    ABTS_INT_EQUAL(tc, 0, raw[17]);
    ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Rejected values leave the IE untouched */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 0);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 17, len);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 65);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 17, len);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);

    /* Malformed on the wire: IPv6D set but the length does not cover it */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 17));
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 0));
    ABTS_INT_EQUAL(tc, 56, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 18));

    /* Malformed on the wire: bits outside 1..63 */
    raw[17] = 0;
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 18));
    raw[17] = 64;
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 18));
    raw[17] = 255;
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 18));

    /* Malformed on the wire: IPv6D without IPv6 */
    memset(&addr, 0, sizeof(addr));
    addr.ipv4 = 1;
    addr.ipv6d = 1;
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 6));

    /* IPv4-only IE cannot carry a prefix length */
    memset(&paa, 0, sizeof(paa));
    paa.session_type = OGS_PDU_SESSION_TYPE_IPV4;
    paa.addr = htobe32(0x0a2d0002);
    rv = ogs_pfcp_paa_to_ue_ip_addr(&paa, &addr, &len);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 5, len);
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 5, len);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));
}

static void test_ue_ip_addr_ipv4v6(abts_case *tc, void *data)
{
    int rv, len = 0;
    ogs_paa_t paa;
    ogs_pfcp_ue_ip_addr_t addr;
    uint8_t *raw = (uint8_t *)&addr;
    uint8_t addr6[OGS_IPV6_LEN];
    uint32_t addr4 = htobe32(0x0a2d0002); /* 10.45.0.2 */

    ipv6_addr(tc, "2001:db8:cafe:100::2", addr6);

    memset(&paa, 0, sizeof(paa));
    paa.session_type = OGS_PDU_SESSION_TYPE_IPV4V6;
    paa.both.addr = addr4;
    memcpy(paa.both.addr6, addr6, OGS_IPV6_LEN);

    rv = ogs_pfcp_paa_to_ue_ip_addr(&paa, &addr, &len);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 21, len);
    ABTS_INT_EQUAL(tc, 1, addr.ipv4);
    ABTS_INT_EQUAL(tc, 1, addr.ipv6);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    ABTS_TRUE(tc, memcmp(raw + 1, &addr4, OGS_IPV4_LEN) == 0);
    ABTS_TRUE(tc, memcmp(raw + 5, addr6, OGS_IPV6_LEN) == 0);
    ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* /56 : bits at offset 21, length 22, addresses untouched */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 22, len);
    ABTS_INT_EQUAL(tc, 1, addr.ipv6d);
    ABTS_INT_EQUAL(tc, 8, raw[21]);
    ABTS_INT_EQUAL(tc, 8, addr.both.ipv6_prefix_delegation_bits);
    ABTS_TRUE(tc, memcmp(raw + 1, &addr4, OGS_IPV4_LEN) == 0);
    ABTS_TRUE(tc, memcmp(raw + 5, addr6, OGS_IPV6_LEN) == 0);
    ABTS_TRUE(tc, addr.both.addr == addr4);
    ABTS_TRUE(tc, memcmp(addr.both.addr6, addr6, OGS_IPV6_LEN) == 0);
    ABTS_INT_EQUAL(tc, 56, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Length that stops before the trailing octet is rejected */
    ABTS_INT_EQUAL(tc, 0, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, 21));

    /* Idempotent, then /60 */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 56);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 22, len);
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 60);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 22, len);
    ABTS_INT_EQUAL(tc, 4, raw[21]);
    ABTS_INT_EQUAL(tc, 60, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Back to /64 */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 64);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 21, len);
    ABTS_INT_EQUAL(tc, 0, addr.ipv6d);
    ABTS_INT_EQUAL(tc, 0, raw[21]);
    ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_addr_ipv6_prefixlen(&addr, len));

    /* Bad prefix length */
    rv = ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(&addr, &len, 100);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 21, len);
}

/* Compare the first 64 bits of a pool entry with a textual prefix */
static bool prefix64_equal(abts_case *tc,
        const ogs_pfcp_ue_ip_t *ue_ip, const char *str)
{
    uint8_t addr6[OGS_IPV6_LEN];

    ipv6_addr(tc, str, addr6);
    return memcmp(ue_ip->addr, addr6, 8) == 0;
}

/*
 * Every entry must be a distinct full IPv6 address with a non-zero
 * interface identifier. The interface identifier counter restarts for
 * each range: entry, so it is only unique within a single range.
 */
static void check_unique_iid(abts_case *tc, ogs_pfcp_subnet_t *subnet)
{
    int i, j;

    for (i = 0; i < subnet->pool.size; i++) {
        ogs_pfcp_ue_ip_t *ue_ip = &subnet->pool.array[i];

        ABTS_TRUE(tc, ue_ip->addr[2] == 0);
        ABTS_TRUE(tc, ue_ip->addr[3] != 0);
        ABTS_PTR_EQUAL(tc, subnet, ue_ip->subnet);

        for (j = 0; j < i; j++) {
            ogs_pfcp_ue_ip_t *other = &subnet->pool.array[j];
            ABTS_TRUE(tc, memcmp(ue_ip->addr, other->addr,
                        sizeof(ue_ip->addr)) != 0);
            if (subnet->num_of_range <= 1)
                ABTS_TRUE(tc, ue_ip->addr[3] != other->addr[3]);
        }
    }
}

static void test_pool_prefix_delegation(abts_case *tc, void *data)
{
    int rv, i;
    ogs_pfcp_subnet_t *subnet = NULL;
    char str[OGS_ADDRSTRLEN];

    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    ABTS_INT_EQUAL(tc, AF_INET6, subnet->family);
    ABTS_INT_EQUAL(tc, 48, subnet->prefixlen);

    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 56, subnet->pd_prefixlen);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* A /48 has 256 blocks of /56, but the pool is capped */
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.avail);

    /* Block 0 holds the subnet address and the gateway and is skipped,
     * so the entries are 2001:db8:cafe:100::/56, :200::/56, ... */
    for (i = 0; i < subnet->pool.size; i++) {
        ogs_pfcp_ue_ip_t *ue_ip = &subnet->pool.array[i];

        ogs_snprintf(str, sizeof(str), "2001:db8:cafe:%x00::", i + 1);
        ABTS_TRUE(tc, prefix64_equal(tc, ue_ip, str));
        ABTS_TRUE(tc, ue_ip->addr[3] == htobe32(i + 2));
        ABTS_INT_EQUAL(tc, 56, ogs_pfcp_ue_ip_prefixlen(ue_ip));
        ABTS_TRUE(tc, ue_ip->static_ip == false);
    }
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);
}

static void test_pool_default(abts_case *tc, void *data)
{
    int rv, i;
    ogs_pfcp_subnet_t *subnet = NULL;
    char str[OGS_ADDRSTRLEN];

    /* prefix_delegation absent (0): one /64 per entry, as before */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    ABTS_INT_EQUAL(tc, 0, subnet->pd_prefixlen);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);

    for (i = 0; i < subnet->pool.size; i++) {
        ogs_pfcp_ue_ip_t *ue_ip = &subnet->pool.array[i];

        ogs_snprintf(str, sizeof(str), "2001:db8:cafe:%x::", i + 1);
        ABTS_TRUE(tc, prefix64_equal(tc, ue_ip, str));
        ABTS_TRUE(tc, ue_ip->addr[3] == htobe32(i + 2));
        ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_prefixlen(ue_ip));
    }
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);

    /* Explicit "0" also disables */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "0");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, subnet->pd_prefixlen);
    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[0],
                "2001:db8:cafe:1::"));
    ABTS_INT_EQUAL(tc, 64,
            ogs_pfcp_ue_ip_prefixlen(&subnet->pool.array[0]));

    ogs_pfcp_subnet_remove(subnet);
}

static void test_pool_gateway_block(abts_case *tc, void *data)
{
    int rv;
    ogs_pfcp_subnet_t *subnet = NULL;

    /* Gateway in the third /56 block: that block is skipped too */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe:2ff::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);

    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[0],
                "2001:db8:cafe:100::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[1],
                "2001:db8:cafe:300::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[2],
                "2001:db8:cafe:400::"));
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);
}

static void test_pool_range(abts_case *tc, void *data)
{
    int rv;
    ogs_pfcp_subnet_t *subnet = NULL;

    /* low is aligned up to :200::, high down to :400:: (inclusive) */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    subnet->num_of_range = 2;
    subnet->range[0].low = "2001:db8:cafe:180::";
    subnet->range[0].high = "2001:db8:cafe:4ff::";
    subnet->range[1].low = "2001:db8:cafe:a00::";
    subnet->range[1].high = "2001:db8:cafe:b00::";

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 5, subnet->pool.size);

    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[0],
                "2001:db8:cafe:200::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[1],
                "2001:db8:cafe:300::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[2],
                "2001:db8:cafe:400::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[3],
                "2001:db8:cafe:a00::"));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[4],
                "2001:db8:cafe:b00::"));
    ABTS_INT_EQUAL(tc, 56, ogs_pfcp_ue_ip_prefixlen(&subnet->pool.array[4]));
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);

    /* The same range syntax with prefix delegation disabled: /64 units,
     * low and high inclusive, exactly like before */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    subnet->num_of_range = 2;
    subnet->range[0].low = "2001:db8:cafe:a0::";
    subnet->range[0].high = "2001:db8:cafe:a3::";
    subnet->range[1].low = "2001:db8:cafe:c0::";
    subnet->range[1].high = NULL;

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);

    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[0],
                "2001:db8:cafe:a0::"));
    ABTS_TRUE(tc, subnet->pool.array[0].addr[3] == htobe32(1));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[3],
                "2001:db8:cafe:a3::"));
    ABTS_TRUE(tc, subnet->pool.array[3].addr[3] == htobe32(4));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[4],
                "2001:db8:cafe:c0::"));
    ABTS_TRUE(tc, subnet->pool.array[4].addr[3] == htobe32(1));
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[5],
                "2001:db8:cafe:c1::"));
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);
}

static void test_pool_subnet_end(abts_case *tc, void *data)
{
    int rv, i;
    ogs_pfcp_subnet_t *subnet = NULL;
    char str[OGS_ADDRSTRLEN];

    /* /56 subnet with /60 blocks: block 0 (network + gateway) and the
     * last block (holding the subnet's last address) are excluded,
     * leaving 2001:db8:cafe:10::/60 .. 2001:db8:cafe:e0::/60 */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "56",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "60");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 14, subnet->pool.size);

    for (i = 0; i < subnet->pool.size; i++) {
        ogs_snprintf(str, sizeof(str), "2001:db8:cafe:%x0::", i + 1);
        ABTS_TRUE(tc, prefix64_equal(tc, &subnet->pool.array[i], str));
        ABTS_INT_EQUAL(tc, 60,
                ogs_pfcp_ue_ip_prefixlen(&subnet->pool.array[i]));
    }
    check_unique_iid(tc, subnet);

    ogs_pfcp_subnet_remove(subnet);

    /* A subnet that is exactly one block yields nothing */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "56",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, subnet->pool.size);

    ogs_pfcp_subnet_remove(subnet);

    /* A range beyond the subnet yields nothing either */
    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    subnet->num_of_range = 1;
    subnet->range[0].low = "2001:db8:cafe:ff00::";
    subnet->range[0].high = "2001:db8:cafe:ffff::";
    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, subnet->pool.size);

    ogs_pfcp_subnet_remove(subnet);
}

static void test_pool_ipv4_unchanged(abts_case *tc, void *data)
{
    int rv, i;
    ogs_pfcp_subnet_t *subnet = NULL;

    subnet = ogs_pfcp_subnet_add("10.45.0.0", "16", "10.45.0.1",
            NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);
    ABTS_INT_EQUAL(tc, AF_INET, subnet->family);

    /* prefix_delegation is rejected on IPv4 and leaves the subnet alone */
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 0, subnet->pd_prefixlen);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "0");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet->pool.size);

    /* 10.45.0.0 (network) and 10.45.0.1 (gateway) are skipped */
    for (i = 0; i < subnet->pool.size; i++) {
        ogs_pfcp_ue_ip_t *ue_ip = &subnet->pool.array[i];
        ABTS_TRUE(tc, ue_ip->addr[0] == htobe32(0x0a2d0000 + i + 2));
        ABTS_TRUE(tc, ue_ip->addr[1] == 0);
        ABTS_TRUE(tc, ue_ip->addr[3] == 0);
        ABTS_INT_EQUAL(tc, 64, ogs_pfcp_ue_ip_prefixlen(ue_ip));
    }

    ogs_pfcp_subnet_remove(subnet);
}

static void test_set_prefix_delegation(abts_case *tc, void *data)
{
    int rv;
    ogs_pfcp_subnet_t *subnet = NULL;

    subnet = ogs_pfcp_subnet_add("2001:db8:cafe::", "48",
            "2001:db8:cafe::1", NULL, "ogstun");
    ABTS_PTR_NOTNULL(tc, subnet);

    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 56, subnet->pd_prefixlen);

    /* Rejected values do not modify the subnet */
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "64");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "65");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "47");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "-1");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "abc");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "56x");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    ABTS_INT_EQUAL(tc, 56, subnet->pd_prefixlen);

    /* Boundaries */
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "48");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 48, subnet->pd_prefixlen);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "63");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 63, subnet->pd_prefixlen);
    rv = ogs_pfcp_subnet_set_prefix_delegation(subnet, "0");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, subnet->pd_prefixlen);

    ogs_pfcp_subnet_remove(subnet);
}

/* Load a YAML document from a string into ogs_app()->document */
static yaml_document_t *load_yaml(abts_case *tc, const char *text)
{
    yaml_parser_t parser;
    yaml_document_t *document = NULL;

    document = calloc(1, sizeof(yaml_document_t));
    ABTS_PTR_NOTNULL(tc, document);

    ABTS_TRUE(tc, yaml_parser_initialize(&parser));
    yaml_parser_set_input_string(
            &parser, (const unsigned char *)text, strlen(text));
    ABTS_TRUE(tc, yaml_parser_load(&parser, document));
    yaml_parser_delete(&parser);

    ogs_app()->document = document;

    return document;
}

static void unload_yaml(yaml_document_t *document)
{
    ogs_app()->document = NULL;
    yaml_document_delete(document);
    free(document);
    ogs_pfcp_subnet_remove_all();
}

static void test_yaml_prefix_delegation(abts_case *tc, void *data)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_pfcp_subnet_t *subnet4 = NULL, *subnet6 = NULL;

    static const char *valid =
        "smf:\n"
        "  pfcp:\n"
        "    server:\n"
        "      - address: 127.0.0.4\n"
        "  session:\n"
        "    - subnet: 10.45.0.0/16\n"
        "      gateway: 10.45.0.1\n"
        "    - subnet: 2001:db8:cafe::/48\n"
        "      gateway: 2001:db8:cafe::1\n"
        "      prefix_delegation: 56\n";
    static const char *too_short =
        "smf:\n"
        "  pfcp:\n"
        "    server:\n"
        "      - address: 127.0.0.4\n"
        "  session:\n"
        "    - subnet: 2001:db8:cafe::/48\n"
        "      gateway: 2001:db8:cafe::1\n"
        "      prefix_delegation: 40\n";
    static const char *ipv4 =
        "smf:\n"
        "  pfcp:\n"
        "    server:\n"
        "      - address: 127.0.0.4\n"
        "  session:\n"
        "    - subnet: 10.45.0.0/16\n"
        "      gateway: 10.45.0.1\n"
        "      prefix_delegation: 56\n";
    static const char *not_a_number =
        "smf:\n"
        "  pfcp:\n"
        "    server:\n"
        "      - address: 127.0.0.4\n"
        "  session:\n"
        "    - subnet: 2001:db8:cafe::/48\n"
        "      gateway: 2001:db8:cafe::1\n"
        "      prefix_delegation: yes\n";

    ogs_app()->file = "pfcp-ue-ip-test.yaml";

    document = load_yaml(tc, valid);
    rv = ogs_pfcp_context_parse_config("smf", "upf");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->family == AF_INET) subnet4 = subnet;
        if (subnet->family == AF_INET6) subnet6 = subnet;
    }
    ABTS_PTR_NOTNULL(tc, subnet4);
    ABTS_PTR_NOTNULL(tc, subnet6);
    ABTS_INT_EQUAL(tc, 0, subnet4->pd_prefixlen);
    ABTS_INT_EQUAL(tc, 56, subnet6->pd_prefixlen);

    rv = ogs_pfcp_ue_pool_generate();
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, TEST_POOL_SESS, subnet6->pool.size);
    ABTS_TRUE(tc, prefix64_equal(tc, &subnet6->pool.array[0],
                "2001:db8:cafe:100::"));
    ABTS_INT_EQUAL(tc, 56,
            ogs_pfcp_ue_ip_prefixlen(&subnet6->pool.array[0]));
    ABTS_INT_EQUAL(tc, 64,
            ogs_pfcp_ue_ip_prefixlen(&subnet4->pool.array[0]));
    unload_yaml(document);

    document = load_yaml(tc, too_short);
    rv = ogs_pfcp_context_parse_config("smf", "upf");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    unload_yaml(document);

    document = load_yaml(tc, ipv4);
    rv = ogs_pfcp_context_parse_config("smf", "upf");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    unload_yaml(document);

    document = load_yaml(tc, not_a_number);
    rv = ogs_pfcp_context_parse_config("smf", "upf");
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
    unload_yaml(document);

    ogs_app()->file = NULL;
}

abts_suite *test_pfcp_ue_ip(abts_suite *suite)
{
    int id;
    ogs_log_level_e level;

    ogs_app_context_init();
    ogs_app()->pool.nf = 8;
    ogs_app()->pool.sess = TEST_POOL_SESS;
    ogs_pfcp_context_init();

    suite = ADD_SUITE(suite)

    id = ogs_log_get_domain_id("pfcp");
    level = ogs_log_get_domain_level(id);
    ogs_log_set_domain_level(id, OGS_LOG_NONE);

    abts_run_test(suite, test_ue_ip_addr_ipv6_only, NULL);
    abts_run_test(suite, test_ue_ip_addr_ipv4v6, NULL);
    abts_run_test(suite, test_pool_prefix_delegation, NULL);
    abts_run_test(suite, test_pool_default, NULL);
    abts_run_test(suite, test_pool_gateway_block, NULL);
    abts_run_test(suite, test_pool_range, NULL);
    abts_run_test(suite, test_pool_subnet_end, NULL);
    abts_run_test(suite, test_pool_ipv4_unchanged, NULL);
    abts_run_test(suite, test_set_prefix_delegation, NULL);
    abts_run_test(suite, test_yaml_prefix_delegation, NULL);

    ogs_log_set_domain_level(id, level);
    ogs_pfcp_context_final();
    ogs_app_context_final();

    return suite;
}
