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

#if !defined(OGS_GTP_INSIDE) && !defined(OGS_GTP_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_GTP_UTIL_H
#define OGS_GTP_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

int ogs_gtpu_parse_header(
        ogs_gtp2_header_desc_t *header_desc, ogs_pkbuf_t *pkbuf);
uint16_t ogs_in_cksum(uint16_t *addr, int len);

/*
 * RFC 8200 section 8.1 upper-layer checksum: the IPv6 pseudo-header
 * (src, dst, 32-bit upper-layer length, 3 zero octets, next header) is
 * folded together with `payload` (the UDP/ICMPv6 header plus data) without
 * copying it. The result is the one's complement in network byte order,
 * ready to be stored directly into udph->uh_sum / icmp6_cksum. For UDP a
 * computed value of 0 must be transmitted as 0xffff (RFC 8200 section 8.1);
 * this is left to the caller.
 */
uint16_t ogs_in6_cksum(const uint8_t *src, const uint8_t *dst, uint8_t nxt,
        const void *payload, size_t len);

typedef struct ogs_gtp2_sender_f_teid_s {
    bool teid_presence;
    uint32_t teid;
} ogs_gtp2_sender_f_teid_t;

void ogs_gtp2_sender_f_teid(
        ogs_gtp2_sender_f_teid_t *sender_f_teid, ogs_gtp2_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* OGS_GTP_UTIL_H */
