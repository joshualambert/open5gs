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

#ifndef SMF_DHCPV6_H
#define SMF_DHCPV6_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DHCPv6 prefix delegation server (RFC 8415, RFC 6603) for the packets the
 * UPF steers to the SMF through the UP2CP PDR. The SMF is the delegating
 * router of TS 23.401 section 5.3.1.2.2 / TS 23.501 section 5.8.2.2.4.
 *
 * SOL_MAX_RT / INF_MAX_RT advertised when the client asks for them
 * (RFC 8415 section 21.24 / 21.25).
 */
#define SMF_DHCPV6_SOL_MAX_RT               3600
#define SMF_DHCPV6_INF_MAX_RT               3600

/* Upper bound of a DHCPv6 reply payload built by the SMF (the reply is
 * dropped when it does not fit). 40 + 8 + this stays below the IPv6
 * minimum MTU of 1280 octets. */
#define SMF_DHCPV6_MAX_MESSAGE_LEN          1024

/*
 * True when `ip6pkt` (an IPv6 packet as received from the UE) is a DHCPv6
 * message worth handling: UDP directly after the IPv6 header, destination
 * port 547, consistent lengths, link-local source and a valid UDP checksum.
 * Malformed DHCPv6 packets are logged and rejected here.
 */
bool smf_dhcpv6_is_request(ogs_pkbuf_t *ip6pkt);

/*
 * Handle one DHCPv6 message from the UE of `sess`. Returns the complete
 * IPv6+UDP reply (allocated with OGS_GTPV1U_5GC_HEADER_LEN of headroom, to
 * be passed to smf_gtp_send_to_ue()) or NULL when nothing is to be sent.
 */
ogs_pkbuf_t *smf_dhcpv6_handle(smf_sess_t *sess, ogs_pkbuf_t *ip6pkt);

/*
 * Prefix handed to the UE of `sess` with DHCPv6-PD (lifetimes not filled):
 * with `pd_exclude` the whole block with the link /64 excluded (RFC 6603),
 * otherwise the half of the block that does not contain the link /64.
 * False when the session has no IPv6 block (prefix delegation disabled).
 */
bool smf_dhcpv6_delegated_prefix(
        smf_sess_t *sess, bool pd_exclude, ogs_dhcpv6_iaprefix_t *prefix);

/* Configured IPv6 DNS servers in binary form. Returns their number. */
int smf_dhcpv6_dns_servers(uint8_t (*addr6)[OGS_IPV6_LEN], int max);

#ifdef __cplusplus
}
#endif

#endif /* SMF_DHCPV6_H */
