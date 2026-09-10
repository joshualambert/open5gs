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

#if !defined(OGS_PFCP_INSIDE) && !defined(OGS_PFCP_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_PFCP_CONV_H
#define OGS_PFCP_CONV_H

#ifdef __cplusplus
extern "C" {
#endif

int ogs_pfcp_sockaddr_to_node_id(ogs_pfcp_node_id_t *node_id, int *len);

int ogs_pfcp_f_seid_to_sockaddr(
    ogs_pfcp_f_seid_t *f_seid, uint16_t port, ogs_sockaddr_t **list);
int ogs_pfcp_sockaddr_to_f_seid(ogs_pfcp_f_seid_t *f_seid, int *len);
int ogs_pfcp_f_seid_to_ip(ogs_pfcp_f_seid_t *f_seid, ogs_ip_t *ip);

int ogs_pfcp_sockaddr_to_f_teid(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_pfcp_f_teid_t *f_teid, int *len);
int ogs_pfcp_f_teid_to_sockaddr(
    ogs_pfcp_f_teid_t *f_teid, int f_teid_len,
    ogs_sockaddr_t **addr, ogs_sockaddr_t **addr6);
int ogs_pfcp_f_teid_to_ip(ogs_pfcp_f_teid_t *f_teid, ogs_ip_t *ip);

int ogs_pfcp_user_plane_ip_resource_info_to_f_teid(
    ogs_user_plane_ip_resource_info_t *info,
    ogs_pfcp_f_teid_t *f_teid, int *len);

int ogs_pfcp_paa_to_ue_ip_addr(
    ogs_paa_t *paa, ogs_pfcp_ue_ip_addr_t *addr, int *len);

/*
 * IPv6 prefix delegation (TS 29.244 8.2.62, IPv6D flag)
 *
 * ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen() sets IPv6D and the "IPv6 Prefix
 * Delegation Bits" octet (64 - prefixlen) when prefixlen is 1..63, or clears
 * them when prefixlen is 64. *len is recomputed from the flags, so the call
 * is idempotent. Requires addr->ipv6 == 1; returns OGS_ERROR otherwise or
 * for an out-of-range prefixlen.
 *
 * ogs_pfcp_ue_ip_addr_ipv6_prefixlen() returns 64 when IPv6D is not set,
 * the network prefix length (1..63) when it is, or 0 when the IE is
 * malformed (len too short for the trailing octet, bits outside 1..63).
 */
int ogs_pfcp_ue_ip_addr_set_ipv6_prefixlen(
        ogs_pfcp_ue_ip_addr_t *addr, int *len, uint8_t prefixlen);
uint8_t ogs_pfcp_ue_ip_addr_ipv6_prefixlen(
        const ogs_pfcp_ue_ip_addr_t *addr, int len);

int ogs_pfcp_ip_to_outer_header_creation(ogs_ip_t *ip,
    ogs_pfcp_outer_header_creation_t *outer_header_creation, int *len);
void ogs_pfcp_outer_header_creation_to_ip(
    ogs_pfcp_outer_header_creation_t *outer_header_creation, ogs_ip_t *ip);

#ifdef __cplusplus
}
#endif

#endif
