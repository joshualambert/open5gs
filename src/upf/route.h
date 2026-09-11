/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef UPF_ROUTE_H
#define UPF_ROUTE_H

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-session kernel routes (docs/ipv6-prefix-delegation/DESIGN.md 5.5).
 *
 * A `static: true` subnet has no address on its tun device that covers the
 * subscriber blocks, and framed routes are only known to the UPF trie, so
 * the kernel would never hand such downlink traffic to the tun. The UPF
 * therefore installs a unicast route for each of them in the main table
 * while the session exists and removes it with the session.
 *
 * All routes are tagged with rtm_protocol UPF_ROUTE_PROTO so they can be
 * told apart from operator routes (`ip -6 route show proto 250`) and are
 * flushed at start-up when a previous instance did not clean up.
 *
 * On non-Linux platforms the functions are stubs that log once and return
 * OGS_OK, so a session is never affected.
 */
#define UPF_ROUTE_PROTO 250

int upf_route_init(void);
void upf_route_final(void);

/*
 * prefix points to 4 (AF_INET) or 16 (AF_INET6) bytes in network order;
 * bits beyond prefixlen are ignored. ifname is the output interface
 * (the subnet's `dev`). Both functions block until the kernel has
 * acknowledged the request. upf_route_add() treats EEXIST as success,
 * upf_route_del() treats ESRCH as success.
 */
int upf_route_add(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname);
int upf_route_del(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname);

#ifdef __cplusplus
}
#endif

#endif /* UPF_ROUTE_H */
