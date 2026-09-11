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

#include "context.h"
#include "route.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#if HAVE_LINUX_RTNETLINK_H

#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*
 * Linux rtnetlink implementation (no libnl).
 *
 * Every request is one datagram:
 *
 *   struct nlmsghdr   nlmsg_type  = RTM_NEWROUTE | RTM_DELROUTE | RTM_GETROUTE
 *                     nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK
 *                                   [| NLM_F_CREATE | NLM_F_REPLACE]  (add)
 *                                   [| NLM_F_DUMP]                    (get)
 *   struct rtmsg      rtm_family   = AF_INET | AF_INET6
 *                     rtm_dst_len  = prefixlen
 *                     rtm_table    = RT_TABLE_MAIN
 *                     rtm_protocol = UPF_ROUTE_PROTO (250)
 *                     rtm_scope    = RT_SCOPE_LINK (v4) | RT_SCOPE_UNIVERSE (v6)
 *                                    RT_SCOPE_NOWHERE on delete (match any)
 *                     rtm_type     = RTN_UNICAST
 *   struct rtattr     RTA_DST (4 or 16 bytes, masked to prefixlen)
 *   struct rtattr     RTA_OIF (int ifindex)
 *
 * and the reply is a NLMSG_ERROR with error == 0 (ACK) or -errno. The
 * kernel also uses rtm_protocol and RTA_OIF as *filters* on RTM_DELROUTE,
 * so a delete from here can never remove a route that is not ours.
 *
 * The socket is only used from the UPF main thread (initialisation and
 * PFCP session handling); the data plane never touches it.
 */

#define UPF_ROUTE_NL_BUFLEN     (64 * 1024)
#define UPF_ROUTE_NL_TIMEOUT    2   /* seconds, upper bound for one ACK */

typedef struct upf_route_req_s {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[256];
} upf_route_req_t;

static int nl_fd = -1;
static uint32_t nl_seq = 0;
static char *nl_buf = NULL;

static int nl_addattr(struct nlmsghdr *n, size_t maxlen, int type,
        const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    struct rtattr *rta = NULL;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        ogs_error("netlink attribute %d does not fit", type);
        return OGS_ERROR;
    }

    rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return OGS_OK;
}

static int nl_send(struct nlmsghdr *n)
{
    struct sockaddr_nl kernel;
    ssize_t rc;

    ogs_assert(nl_fd >= 0);

    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    n->nlmsg_seq = ++nl_seq;
    n->nlmsg_pid = 0;

    rc = sendto(nl_fd, n, n->nlmsg_len, 0,
            (struct sockaddr *)&kernel, sizeof(kernel));
    if (rc < 0 || (size_t)rc != n->nlmsg_len) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "netlink sendto() failed");
        return OGS_ERROR;
    }

    return OGS_OK;
}

/* One recvmsg() into nl_buf. Returns the byte count or -1. */
static ssize_t nl_recv(void)
{
    struct sockaddr_nl from;
    struct iovec iov;
    struct msghdr msg;
    ssize_t len;

    ogs_assert(nl_fd >= 0);
    ogs_assert(nl_buf);

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = nl_buf;
    iov.iov_len = UPF_ROUTE_NL_BUFLEN;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    len = recvmsg(nl_fd, &msg, 0);
    if (len < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "netlink recvmsg() failed");
        return -1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        ogs_error("netlink message truncated (%zd bytes)", len);
        return -1;
    }
    if (msg.msg_namelen != sizeof(from) || from.nl_pid != 0) {
        /* Not from the kernel, ignore */
        return 0;
    }

    return len;
}

/*
 * Waits for the acknowledgement of the request with sequence number seq.
 * Returns 0 on success or the positive errno reported by the kernel;
 * -1 when no answer could be read.
 */
static int nl_wait_ack(uint32_t seq)
{
    for (;;) {
        ssize_t len = nl_recv();
        struct nlmsghdr *h = NULL;

        if (len < 0)
            return -1;

        for (h = (struct nlmsghdr *)nl_buf; NLMSG_OK(h, (size_t)len);
                h = NLMSG_NEXT(h, len)) {
            struct nlmsgerr *err = NULL;

            if (h->nlmsg_seq != seq)
                continue;

            if (h->nlmsg_type != NLMSG_ERROR) {
                /* Unexpected payload on a request that only wants an ACK */
                continue;
            }

            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
                ogs_error("netlink: short NLMSG_ERROR");
                return -1;
            }

            err = (struct nlmsgerr *)NLMSG_DATA(h);
            return -err->error;
        }
    }
}

static void nl_mask_prefix(uint8_t *dst, const uint8_t *src,
        size_t addrlen, uint8_t prefixlen)
{
    size_t i;

    for (i = 0; i < addrlen; i++) {
        if (prefixlen >= 8) {
            dst[i] = src[i];
            prefixlen -= 8;
        } else if (prefixlen > 0) {
            dst[i] = src[i] & (uint8_t)(0xff << (8 - prefixlen));
            prefixlen = 0;
        } else {
            dst[i] = 0;
        }
    }
}

static const char *nl_prefix_str(int family, const uint8_t *prefix,
        uint8_t prefixlen, char *buf, size_t buflen)
{
    char addr[OGS_ADDRSTRLEN];

    if (!inet_ntop(family, prefix, addr, sizeof(addr)))
        ogs_cpystrn(addr, "?", sizeof(addr));
    ogs_snprintf(buf, buflen, "%s/%d", addr, prefixlen);

    return buf;
}

/*
 * Sends RTM_NEWROUTE or RTM_DELROUTE for prefix/prefixlen via ifindex
 * (0 = any) in table `table` and waits for the ACK. Returns 0 or errno.
 */
static int nl_route_request(uint16_t type, int family,
        const uint8_t *prefix, uint8_t prefixlen,
        int ifindex, uint8_t table)
{
    upf_route_req_t req;
    uint8_t dst[OGS_IPV6_LEN];
    size_t addrlen;
    int rv;

    ogs_assert(type == RTM_NEWROUTE || type == RTM_DELROUTE);
    ogs_assert(family == AF_INET || family == AF_INET6);
    ogs_assert(prefix);

    addrlen = family == AF_INET ? OGS_IPV4_LEN : OGS_IPV6_LEN;
    if (prefixlen > addrlen * 8) {
        ogs_error("Invalid prefix length %d for family %d",
                prefixlen, family);
        return EINVAL;
    }

    nl_mask_prefix(dst, prefix, addrlen, prefixlen);

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.n.nlmsg_type = type;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (type == RTM_NEWROUTE)
        req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

    req.r.rtm_family = family;
    req.r.rtm_dst_len = prefixlen;
    req.r.rtm_table = table;
    req.r.rtm_protocol = UPF_ROUTE_PROTO;
    req.r.rtm_type = RTN_UNICAST;
    if (type == RTM_NEWROUTE)
        req.r.rtm_scope = family == AF_INET ?
            RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
    else
        req.r.rtm_scope = RT_SCOPE_NOWHERE;

    rv = nl_addattr(&req.n, sizeof(req), RTA_DST, dst, addrlen);
    if (rv != OGS_OK)
        return EINVAL;
    if (ifindex) {
        rv = nl_addattr(&req.n, sizeof(req), RTA_OIF,
                &ifindex, sizeof(ifindex));
        if (rv != OGS_OK)
            return EINVAL;
    }

    if (nl_send(&req.n) != OGS_OK)
        return EIO;

    rv = nl_wait_ack(req.n.nlmsg_seq);
    if (rv < 0)
        return EIO;

    return rv;
}

typedef struct upf_route_stale_s {
    int family;
    uint8_t prefix[OGS_IPV6_LEN];
    uint8_t prefixlen;
    int ifindex;
    uint8_t table;
} upf_route_stale_t;

/*
 * Dumps the routes of one family and collects those tagged with
 * UPF_ROUTE_PROTO into *stale (grown with ogs_realloc). The deletes are
 * sent after the dump has completed so the two exchanges do not interleave
 * on the socket. Returns OGS_OK / OGS_ERROR.
 */
static int nl_collect_stale(int family,
        upf_route_stale_t **stale, int *num_of_stale)
{
    upf_route_req_t req;
    bool done = false;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.n.nlmsg_type = RTM_GETROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.r.rtm_family = family;
    req.r.rtm_table = RT_TABLE_MAIN;

    if (nl_send(&req.n) != OGS_OK)
        return OGS_ERROR;

    while (!done) {
        ssize_t len = nl_recv();
        struct nlmsghdr *h = NULL;

        if (len < 0)
            return OGS_ERROR;

        for (h = (struct nlmsghdr *)nl_buf; NLMSG_OK(h, (size_t)len);
                h = NLMSG_NEXT(h, len)) {
            struct rtmsg *r = NULL;
            struct rtattr *rta = NULL;
            size_t rtalen;
            upf_route_stale_t entry;
            bool have_dst = false;

            if (h->nlmsg_seq != req.n.nlmsg_seq)
                continue;

            if (h->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
                ogs_error("RTM_GETROUTE(family:%d) failed: %s",
                        family, strerror(-err->error));
                return OGS_ERROR;
            }
            if (h->nlmsg_type != RTM_NEWROUTE)
                continue;
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*r)))
                continue;

            r = (struct rtmsg *)NLMSG_DATA(h);
            if (r->rtm_family != family)
                continue;
            if (r->rtm_protocol != UPF_ROUTE_PROTO)
                continue;

            memset(&entry, 0, sizeof(entry));
            entry.family = family;
            entry.prefixlen = r->rtm_dst_len;
            entry.table = r->rtm_table;

            rta = RTM_RTA(r);
            rtalen = RTM_PAYLOAD(h);
            for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
                switch (rta->rta_type) {
                case RTA_DST:
                    if (RTA_PAYLOAD(rta) <= sizeof(entry.prefix)) {
                        memcpy(entry.prefix, RTA_DATA(rta),
                                RTA_PAYLOAD(rta));
                        have_dst = true;
                    }
                    break;
                case RTA_OIF:
                    if (RTA_PAYLOAD(rta) >= sizeof(int))
                        memcpy(&entry.ifindex, RTA_DATA(rta), sizeof(int));
                    break;
                case RTA_TABLE:
                    if (RTA_PAYLOAD(rta) >= sizeof(uint32_t)) {
                        uint32_t t;
                        memcpy(&t, RTA_DATA(rta), sizeof(t));
                        if (t <= 0xff)
                            entry.table = t;
                    }
                    break;
                default:
                    break;
                }
            }

            /* A default route has no RTA_DST; our routes always have one */
            if (!have_dst && entry.prefixlen != 0)
                continue;

            *stale = ogs_realloc(*stale,
                    sizeof(**stale) * (*num_of_stale + 1));
            ogs_assert(*stale);
            (*stale)[*num_of_stale] = entry;
            (*num_of_stale)++;
        }
    }

    return OGS_OK;
}

int upf_route_init(void)
{
    struct sockaddr_nl local;
    struct timeval tv;
    upf_route_stale_t *stale = NULL;
    int num_of_stale = 0;
    int flushed = 0;
    int i;

    ogs_assert(nl_fd < 0);

    nl_buf = ogs_malloc(UPF_ROUTE_NL_BUFLEN);
    ogs_assert(nl_buf);

    nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl_fd < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "socket(AF_NETLINK, NETLINK_ROUTE) failed");
        goto error;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(nl_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "bind(AF_NETLINK) failed");
        goto error;
    }

    /* Never let a lost ACK block the control plane for good */
    tv.tv_sec = UPF_ROUTE_NL_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                "setsockopt(SO_RCVTIMEO) failed");

    /*
     * Remove what a previous instance left behind. Anything with
     * rtm_protocol == UPF_ROUTE_PROTO belongs to a session that no longer
     * exists (the UPF holds no session state across restarts).
     */
    if (nl_collect_stale(AF_INET6, &stale, &num_of_stale) != OGS_OK ||
        nl_collect_stale(AF_INET, &stale, &num_of_stale) != OGS_OK) {
        ogs_error("Cannot dump the kernel routing table; "
                "stale per-session routes (proto %d) are not flushed",
                UPF_ROUTE_PROTO);
    }

    for (i = 0; i < num_of_stale; i++) {
        char buf[OGS_ADDRSTRLEN + 8];
        int rv = nl_route_request(RTM_DELROUTE, stale[i].family,
                stale[i].prefix, stale[i].prefixlen,
                stale[i].ifindex, stale[i].table);
        if (rv == 0 || rv == ESRCH) {
            flushed++;
            ogs_debug("Flushed stale route %s (proto %d)",
                    nl_prefix_str(stale[i].family, stale[i].prefix,
                        stale[i].prefixlen, buf, sizeof(buf)),
                    UPF_ROUTE_PROTO);
        } else {
            ogs_error("Cannot flush stale route %s (proto %d): %s",
                    nl_prefix_str(stale[i].family, stale[i].prefix,
                        stale[i].prefixlen, buf, sizeof(buf)),
                    UPF_ROUTE_PROTO, strerror(rv));
        }
    }

    if (stale)
        ogs_free(stale);

    ogs_info("Per-session kernel routes: %d stale route%s (proto %d) flushed",
            flushed, flushed == 1 ? "" : "s", UPF_ROUTE_PROTO);

    return OGS_OK;

error:
    if (nl_fd >= 0) {
        close(nl_fd);
        nl_fd = -1;
    }
    ogs_free(nl_buf);
    nl_buf = NULL;
    return OGS_ERROR;
}

void upf_route_final(void)
{
    if (nl_fd >= 0) {
        close(nl_fd);
        nl_fd = -1;
    }
    if (nl_buf) {
        ogs_free(nl_buf);
        nl_buf = NULL;
    }
}

static int upf_route_change(uint16_t type, int family,
        const uint8_t *addr, uint8_t prefixlen, const char *ifname)
{
    char buf[OGS_ADDRSTRLEN + 8];
    uint8_t prefix[OGS_IPV6_LEN];
    unsigned int ifindex;
    int rv;

    ogs_assert(addr);
    ogs_assert(ifname);
    ogs_assert(family == AF_INET || family == AF_INET6);

    /* Log and send the masked prefix, whatever the caller handed in */
    memset(prefix, 0, sizeof(prefix));
    if (prefixlen <= (family == AF_INET ? OGS_IPV4_LEN : OGS_IPV6_LEN) * 8)
        nl_mask_prefix(prefix, addr,
                family == AF_INET ? OGS_IPV4_LEN : OGS_IPV6_LEN, prefixlen);

    if (nl_fd < 0) {
        ogs_error("Kernel route %s %s dev %s: netlink socket is not open",
                type == RTM_NEWROUTE ? "add" : "del",
                nl_prefix_str(family, prefix, prefixlen, buf, sizeof(buf)),
                ifname);
        return OGS_ERROR;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "Kernel route %s %s: if_nametoindex(%s) failed",
                type == RTM_NEWROUTE ? "add" : "del",
                nl_prefix_str(family, prefix, prefixlen, buf, sizeof(buf)),
                ifname);
        return OGS_ERROR;
    }

    rv = nl_route_request(type, family, prefix, prefixlen,
            (int)ifindex, RT_TABLE_MAIN);

    if (rv == 0 ||
        (type == RTM_NEWROUTE && rv == EEXIST) ||
        (type == RTM_DELROUTE && rv == ESRCH)) {
        ogs_debug("Kernel route %s %s dev %s proto %d%s",
                type == RTM_NEWROUTE ? "add" : "del",
                nl_prefix_str(family, prefix, prefixlen, buf, sizeof(buf)),
                ifname, UPF_ROUTE_PROTO,
                rv ? " (already in that state)" : "");
        return OGS_OK;
    }

    ogs_error("Kernel route %s %s dev %s proto %d failed: %s",
            type == RTM_NEWROUTE ? "add" : "del",
            nl_prefix_str(family, prefix, prefixlen, buf, sizeof(buf)),
            ifname, UPF_ROUTE_PROTO, strerror(rv));

    return OGS_ERROR;
}

int upf_route_add(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname)
{
    return upf_route_change(RTM_NEWROUTE, family, prefix, prefixlen, ifname);
}

int upf_route_del(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname)
{
    return upf_route_change(RTM_DELROUTE, family, prefix, prefixlen, ifname);
}

#else /* !HAVE_LINUX_RTNETLINK_H */

static void upf_route_unsupported(void)
{
    static bool logged = false;

    if (logged)
        return;
    logged = true;
    ogs_warn("Per-session kernel routes are not supported on this platform; "
            "add routes for static subnets and framed routes by hand");
}

int upf_route_init(void)
{
    upf_route_unsupported();
    return OGS_OK;
}

void upf_route_final(void)
{
}

int upf_route_add(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname)
{
    upf_route_unsupported();
    return OGS_OK;
}

int upf_route_del(int family, const uint8_t *prefix, uint8_t prefixlen,
        const char *ifname)
{
    upf_route_unsupported();
    return OGS_OK;
}

#endif /* HAVE_LINUX_RTNETLINK_H */
