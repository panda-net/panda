/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __PANDA_PROTO_IPV6_H__
#define __PANDA_PROTO_IPV6_H__

/* IPv6 node definitions */

#ifndef __KERNEL__
#include <arpa/inet.h>
#endif

#include <linux/ipv6.h>

#include "panda/parser.h"

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)

#define IPV6_FLOWLABEL_MASK	htonl(0x000FFFFF)

static inline __be32 ip6_flowlabel(const struct ipv6hdr *hdr)
{
	return *(__be32 *)hdr & IPV6_FLOWLABEL_MASK;
}

static inline int ipv6_proto(const void *viph)
{
	return ((struct ipv6hdr *)viph)->nexthdr;
}

static inline int ipv6_proto_stopflowlabel(const void *viph)
{
	const struct ipv6hdr *iph = viph;

	if (ip6_flowlabel(iph)) {
		/* Don't continue if flowlabel is non-zero */
		return PANDA_STOP_OKAY;
	}

	return iph->nexthdr;
}

static inline ssize_t ipv6_length_check(const void *viph)
{
	const struct ipv6hdr *iph = viph;

	if (iph->version != 6)
		return PANDA_STOP_UNKNOWN_PROTO;

	return sizeof(struct ipv6hdr);
}

#endif /* __PANDA_PROTO_IPV6_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_ipv6 protocol node
 *
 * Parse IPv6 header
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node panda_parse_ipv6 __unused() = {
	.name = "IPv6",
	.min_len = sizeof(struct ipv6hdr),
	.ops.next_proto = ipv6_proto,
};

/* parse_ipv6_stopflowlabel protocol node
 *
 * Parse IPv6 header and stop at a non-zero flow label
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node
				panda_parse_ipv6_stopflowlabel __unused() = {
	.name = "IPv6 stop at non-zero flow label",
	.min_len = sizeof(struct ipv6hdr),
	.ops.next_proto = ipv6_proto_stopflowlabel,
};


/* panda_parse_ipv6_check protocol node
 *
 * Check version is six and parse IPv6 header
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node panda_parse_ipv6_check __unused() = {
	.name = "IPv6",
	.min_len = sizeof(struct ipv6hdr),
	.ops.len = ipv6_length_check,
	.ops.next_proto = ipv6_proto,
};

/* parse_ipv6_stopflowlabel_check protocol node
 *
 * Check version is six, parse IPv6 header, and stop at a non-zero flow label
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node
				panda_parse_ipv6_stopflowlabel_check
							__unused() = {
	.name = "IPv6 stop at non-zero flow label",
	.min_len = sizeof(struct ipv6hdr),
	.ops.len = ipv6_length_check,
	.ops.next_proto = ipv6_proto_stopflowlabel,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
