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

#ifndef __PROTO_IPV4_H__
#define __PROTO_IPV4_H__

/* IPv4 node definitions */

#include <arpa/inet.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <string.h>

#include "panda/parser.h"

#define IP_MF		0x2000	/* Flag: "More Fragments"   */
#define IP_OFFSET	0x1FFF	/* "Fragment Offset" part   */

static inline size_t ipv4_len(const void *viph)
{
	return ((struct iphdr *)viph)->ihl * 4;
}

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static inline int ipv4_proto(const void *viph)
{
	const struct iphdr *iph = viph;

	if (ip_is_fragment(iph) && (iph->frag_off & htons(IP_OFFSET))) {
		/* Stop at a non-first fragment */
		return PANDA_STOP_OKAY;
	}

	return iph->protocol;
}

static inline int ipv4_proto_stop1stfrag(const void *viph)
{
	const struct iphdr *iph = viph;

	if (ip_is_fragment(iph)) {
		/* Stop at all fragments */
		return PANDA_STOP_OKAY;
	}

	return iph->protocol;
}

static inline ssize_t ipv4_length(const void *viph)
{
	return ipv4_len(viph);
}

#endif /* __PROTO_IPV4_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_ipv4 protocol node
 *
 * Parse IPv4 header
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static struct panda_proto_node panda_parse_ipv4 __unused() = {
	.name = "IPv4",
	.min_len = sizeof(struct iphdr),
	.ops.len = ipv4_length,
	.ops.next_proto = ipv4_proto,
};

/* panda_parse_ipv4_stop1stfrag protocol node
 *
 * Parse IPv4 header but don't parse into first fragment
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static struct panda_proto_node panda_parse_ipv4_stop1stfrag __unused() = {
	.name = "IPv4 without parsing 1st fragment",
	.min_len = sizeof(struct iphdr),
	.ops.len = ipv4_length,
	.ops.next_proto = ipv4_proto_stop1stfrag,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
