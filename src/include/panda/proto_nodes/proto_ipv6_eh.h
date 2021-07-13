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

#ifndef __PANDA_PROTO_IPV6_EH_H__
#define __PANDA_PROTO_IPV6_EH_H__

/* Generic definitions for IPv6 extension headers */

#ifndef __KERNEL__
#include <arpa/inet.h>
#endif

#include <linux/ipv6.h>

#include "panda/parser.h"

struct ipv6_frag_hdr {
	__u8    nexthdr;
	__u8    reserved;
	__be16  frag_off;
	__be32  identification;
};

#define IP6_MF		0x0001
#define IP6_OFFSET	0xFFF8

static inline int ipv6_eh_proto(const void *vopt)
{
	return ((struct ipv6_opt_hdr *)vopt)->nexthdr;
}

static inline ssize_t ipv6_eh_len(const void *vopt)
{
	return ipv6_optlen((struct ipv6_opt_hdr *)vopt);
}

static inline int ipv6_frag_proto(const void *vfraghdr)
{
	const struct ipv6_frag_hdr *fraghdr = vfraghdr;

	if (fraghdr->frag_off & htons(IP6_OFFSET)) {
		/* Stop at non-first fragment */
		return PANDA_STOP_OKAY;
	}

	return fraghdr->nexthdr;
}

#endif /* __PANDA_PROTO_IPV6_EH_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

static const struct panda_proto_node panda_parse_ipv6_eh __unused() = {
	.name = "IPv6 EH",
	.min_len = sizeof(struct ipv6_opt_hdr),
	.ops.next_proto = ipv6_eh_proto,
	.ops.len = ipv6_eh_len,
};

/* panda_parse_ipv6_eh protocol node
 *
 * Parse IPv6 extension header (Destinaion Options, Hop-by-Hop Options,
 * or Routing Header
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node panda_parse_ipv6_frag_eh __unused() = {
	.name = "IPv6 EH",
	.min_len = sizeof(struct ipv6_frag_hdr),
	.ops.next_proto = ipv6_frag_proto,
};

/* panda_parse_ipv6_frag_eh protocol node
 *
 * Parse IPv6 fragmentation header, stop parsing at first fragment
 *
 * Next protocol operation returns IP proto number (e.g. IPPROTO_TCP)
 */
static const struct panda_proto_node panda_parse_ipv6_frag_eh_stop1stfrag
							__unused() = {
	.name = "IPv6 EH",
	.min_len = sizeof(struct ipv6_frag_hdr),
};

#endif /* PANDA_DEFINE_PARSE_NODE */
