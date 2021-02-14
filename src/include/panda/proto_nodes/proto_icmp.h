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

#ifndef __PANDA_PROTO_ICMP_H__
#define __PANDA_PROTO_ICMP_H__

/* Generic ICMP node definitions */

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "panda/parser.h"

static inline bool icmp_has_id(__u8 type)
{
	switch (type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMPV6_ECHO_REQUEST:
	case ICMPV6_ECHO_REPLY:
		return true;
	}

	return false;
}

#endif /* __PANDA_PROTO_ICMP_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_icmpv4 protocol node
 *
 * Parse ICMPv4 header
 */
static struct panda_proto_node panda_parse_icmpv4 __unused() = {
	.name = "ICMPv4",
	.min_len = sizeof(struct icmphdr),
};

/* panda_parse_icmpv6 protocol node
 *
 * Parse ICMPv6 header
 */
static struct panda_proto_node panda_parse_icmpv6 __unused() = {
	.name = "ICMPv6",
	.min_len = sizeof(struct icmp6hdr),
};

#endif /* PANDA_DEFINE_PARSE_NODE */
