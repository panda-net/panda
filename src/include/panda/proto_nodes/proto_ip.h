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

#ifndef __PANDA_PROTO_IP_H__
#define __PANDA_PROTO_IP_H__

#include "panda/parser.h"

/* IP overlay node definitions */

#include <asm/byteorder.h>

struct ip_hdr_byte {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    rsvd:4,
		version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8    version:4,
		rsvd:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};

static inline int ip_proto(const void *viph)
{
	return ((struct ip_hdr_byte *)viph)->version;
}

static inline size_t ip_min_len(const void *viph)
{
	return sizeof(struct ip_hdr_byte);
}

#endif /* __PANDA_PROTO_IP_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* parse_ip protocol node
 *
 * Parses first byte of IP header to distinguish IP version (i.e. IPv4
 * and IPv6)
 *
 * Next protocol operation returns IP version number (e.g. 4 for IPv4,
 * 6 for IPv6)
 */
static const struct panda_proto_node panda_parse_ip __unused() = {
	.name = "IP overlay",
	.overlay = 1,
	.min_len = sizeof(struct ip_hdr_byte),
	.ops.next_proto = ip_proto,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
