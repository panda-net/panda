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

#ifndef __PANDA_PROTO_VLAN_H__
#define __PANDA_PROTO_VLAN_H__

#include "panda/parser.h"

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */

/* VLAN node definitions */

#ifndef __KERNEL__
struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};
#endif

static inline int vlan_proto(const void *vvlan)
{
	return ((struct vlan_hdr *)vvlan)->h_vlan_encapsulated_proto;
}

#endif /* __PANDA_PROTO_VLAN_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_vlan protocol node
 *
 * Parse VLAN header
 *
 * Next protocol operation returns Ethertype (e.g. ETH_P_IPV4)
 */
static const struct panda_proto_node panda_parse_vlan __unused() = {
	.name = "VLAN",
	.min_len = sizeof(struct vlan_hdr),
	.ops.next_proto = vlan_proto,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
