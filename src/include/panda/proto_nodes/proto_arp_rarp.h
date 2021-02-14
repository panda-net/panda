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

#ifndef __PANDA_PROTO_ARP_RARP_H__
#define __PANDA_PROTO_ARP_RARP_H__

#include <arpa/inet.h>
#include <linux/if_arp.h>

#include "panda/parser.h"

/* ARP and RARP node definitions */

struct earphdr {
	struct arphdr arp;
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_tha[ETH_ALEN];
	__u8 ar_tip[4];
};

static inline ssize_t arp_len_check(const void *vearp)
{
	const struct earphdr *earp = vearp;
	const struct arphdr *arp = &earp->arp;

	if (arp->ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->ar_pro != htons(ETH_P_IP) ||
	    arp->ar_hln != ETH_ALEN ||
	    arp->ar_pln != 4 ||
	    (arp->ar_op != htons(ARPOP_REPLY) &&
	     arp->ar_op != htons(ARPOP_REQUEST)))
		return PANDA_STOP_FAIL;

	return sizeof(struct earphdr);
}

#endif /* __PANDA_PROTO_ARP_RARP_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_arp protocol node
 *
 * Parse ARP header
 */
static struct panda_proto_node panda_parse_arp __unused() = {
	.name = "ARP",
	.min_len = sizeof(struct earphdr),
	.ops.len = arp_len_check,
};

/* panda_parse_rarp protocol node
 *
 * Parse RARP header
 */
static struct panda_proto_node panda_parse_rarp __unused() = {
	.name = "RARP",
	.min_len = sizeof(struct earphdr),
	.ops.len = arp_len_check,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
