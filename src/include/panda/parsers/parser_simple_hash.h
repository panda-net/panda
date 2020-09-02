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

#ifndef __PANDA_PARSER_HASH_H__
#define __PANDA_PARSER_HASH_H__

/* Hash parser definitions
 *
 * Hash parser parses to extract port information from an IPv4 or IPv6
 * packet in a plane Ethernet frame. Encapsulation is not supported in
 * this parser.
 */
#include <linux/types.h>
#include <unistd.h>

#include "panda/parser_metadata.h"
#include "panda/utility.h"

/* Meta data structure for multiple frames (i.e. to retrieve metadata
 * for multiple levels of encapsulation)
 */
#define PANDA_SIMPLE_HASH_START_FIELD_HASH eth_proto
struct panda_parser_simple_hash_metadata {
	struct panda_metadata panda_data;

	PANDA_METADATA_addr_type;

	PANDA_METADATA_eth_proto __aligned(8);
	PANDA_METADATA_ip_proto;
	PANDA_METADATA_flow_label;
	PANDA_METADATA_ports;

	PANDA_METADATA_addrs; /* Must be last */
};

#define PANDA_SIMPLE_HASH_OFFSET_HASH				\
	offsetof(struct panda_parser_simple_hash_metadata,	\
		 PANDA_SIMPLE_HASH_START_FIELD_HASH)

/* Externs for simple hash parser */
PANDA_PARSER_EXTERN(panda_parser_simple_hash_ether);

/* Function to get hash from Ethernet packet */
static inline __u32 panda_parser_hash_hash_ether(const void *p, size_t len)
{
	struct panda_parser_simple_hash_metadata mdata;

	if (panda_parse(panda_parser_simple_hash_ether, p, len,
			&mdata.panda_data, 0, 0) != PANDA_STOP_OKAY)
		return 0;

	PANDA_HASH_CONSISTENTIFY(&mdata);

	return PANDA_COMMON_COMPUTE_HASH(&mdata,
					 PANDA_SIMPLE_HASH_START_FIELD_HASH);
}

#endif /* __PANDA_PARSER_HASH_H__ */
