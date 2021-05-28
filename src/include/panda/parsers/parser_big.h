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

#ifndef __PANDA_PARSER_BIG_H__
#define __PANDA_PARSER_BIG_H__

/* Big parser definitions
 *
 * Big parser attempts to parse the and retrieve metadata for all of the
 * common PANDA protocol and metadata extractions.
 */

#include <linux/types.h>
#include <unistd.h>

#include "panda/parser_metadata.h"
#ifndef NO_OPTIMIZED_PARSER
#include "parsers/parser_big.p.h"
#endif

/* Meta data structure for multiple frames (i.e. to retrieve metadata
 * for multiple levels of encapsulation)
 */
struct panda_parser_big_metadata {
	struct panda_metadata panda_data;
	struct panda_metadata_all frame[0];
};

/* Meta data structure for just one frame */
struct panda_parser_big_metadata_one {
	struct panda_metadata panda_data;
	struct panda_metadata_all frame;
};

/* Externs for parsers defined by big parsers. Note there are two parser,
 * one to parse a packet containing an Ethernet header, and one containing
 * and IP header.
 */
PANDA_PARSER_EXTERN(panda_parser_big_ether);
PANDA_PARSER_EXTERN(panda_parser_big_ip);

/* Externs for optimized parsers defined by big parsers */
PANDA_PARSER_EXTERN(panda_parser_big_ether_opt);
PANDA_PARSER_EXTERN(panda_parser_big_ip_opt);

void panda_parser_big_print_frame(struct panda_metadata_all *frame);
void panda_parser_big_print_hash_input(struct panda_metadata_all *frame);

#define PANDA_PARSER_BIG_ENCAP_DEPTH	4

/* Utility functions for various ways to parse packets and compute packet
 * hashes using the parsers for big parser
 */

/* Parse packet starting with Ethernet header */
static inline bool panda_parser_big_parse_ether(void *p, size_t len,
				struct panda_parser_big_metadata *mdata)
{
	return (panda_parse(panda_parser_big_ether, p, len, &mdata->panda_data,
			   0, PANDA_PARSER_BIG_ENCAP_DEPTH) == PANDA_STOP_OKAY);
}

/* Parse packet starting with a known layer 3 protocol. Determine start
 * node by performing a protocol look up on the root node of the Ethernet
 * parser (i.e. get the start node by looking up the Ethertype in the
 * Ethernet protocol table)
 */
static inline bool panda_parser_big_parse_l3(void *p, size_t len, __be16 proto,
				struct panda_parser_big_metadata *mdata)
{
	const struct panda_parse_node *start_node =
		panda_parse_lookup_by_proto(
				panda_parser_big_ether->root_node, proto);

	return (start_node && __panda_parse(panda_parser_big_ether,
					    start_node, p, len,
					    &mdata->panda_data, 0,
					    PANDA_PARSER_BIG_ENCAP_DEPTH) ==
						PANDA_STOP_OKAY);
}

/* Parse packet starting with IP header. Root node distinguished based
 * on IP version number
 */
static inline bool panda_parser_big_parse_ip(void *p, size_t len,
				struct panda_parser_big_metadata *mdata)
{
	return (panda_parse(panda_parser_big_ip, p, len, &mdata->panda_data,
			    0, PANDA_PARSER_BIG_ENCAP_DEPTH) ==
						PANDA_STOP_OKAY);
}

/* Produce canonical hash from frame contents */
static inline __u32 panda_parser_big_hash_frame(
				struct panda_metadata_all *frame)
{
	PANDA_HASH_CONSISTENTIFY(frame);

	return PANDA_COMMON_COMPUTE_HASH(frame, PANDA_HASH_START_FIELD_ALL);
}

/* Return hash for packet starting with Ethernet header */
static inline __u32 panda_parser_big_hash_ether(void *p, size_t len)
{
	struct panda_parser_big_metadata_one mdata;

	memset(&mdata, 0, sizeof(mdata));

	if (panda_parser_big_parse_ether(p, len,
			(struct panda_parser_big_metadata *)&mdata))
		return panda_parser_big_hash_frame(&mdata.frame);

	return 0;
}

/* Return hash for a packet starting with the indicated layer 3 protocols
 * (i.e. an EtherType)
 */
static inline __u32 panda_parser_big_hash_l3(void *p, size_t len, __be16 proto)
{
	struct panda_parser_big_metadata_one mdata;

	memset(&mdata, 0, sizeof(mdata));
	mdata.frame.eth_proto = proto;

	if (panda_parser_big_parse_l3(p, len, proto,
			     (struct panda_parser_big_metadata *)&mdata))
		return panda_parser_big_hash_frame(&mdata.frame);

	return 0;
}

/* Return hash for packet starting with in IP header header (IPv4 or
 * IPv6 distinguished by inspecting IP version number
 */
static inline __u32 panda_parser_big_hash_ip(void *p, size_t len)
{
	struct panda_parser_big_metadata_one mdata;

	memset(&mdata, 0, sizeof(mdata));

	if (panda_parser_big_parse_ip(p, len,
			     (struct panda_parser_big_metadata *)&mdata))
		return panda_parser_big_hash_frame(&mdata.frame);

	return 0;
}

#endif /* __PANDA_PARSER_BIG_H__ */
