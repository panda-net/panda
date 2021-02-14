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

/* Helper definitions for PANDA parser metadata handling
 *
 * This defines a set of macros, constants, and functions that can be
 * optionally used in constructing parse nodes and to assist in meta
 * data handling as well as packet hashing.
 */

#ifndef __PANDA_PARSER_METADATA_H__
#define __PANDA_PARSER_METADATA_H__

#include <linux/if_ether.h>

#include "panda/parser.h"
#include "panda/proto_nodes.h"

/* The PANDA helpers defines a common set of fields that may be used in
 * parser specific metadata structures. This is done at the granularity of
 * field names. When the common names and their types are used in meta
 * data structure then helper marcos can be used to create functions
 * that take the parser specific data structure as an argument but
 * operate on the common fields. In this way we can essentially have
 * the same functions operate on different input structures, in particular
 * we can define per protocol macros that extract common fields into
 * different metadata structures. The type of the structure is an argument
 * to the macro, and then from that a function definition can be ommited that
 * uses the type. Here is an example to extract common metadata for IPv4
 * into a user defined metadata structure.
 *
 * #define PANDA_METADATA_ipv4_addrs(NAME, STRUCT)			\
 * static void NAME(const void *viph, void *iframe)			\
 * {									\
 *	struct STRUCT *frame = iframe;					\
 *	const struct iphdr *iph = viph;					\
 *									\
 *       frame->addr_type = PANDA_ADDR_TYPE_IPV4;			\
 *       frame->ip_proto = iph->protocol;				\
 *       memcpy(frame->addrs.v4_addrs, &iph->saddr,			\
 *              sizeof(frame->addrs.v4_addrs));				\
 * }
 *
 * In this example the common metadata field names used are addr_type,
 * addrs.v4, and ip_proto.
 *
 * #defines for metadata names and their types are below. Note the macros
 * can be used to define the common metadata fields in a data structure,
 * however this is not required. As long as the types and names are
 * maintained differnt definitions may be used. This is particulary relevant
 * when common names are in data structures and the user may wish to add
 * other elements in the structure
 */

/* Common metadata names and macro definitions. Add new common meta
 * data names to this list
 */

#define PANDA_METADATA_eth_proto	__be16	eth_proto
#define PANDA_METADATA_eth_addrs	__u8 eth_addrs[2 * ETH_ALEN]

/* Meta data structure containing all common metadata in canonical field
 * order. eth_proto is declared as the hash start field for the common
 * metadata structure.
 */
struct panda_metadata_all {
	PANDA_METADATA_eth_addrs;

#define PANDA_HASH_START_FIELD_ALL eth_proto
	PANDA_METADATA_eth_proto __aligned(8);
};

#define PANDA_HASH_OFFSET_ALL					\
	offsetof(struct panda_metadata_all,			\
		 PANDA_HASH_START_FIELD_ALL)

/* Template for hash consistentify. Sort the source and destination IP (and the
 * ports if the IP address are the same) to have consistent hash within the two
 * directions.
 */
#define PANDA_HASH_CONSISTENTIFY(FRAME) do {				\
} while (0)

/* Helper to get starting address for hash start. This is just the
 * address of the field name in HASH_START_FIELD of a metadata
 * structure instance (indicated by pointer in FRAME)
 */
#define PANDA_HASH_START(FRAME, HASH_START_FIELD)			\
	(&(FRAME)->HASH_START_FIELD)

/* Helper that returns the hash length for a metadata structure. This
 * returns the end of the address fields for the given type (the
 * address fields are assumed to be the common metadata fields in a nion
 * in the last fields in the metadata structure). The macro returns the
 * offset of the last byte of address minus the offset of the field
 * where the hash starts as indicated by the HASH_OFFSET argument.
 */
#define PANDA_HASH_LENGTH(FRAME, HASH_OFFSET) ({			\
	size_t diff = HASH_OFFSET;					\
									\
	sizeof(*(FRAME)) - diff;					\
})

/* Helpers to extract common metadata */

/* Meta data helper for Ethernet.
 * Uses common metadata fields: eth_proto, eth_addrs
 */
#define PANDA_METADATA_TEMP_ether(NAME, STRUCT)				\
static void NAME(const void *veth, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
									\
	frame->eth_proto = ((struct ethhdr *)veth)->h_proto;		\
	memcpy(frame->eth_addrs, &((struct ethhdr *)veth)->h_dest,	\
	       sizeof(frame->eth_addrs));				\
}

/* Meta data helper for Ethernet without extracting addresses.
 * Uses common metadata fields: eth_proto
 */
#define PANDA_METADATA_TEMP_ether_noaddrs(NAME, STRUCT)			\
static void NAME(const void *veth, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
									\
	frame->eth_proto = ((struct ethhdr *)veth)->h_proto;		\
}

#endif /* __PANDA_PARSER_METADATA_H__ */
