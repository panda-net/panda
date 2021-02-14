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

enum panda_addr_types {
	PANDA_ADDR_TYPE_INVALID = 0, /* Invalid addr type */
	PANDA_ADDR_TYPE_IPV4,
	PANDA_ADDR_TYPE_IPV6,
};

#define	PANDA_METADATA_addr_type	__u8 addr_type
#define PANDA_METADATA_addrs						\
	union {								\
		union {							\
			__be32		v4_addrs[2];			\
			struct {					\
				__be32	saddr;				\
				__be32	daddr;				\
			} v4;						\
		};							\
		union {							\
			struct in6_addr v6_addrs[2];			\
			struct {					\
				struct in6_addr saddr;			\
				struct in6_addr daddr;			\
			} v6;						\
		};							\
	} addrs

#define	PANDA_METADATA_ip_proto	__u8 ip_proto
#define	PANDA_METADATA_is_fragment	__u8 is_fragment: 1
#define	PANDA_METADATA_first_frag	__u8 first_frag: 1

#define PANDA_METADATA_flow_label	__u32 flow_label

#define PANDA_METADATA_ports						\
	union {								\
		__be32 ports;						\
		__be16 port16[2];					\
		struct {						\
			__be16 src_port;				\
			__be16 dst_port;				\
		};							\
		struct {						\
			__be16 sport;					\
			__be16 dport;					\
		} port_pair;						\
	}

#define PANDA_METADATA_tcp_options					\
	struct {							\
		__u16 mss;						\
		__u8 window_scaling;					\
		struct {						\
			__u32 value;					\
			__u32 echo;					\
		} timestamp;						\
		struct {						\
			__u32 left_edge;				\
			__u32 right_edge;				\
		} sack[TCP_MAX_SACKS];					\
	} tcp_options

#define PANDA_METADATA_keyid		__be32  keyid

/* Meta data structure containing all common metadata in canonical field
 * order. eth_proto is declared as the hash start field for the common
 * metadata structure. addrs is last field for canonical hashing.
 */
struct panda_metadata_all {
	PANDA_METADATA_addr_type;
	PANDA_METADATA_is_fragment;
	PANDA_METADATA_first_frag;
	PANDA_METADATA_eth_addrs;
	PANDA_METADATA_tcp_options;

#define PANDA_HASH_START_FIELD_ALL eth_proto
	PANDA_METADATA_eth_proto __aligned(8);
	PANDA_METADATA_ip_proto;
	PANDA_METADATA_flow_label;
	PANDA_METADATA_keyid;
	PANDA_METADATA_ports;

	PANDA_METADATA_addrs; /* Must be last */
};

#define PANDA_HASH_OFFSET_ALL					\
	offsetof(struct panda_metadata_all,			\
		 PANDA_HASH_START_FIELD_ALL)

/* Template for hash consistentify. Sort the source and destination IP (and the
 * ports if the IP address are the same) to have consistent hash within the two
 * directions.
 */
#define PANDA_HASH_CONSISTENTIFY(FRAME) do {				\
	int addr_diff, i;						\
									\
	switch ((FRAME)->addr_type) {					\
	case PANDA_ADDR_TYPE_IPV4:					\
		addr_diff = (FRAME)->addrs.v4_addrs[1] -		\
					(FRAME)->addrs.v4_addrs[0];	\
		if ((addr_diff < 0) ||					\
		    (addr_diff == 0 && ((FRAME)->port16[1] <		\
					(FRAME)->port16[0]))) {		\
			PANDA_SWAP((FRAME)->addrs.v4_addrs[0],		\
				   (FRAME)->addrs.v4_addrs[1]);		\
			PANDA_SWAP((FRAME)->port16[0],			\
				   (FRAME)->port16[1]);			\
		}							\
		break;							\
	case PANDA_ADDR_TYPE_IPV6:					\
		addr_diff = memcmp(&(FRAME)->addrs.v6_addrs[1],		\
				   &(FRAME)->addrs.v6_addrs[0],		\
				   sizeof((FRAME)->addrs.v6_addrs[1]));	\
		if ((addr_diff < 0) ||					\
		    (addr_diff == 0 && ((FRAME)->port16[1] <		\
					(FRAME)->port16[0]))) {		\
			for (i = 0; i < 4; i++)				\
				PANDA_SWAP((FRAME)->addrs.v6_addrs[0].	\
							s6_addr32[i],	\
				     (FRAME)->addrs.v6_addrs[1].	\
							s6_addr32[i]);	\
			PANDA_SWAP((FRAME)->port16[0],			\
				   (FRAME)->port16[1]);			\
		}							\
		break;							\
	}								\
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
	size_t diff = HASH_OFFSET + sizeof((FRAME)->addrs);		\
									\
	switch ((FRAME)->addr_type) {					\
	case PANDA_ADDR_TYPE_IPV4:					\
		diff -= sizeof((FRAME)->addrs.v4_addrs);		\
		break;							\
	case PANDA_ADDR_TYPE_IPV6:					\
		diff -= sizeof((FRAME)->addrs.v6_addrs);		\
		break;							\
	}								\
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

/* Meta data helper for IPv4.
 * Uses common metadata fields: is_fragment, first_frag, ip_proto,
 * addr_type, addrs.v4_addrs
 */
#define PANDA_METADATA_TEMP_ipv4(NAME, STRUCT)				\
static void NAME(const void *viph, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct iphdr *iph = viph;					\
									\
	if (ip_is_fragment(iph)) {					\
		frame->is_fragment = 1;					\
		frame->first_frag =					\
				!(iph->frag_off & htons(IP_OFFSET));	\
	}								\
									\
	frame->addr_type = PANDA_ADDR_TYPE_IPV4;			\
	frame->ip_proto = iph->protocol;				\
	memcpy(frame->addrs.v4_addrs, &iph->saddr,			\
	       sizeof(frame->addrs.v4_addrs));				\
}

/* Meta data helper for IPv4 to only extract IP address.
 * Uses common meta * data fields: ip_proto, addr_type, addrs.v4_addrs
 */
#define PANDA_METADATA_TEMP_ipv4_addrs(NAME, STRUCT)			\
static void NAME(const void *viph, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct iphdr *iph = viph;					\
									\
	frame->addr_type = PANDA_ADDR_TYPE_IPV4;			\
	frame->ip_proto = iph->protocol;				\
	memcpy(frame->addrs.v4_addrs, &iph->saddr,			\
	       sizeof(frame->addrs.v4_addrs));				\
}

/* Meta data helper for IPv6.
 * Uses common metadata fields: ip_proto, addr_type, flow_label, addrs.v6_addrs
 */
#define PANDA_METADATA_TEMP_ipv6(NAME, STRUCT)				\
static void NAME(const void *viph, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct ipv6hdr *iph = viph;				\
									\
	frame->ip_proto = iph->nexthdr;					\
	frame->addr_type = PANDA_ADDR_TYPE_IPV6;			\
	frame->flow_label = ntohl(ip6_flowlabel(iph));			\
	memcpy(frame->addrs.v6_addrs, &iph->saddr,			\
	       sizeof(frame->addrs.v6_addrs));				\
}

/* Meta data helper for IPv6 to only extract IP address.
 * Uses common metadata fields: ip_proto, addr_type, addrs.v6_addrs
 */
#define PANDA_METADATA_TEMP_ipv6_addrs(NAME, STRUCT)			\
static void NAME(const void *viph, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct ipv6hdr *iph = viph;				\
									\
	frame->ip_proto = iph->nexthdr;					\
	frame->addr_type = PANDA_ADDR_TYPE_IPV6;			\
	memcpy(frame->addrs.v6_addrs, &iph->saddr,			\
	       sizeof(frame->addrs.v6_addrs));				\
}

/* Meta data helper for transport ports.
 * Uses common metadata fields: ports
 */
#define PANDA_METADATA_TEMP_ports(NAME, STRUCT)				\
static void NAME(const void *vphdr, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
									\
	frame->ports = ((struct port_hdr *)vphdr)->ports;		\
}

/* Meta data helpers for TCP options */

/* Meta data helper for TCP MSS option
 * Uses common metadata field: tcp_options
 */
#define PANDA_METADATA_TEMP_tcp_option_mss(NAME, STRUCT)		\
static void NAME(const void *vopt, void *iframe)			\
{									\
	const struct tcp_opt_union *opt = vopt;				\
	struct STRUCT *frame = iframe;					\
									\
	frame->tcp_options.mss = ntohs(opt->mss);			\
}

/* Meta data helper for TCP window scaling option
 * Uses common metadata field: tcp_options
 */
#define PANDA_METADATA_TEMP_tcp_option_window_scaling(NAME, STRUCT)	\
static void NAME(const void *vopt, void *iframe)			\
{									\
	const struct tcp_opt_union *opt = vopt;				\
	struct STRUCT *frame = iframe;					\
									\
	frame->tcp_options.window_scaling = opt->window_scaling;	\
}

/* Meta data helper for TCP timestamps option
 * Uses common metadata field: tcp_options
 */
#define PANDA_METADATA_TEMP_tcp_option_timestamp(NAME, STRUCT)		\
static void NAME(const void *vopt, void *iframe)			\
{									\
	const struct tcp_opt_union *opt = vopt;				\
	struct STRUCT *frame = iframe;					\
									\
	frame->tcp_options.timestamp.value =				\
				ntohl(opt->timestamp.value);		\
	frame->tcp_options.timestamp.echo =				\
				ntohl(opt->timestamp.echo);		\
}

/* Meta data helper for TCP sack option
 * Uses common metadata field: tcp_options
 */
#define PANDA_METADATA_TEMP_tcp_option_sack(NAME, STRUCT)		\
static void NAME(const void *vopt, void *iframe)			\
{									\
	const struct tcp_opt_union *opt = vopt;				\
	size_t dlen = opt->opt.len - sizeof(struct tcp_opt);		\
	unsigned int num_sacks = dlen / 8;				\
	struct STRUCT *frame = iframe;					\
	int i;								\
									\
	for (i = 0; i < num_sacks; i++) {				\
		frame->tcp_options.sack[i].left_edge =			\
				ntohl(opt->sack[i].left_edge);		\
		frame->tcp_options.sack[i].right_edge =			\
				ntohl(opt->sack[i].right_edge);		\
	}								\
}

/* Meta data helper for IP overlay (differentiate based on version number).
 * Uses common metadata fields: eth_proto
 */

#define PANDA_METADATA_TEMP_ip_overlay(NAME, STRUCT)			\
static void NAME(const void *viph, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
									\
	switch (((struct ip_hdr_byte *)viph)->version) {		\
	case 4:								\
		frame->eth_proto = __cpu_to_be16(ETH_P_IP);		\
		break;							\
	case 6:								\
		frame->eth_proto = __cpu_to_be16(ETH_P_IPV6);		\
		break;							\
	}								\
}

/* Meta data helper for Routing, DestOpt, and Hop-by-Hop extension headers.
 * Uses common metadata fields: ip_proto
 */
#define PANDA_METADATA_TEMP_ipv6_eh(NAME, STRUCT)			\
static void NAME(const void *vopt, void *iframe)			\
{									\
	((struct STRUCT *)iframe)->ip_proto =				\
			((struct ipv6_opt_hdr *)vopt)->nexthdr;		\
}

/* Meta data helper for Fragmentation extension header.
 * Uses common metadata fields: ip_proto, is_fragment, first_frag
 */
#define PANDA_METADATA_TEMP_ipv6_frag(NAME, STRUCT)			\
static void NAME(const void *vfrag, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct ipv6_frag_hdr *frag = vfrag;			\
									\
	frame->ip_proto = frag->nexthdr;				\
	frame->is_fragment = 1;						\
	frame->first_frag = !(frag->frag_off & htons(IP6_OFFSET));	\
}

/* Meta data helper for Fragmentation extension header without info.
 * Uses common metadata fields: ip_proto
 */
#define PANDA_METADATA_TEMP_ipv6_frag_noinfo(NAME, STRUCT)		\
static void NAME(const void *vfrag, void *iframe)			\
{									\
	((struct STRUCT *)iframe)->ip_proto =				\
			((struct ipv6_frag_hdr *)vfrag)->nexthdr;	\
}

/* Meta data helper for GRE version 0.
 * Uses common metadata fields: keyid
 */
#define PANDA_METADATA_TEMP_gre_v0(NAME, STRUCT)			\
static void NAME(const void *vgre, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct gre_hdr *gre = vgre;				\
									\
	frame->keyid = panda_get_flag_field32(gre->fields,		\
					      GRE_FLAGS_KEY_IDX,	\
					      gre->flags,		\
					      &gre_flag_fields);	\
}

/* Meta data helper for GRE version 1.
 * Uses common metadata fields: keyid
 */
#define PANDA_METADATA_TEMP_gre_v1(NAME, STRUCT)			\
static void NAME(const void *vgre, void *iframe)			\
{									\
	struct STRUCT *frame = iframe;					\
	const struct gre_hdr *gre = vgre;				\
									\
	frame->keyid = panda_get_flag_field32(gre->fields,		\
					      GRE_PPTP_FLAGS_KEY_IDX,	\
					      gre->flags,		\
					      &pptp_gre_flag_fields) &	\
				GRE_PPTP_KEY_MASK;			\
}

#endif /* __PANDA_PARSER_METADATA_H__ */
