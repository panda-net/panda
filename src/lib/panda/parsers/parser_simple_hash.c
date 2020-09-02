// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 SiPanda Inc.
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

/* PANDA Simple Hash Parser
 *
 * Implement a parser to get canonical 4-tuple hash from an Ethernet packet.
 * This does not support encapsulation.
 */

#include <arpa/inet.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "panda/parsers/parser_simple_hash.h"

/* Define protocol nodes that are used below */
#include "panda/proto_nodes_def.h"

/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */

PANDA_METADATA_TEMP_ether_noaddrs(ether_metadata,
				   panda_parser_simple_hash_metadata)
PANDA_METADATA_TEMP_ipv4_addrs(ipv4_metadata,
				panda_parser_simple_hash_metadata)
PANDA_METADATA_TEMP_ipv6(ipv6_metadata, panda_parser_simple_hash_metadata)
PANDA_METADATA_TEMP_ports(ports_metadata, panda_parser_simple_hash_metadata)


/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */

PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata, NULL,
		      ether_table);
PANDA_MAKE_PARSE_NODE(ipv4_check_node, panda_parse_ip,
		      panda_null_extract_metadata,
		      panda_null_handle_proto, ipv4_check_table);
PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata, NULL,
		      ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv6_check_node, panda_parse_ip,
		      panda_null_extract_metadata,
		      panda_null_handle_proto, ipv6_check_table);
PANDA_MAKE_PARSE_NODE(ipv6_node, panda_parse_ipv6_stopflowlabel,
		      ipv6_metadata, NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_eh_node, panda_parse_ipv6_eh, NULL, NULL,
		      ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_frag_node, panda_parse_ipv6_frag_eh, NULL, NULL,
		      ipv6_table);

PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata,
			   NULL);

/* Define hash parser to begin parsing at an Ethernet header */
PANDA_PARSER_ADD(panda_parser_simple_hash_ether,
		 "PANDA simple hash parser for Ethernet", &ether_node);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_check_table,
	{ 4, &ipv4_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &ports_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_check_table,
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_table,
	{ IPPROTO_HOPOPTS, &ipv6_eh_node },
	{ IPPROTO_ROUTING, &ipv6_eh_node },
	{ IPPROTO_DSTOPTS, &ipv6_eh_node },
	{ IPPROTO_FRAGMENT, &ipv6_frag_node },
	{ IPPROTO_TCP, &ports_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
);

