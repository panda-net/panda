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

#if 0
#include <arpa/inet.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "siphash/siphash.h"
#endif

/* Define protocol nodes that are used below */
//#include "panda/proto_nodes_def.h"

/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */
PANDA_METADATA_TEMP_ether(ether_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv4(ipv4_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ports(ports_metadata, panda_metadata_all)

/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */

PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata, NULL,
		      ether_table);
PANDA_MAKE_PARSE_NODE(ipv4_check_node, panda_parse_ip, NULL, NULL,
		      ipv4_check_table);
PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata, NULL,
		      ipv4_table);
PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata, NULL);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_check_table,
	{ 4, &ipv4_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &ports_node },
	{ IPPROTO_UDP, &ports_node },
);

PANDA_PARSER(panda_parser_simple_tuple, "PANDA parser for 5 tuple TCP/UDP",
	     &ether_node);
