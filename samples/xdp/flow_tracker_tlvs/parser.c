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

#include <arpa/inet.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "siphash/siphash.h"

/* Define protocol nodes that are used below */
#include "panda/proto_nodes_def.h"

/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */
PANDA_METADATA_TEMP_ether(ether_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv4(ipv4_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ports(ports_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_mss(tcp_opt_mss_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_window_scaling(tcp_opt_window_scaling_metadata,
					      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_timestamp(tcp_opt_timestamp_metadata,
					 panda_metadata_all)

PANDA_METADATA_TEMP_tcp_option_sack_1(tcp_opt_sack_metadata_1,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_2(tcp_opt_sack_metadata_2,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_3(tcp_opt_sack_metadata_3,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_4(tcp_opt_sack_metadata_4,
				      panda_metadata_all)

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

PANDA_MAKE_LEAF_TLVS_PARSE_NODE(tcp_node, panda_parse_tcp_tlvs,	ports_metadata,
				NULL, tcp_tlv_table);

PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_mss_node, panda_parse_tcp_option_mss,
			  tcp_opt_mss_metadata, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_window_scaling_node,
			  panda_parse_tcp_option_window_scaling,
			  tcp_opt_window_scaling_metadata, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_timestamp_node,
			  panda_parse_tcp_option_timestamp,
			  tcp_opt_timestamp_metadata, NULL);

PANDA_MAKE_TLV_OVERLAY_PARSE_NODE(tcp_opt_sack_node, NULL, NULL,
				  tcp_sack_tlv_table, NULL, PANDA_STOP_OKAY,
				  NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_1, panda_parse_tcp_option_sack_1,
			  tcp_opt_sack_metadata_1, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_2, panda_parse_tcp_option_sack_2,
			  tcp_opt_sack_metadata_2, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_3, panda_parse_tcp_option_sack_3,
			  tcp_opt_sack_metadata_3, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_4, panda_parse_tcp_option_sack_4,
			  tcp_opt_sack_metadata_4, NULL);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_check_table,
	{ 4, &ipv4_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &tcp_node.parse_node },
	{ IPPROTO_UDP, &ports_node },
);

PANDA_MAKE_TLV_TABLE(tcp_tlv_table,
	{ TCPOPT_MSS, &tcp_opt_mss_node },
	{ TCPOPT_WINDOW, &tcp_opt_window_scaling_node },
	{ TCPOPT_TIMESTAMP, &tcp_opt_timestamp_node },
	{ TCPOPT_SACK, &tcp_opt_sack_node }
);

/* Keys are possible lengths of the TCP sack option */
PANDA_MAKE_TLV_TABLE(tcp_sack_tlv_table,
	{ 10, &tcp_opt_sack_1 },
	{ 18, &tcp_opt_sack_2 },
	{ 26, &tcp_opt_sack_3 },
	{ 34, &tcp_opt_sack_4 }
);

PANDA_PARSER(panda_parser_simple_tuple, "PANDA parser for 5 tuple TCP/UDP",
	     &ether_node);
