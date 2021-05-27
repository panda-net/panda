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

/* PANDA Big Parser
 *
 * Implement flow dissector in PANDA. A protocol parse graph is created and
 * metadata is extracted at various nodes.
 */

#include <arpa/inet.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "panda/parsers/parser_big.h"
#include "siphash/siphash.h"

/* Define protocol nodes that are used below */
#include "panda/proto_nodes_def.h"

/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */
PANDA_METADATA_TEMP_ether_off(ether_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv4(ipv4_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv6(ipv6_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ip_overlay(ip_overlay_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv6_eh(ipv6_eh_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv6_frag(ipv6_frag_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ports_off(ports_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_icmp(icmp_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_vlan_8021AD(e8021AD_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_vlan_8021Q(e8021Q_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_mpls(mpls_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_arp_rarp(arp_rarp_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_tipc(tipc_metadata, panda_metadata_all)

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

PANDA_METADATA_TEMP_gre(gre_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp(gre_pptp_metadata, panda_metadata_all)

PANDA_METADATA_TEMP_gre_checksum(gre_checksum_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_keyid(gre_keyid_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_seq(gre_seq_metadata, panda_metadata_all)

PANDA_METADATA_TEMP_gre_pptp_key(gre_pptp_key_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp_seq(gre_pptp_seq_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp_ack(gre_pptp_ack_metadata, panda_metadata_all)

/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */

PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata,
		      NULL, ether_table);
PANDA_MAKE_PARSE_NODE(ipv4_check_node, panda_parse_ip, NULL, NULL,
		      ipv4_check_table);
PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata, NULL,
		      ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv6_check_node, panda_parse_ip, NULL, NULL,
		      ipv6_check_table);
PANDA_MAKE_PARSE_NODE(ipv6_node, panda_parse_ipv6, ipv6_metadata, NULL,
		      ipv6_table);
PANDA_MAKE_PARSE_NODE(ip_overlay_node, panda_parse_ip, ip_overlay_metadata,
		      NULL, ip_table);
PANDA_MAKE_PARSE_NODE(ipv6_eh_node, panda_parse_ipv6_eh, ipv6_eh_metadata,
		      NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_frag_node, panda_parse_ipv6_frag_eh,
		      ipv6_frag_metadata, NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(gre_base_node, panda_parse_gre_base, NULL, NULL,
		      gre_base_table);

PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(gre_v0_node, panda_parse_gre_v0,
				  gre_metadata, NULL, gre_v0_table,
				  gre_v0_flag_fields_table, NULL);
PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(gre_v1_node, panda_parse_gre_v1,
				  gre_pptp_metadata, NULL, gre_v1_table,
				  gre_v1_flag_fields_table, NULL);

PANDA_MAKE_PARSE_NODE(e8021AD_node, panda_parse_vlan, e8021AD_metadata,
		      NULL, ether_table);
PANDA_MAKE_PARSE_NODE(e8021Q_node, panda_parse_vlan, e8021Q_metadata, NULL,
		      ether_table);
PANDA_MAKE_PARSE_NODE(ppp_node, panda_parse_ppp, NULL, NULL, ppp_table);
PANDA_MAKE_PARSE_NODE(pppoe_node, panda_parse_pppoe, NULL, NULL,
		      pppoe_table);
PANDA_MAKE_PARSE_NODE(ipv4ip_node, panda_parse_ipv4ip, NULL, NULL,
		      ipv4ip_table);
PANDA_MAKE_PARSE_NODE(ipv6ip_node, panda_parse_ipv6ip, NULL, NULL,
		      ipv6ip_table);
PANDA_MAKE_PARSE_NODE(batman_node, panda_parse_batman, NULL, NULL,
		      ether_table);

PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv4_node, panda_parse_icmpv4, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv6_node, panda_parse_icmpv6, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(mpls_node, panda_parse_mpls, mpls_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(arp_node, panda_parse_arp, arp_rarp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(rarp_node, panda_parse_rarp, arp_rarp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(tipc_node, panda_parse_tipc, tipc_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(fcoe_node, panda_parse_fcoe, NULL, NULL);
PANDA_MAKE_LEAF_PARSE_NODE(igmp_node, panda_parse_igmp, NULL, NULL);

PANDA_MAKE_LEAF_TLVS_PARSE_NODE(tcp_node, panda_parse_tcp_tlvs,	ports_metadata,
				NULL, NULL, tcp_tlv_table);

PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_mss_node, tcp_option_mss_check_length,
			  tcp_opt_mss_metadata, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_window_scaling_node,
			  tcp_option_window_scaling_check_length,
			  tcp_opt_window_scaling_metadata, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_timestamp_node,
			  tcp_option_timestamp_check_length,
			  tcp_opt_timestamp_metadata, NULL);

PANDA_MAKE_TLV_OVERLAY_PARSE_NODE(tcp_opt_sack_node, NULL, NULL, NULL,
				  tcp_sack_tlv_table, NULL, PANDA_OKAY, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_1, NULL, tcp_opt_sack_metadata_1, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_2, NULL, tcp_opt_sack_metadata_2, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_3, NULL, tcp_opt_sack_metadata_3, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_4, NULL, tcp_opt_sack_metadata_4, NULL);

PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_csum_node, gre_checksum_metadata,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_key_node, gre_keyid_metadata, NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_seq_node, gre_seq_metadata, NULL);

PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_ack_node, gre_pptp_ack_metadata,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_key_node, gre_pptp_key_metadata,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_seq_node, gre_pptp_seq_metadata,
				 NULL);

/* Define parsers. Two of them: one for packets starting with an
 * Ethernet header, and one for packets starting with an IP header.
 */
PANDA_PARSER_ADD(panda_parser_big_ether, "PANDA big parser for Ethernet",
		 &ether_node);
PANDA_PARSER_ADD(panda_parser_big_ip, "PANDA big parser for IP",
		 &ip_overlay_node);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
	{ __cpu_to_be16(ETH_P_8021AD), &e8021AD_node },
	{ __cpu_to_be16(ETH_P_8021Q), &e8021Q_node },
	{ __cpu_to_be16(ETH_P_MPLS_UC), &mpls_node },
	{ __cpu_to_be16(ETH_P_MPLS_MC), &mpls_node },
	{ __cpu_to_be16(ETH_P_ARP), &arp_node },
	{ __cpu_to_be16(ETH_P_RARP), &rarp_node },
	{ __cpu_to_be16(ETH_P_TIPC), &tipc_node },
	{ __cpu_to_be16(ETH_P_BATMAN), &batman_node },
	{ __cpu_to_be16(ETH_P_FCOE), &fcoe_node },
	{ __cpu_to_be16(ETH_P_PPP_SES), &pppoe_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_check_table,
	{ 4, &ipv4_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &tcp_node.parse_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_GRE, &gre_base_node },
	{ IPPROTO_ICMP, &icmpv4_node },
	{ IPPROTO_IGMP, &igmp_node },
	{ IPPROTO_MPLS, &mpls_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_check_table,
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_table,
	{ IPPROTO_HOPOPTS, &ipv6_eh_node },
	{ IPPROTO_ROUTING, &ipv6_eh_node },
	{ IPPROTO_DSTOPTS, &ipv6_eh_node },
	{ IPPROTO_FRAGMENT, &ipv6_frag_node },
	{ IPPROTO_TCP, &tcp_node.parse_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_GRE, &gre_base_node },
	{ IPPROTO_ICMPV6, &icmpv6_node },
	{ IPPROTO_IGMP, &igmp_node },
	{ IPPROTO_MPLS, &mpls_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ip_table,
	{ 4, &ipv4_node },
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4ip_table,
	{ 0, &ipv4_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6ip_table,
	{ 0, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(gre_base_table,
	{ 0, &gre_v0_node.parse_node },
	{ 1, &gre_v1_node.parse_node },
);

PANDA_MAKE_PROTO_TABLE(gre_v0_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
	{ __cpu_to_be16(ETH_P_TEB), &ether_node },
);

PANDA_MAKE_PROTO_TABLE(gre_v1_table,
	{ 0, &ppp_node },
);

PANDA_MAKE_PROTO_TABLE(ppp_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
);

PANDA_MAKE_PROTO_TABLE(pppoe_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
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

PANDA_MAKE_FLAG_FIELDS_TABLE(gre_v0_flag_fields_table,
	{ GRE_FLAGS_CSUM_IDX, &gre_flag_csum_node },
	{ GRE_FLAGS_KEY_IDX, &gre_flag_key_node },
	{ GRE_FLAGS_SEQ_IDX, &gre_flag_seq_node }
);

PANDA_MAKE_FLAG_FIELDS_TABLE(gre_v1_flag_fields_table,
	{ GRE_PPTP_FLAGS_CSUM_IDX, &PANDA_FLAG_NODE_NULL },
	{ GRE_PPTP_FLAGS_KEY_IDX, &gre_pptp_flag_key_node },
	{ GRE_PPTP_FLAGS_SEQ_IDX, &gre_pptp_flag_seq_node },
	{ GRE_PPTP_FLAGS_ACK_IDX, &gre_pptp_flag_ack_node }
);

/* Ancilary functions */

void panda_parser_big_print_frame(struct panda_metadata_all *frame)
{
	PANDA_PRINT_METADATA(frame);
}

void panda_parser_big_print_hash_input(struct panda_metadata_all *frame)
{
	const void *start = PANDA_HASH_START(frame,
					     PANDA_HASH_START_FIELD_ALL);
	size_t len = PANDA_HASH_LENGTH(frame,
				       PANDA_HASH_OFFSET_ALL);

	panda_print_hash_input(start, len);
}
