// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 by Mojatatu Networks.
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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "test-parser-core.h"

#include "panda/parser_metadata.h"
#include "panda/parsers/parser_big.h"

struct panda_priv {
	struct panda_parser_big_metadata_one md;
};

static void core_panda_help(void)
{
	fprintf(stderr,
		"For the `panda' core, arguments must be either not given or "
		"zero length.\n\n"
		"This core uses the panda library which impelements the "
		"engine for the PANDA Parser.\n");
}

static void *core_panda_init(const char *args)
{
	struct panda_priv *p;

	if (args && *args) {
		fprintf(stderr, "The panda core takes no arguments.\n");
		exit(-1);
	}
	p = calloc(1, sizeof(struct panda_priv));

	if (!p || panda_parser_init() < 0) {
		fprintf(stderr, "panda_parser_init failed\n");
		exit(-11);
	}
	return (p);
}

static const char *core_panda_process(void *pv, void *data, size_t len,
				      struct test_parser_out *out,
				      unsigned int flags)
{
	struct panda_priv *p = pv;
	int i, err;

	memset(&p->md, 0, sizeof(p->md));
	memset(out, 0, sizeof(*out));

	err = (flags & CORE_F_NOCORE) ? (int)PANDA_OKAY :
	    panda_parse(panda_parser_big_ether, data, len, &p->md.panda_data, 0,
			PANDA_PARSER_BIG_ENCAP_DEPTH);

	switch (err) {
	case PANDA_OKAY:
		// printf("PANDA status OKAY\n");
		break;
	case PANDA_STOP_OKAY:
		// printf("PANDA status STOP_OKAY\n");
		break;
	case PANDA_STOP_FAIL:
		return "PANDA: parse failed";
	case PANDA_STOP_LENGTH:
		return "PANDA: STOP_LENGTH";
	case PANDA_STOP_UNKNOWN_PROTO:
		return "PANDA: STOP_UNKNOWN_PROTO";
	case PANDA_STOP_ENCAP_DEPTH:
		return "PANDA: STOP_ENCAP_DEPTH";
	}
	if (p->md.panda_data.encaps)
		printf("PANDA encaps %u\n",
		       (unsigned int)p->md.panda_data.encaps);
	if (p->md.panda_data.max_frame_num)
		printf("PANDA max_frame_num %u\n",
		       (unsigned int)p->md.panda_data.max_frame_num);
	if (p->md.panda_data.frame_size)
		printf("PANDA frame_size %u\n",
		       (unsigned int)p->md.panda_data.frame_size);

	switch (p->md.frame.addr_type) {
	case 0:
		break;
	case PANDA_ADDR_TYPE_IPV4:
		out->k_control.addr_type = ADDR_TYPE_IPv4;
		break;
	case PANDA_ADDR_TYPE_IPV6:
		out->k_control.addr_type = ADDR_TYPE_IPv6;
		break;
	case PANDA_ADDR_TYPE_TIPC:
		out->k_control.addr_type = ADDR_TYPE_TIPC;
		break;
	default:
		out->k_control.addr_type = ADDR_TYPE_OTHER;
		break;
	}

	/* The out struct has no represantation for fragments. We need
	 * to add it. For now coment out the printing because it seems
	 * to confuse AFL
	 * if (p->md.frame.is_fragment)
	 *	 printf("PANDA is_fragment %d\n", (int)p->md.frame.is_fragment);
	 * if (p->md.frame.first_frag)
	 *	 printf("PANDA first_frag %d\n", (int)p->md.frame.first_frag);
	 */

	if (p->md.frame.vlan_count)
		printf("PANDA vlan_count %d\n", (int)p->md.frame.vlan_count);
	if (ARRAY_SIZE(p->md.frame.eth_addrs) !=
	    ARRAY_SIZE(out->k_eth_addrs.src) +
	    ARRAY_SIZE(out->k_eth_addrs.dst)) {
		fprintf(stderr, "PANDA and output struct disagree on Ethernet "
			"address size\n");
		exit(-1);
	}

	memcpy(out->k_eth_addrs.dst, p->md.frame.eth_addrs,
	       ARRAY_SIZE(out->k_eth_addrs.dst));
	memcpy(out->k_eth_addrs.src,
	       &p->md.frame.eth_addrs[ARRAY_SIZE(out->k_eth_addrs.dst)],
	       ARRAY_SIZE(out->k_eth_addrs.src));

	out->k_mpls.mpls_ttl = p->md.frame.mpls.ttl;
	out->k_mpls.mpls_bos = p->md.frame.mpls.bos;
	out->k_mpls.mpls_tc = p->md.frame.mpls.tc;
	out->k_mpls.mpls_label = p->md.frame.mpls.label;
	out->k_arp.s_ip = p->md.frame.arp.sip;
	out->k_arp.t_ip = p->md.frame.arp.tip;
	out->k_arp.op = p->md.frame.arp.op;

	memcpy(out->k_arp.s_hw, p->md.frame.arp.sha,
	       panda_min(ARRAY_SIZE(p->md.frame.arp.sha),
			 ARRAY_SIZE(out->k_arp.s_hw)));
	memcpy(out->k_arp.t_hw, p->md.frame.arp.tha,
	       panda_min(ARRAY_SIZE(p->md.frame.arp.tha),
			 ARRAY_SIZE(out->k_arp.t_hw)));

	out->k_tcp_opt.mss = p->md.frame.tcp_options.mss;
	out->k_tcp_opt.ws = p->md.frame.tcp_options.window_scaling;
	out->k_tcp_opt.ts_val = p->md.frame.tcp_options.timestamp.value;
	out->k_tcp_opt.ts_echo = p->md.frame.tcp_options.timestamp.echo;

	/* We assume that the first SACK element with both edges zero
	 * indicates the end of the SACK list.
	 */
	for (i = 0; (i < ARRAY_SIZE(p->md.frame.tcp_options.sack)) &&
	     (i < ARRAY_SIZE(out->k_tcp_opt.sack)) &&
	     (p->md.frame.tcp_options.sack[i].left_edge ||
	      p->md.frame.tcp_options.sack[i].right_edge); i++) {
		out->k_tcp_opt.sack[i].l =
		    p->md.frame.tcp_options.sack[i].left_edge;
		out->k_tcp_opt.sack[i].r =
		    p->md.frame.tcp_options.sack[i].right_edge;
	}

	if (i < ARRAY_SIZE(out->k_tcp_opt.sack)) {
		out->k_tcp_opt.sack[i].l = 0;
		out->k_tcp_opt.sack[i].r = 0;
	}
	out->k_basic.n_proto = p->md.frame.eth_proto;
	out->k_basic.ip_proto = p->md.frame.ip_proto;
	out->k_flow_label.flow_label = p->md.frame.flow_label;

	switch (p->md.frame.vlan_count) {
	case 0:
		break;
	case 1:
		out->k_vlan.vlan_id = p->md.frame.vlan[0].id;
		out->k_vlan.vlan_dei = p->md.frame.vlan[0].dei;
		out->k_vlan.vlan_priority = p->md.frame.vlan[0].priority;
		out->k_vlan.vlan_tpid = p->md.frame.vlan[0].tpid;
		break;
	default:
		printf("PANDA vlan_count %d\n", (int)p->md.frame.vlan_count);
		break;
	}

	if (p->md.frame.keyid)
		printf("PANDA keyid %08lx\n", (unsigned long)p->md.frame.keyid);

	out->k_ports.src = p->md.frame.src_port;
	out->k_ports.dst = p->md.frame.dst_port;
	out->k_icmp.type = p->md.frame.icmp.type;
	out->k_icmp.code = p->md.frame.icmp.code;
	out->k_icmp.id = p->md.frame.icmp.id;

	switch (p->md.frame.addr_type) {
	case PANDA_ADDR_TYPE_IPV4:
		out->k_ipv4_addrs.src = p->md.frame.addrs.v4_addrs[0];
		out->k_ipv4_addrs.dst = p->md.frame.addrs.v4_addrs[1];
		break;
	case PANDA_ADDR_TYPE_IPV6:
		memcpy(out->k_ipv6_addrs.src, p->md.frame.addrs.v6_addrs, 16);
		memcpy(out->k_ipv6_addrs.dst, &p->md.frame.addrs.v6_addrs[1],
		       16);
		break;
	case PANDA_ADDR_TYPE_TIPC:
		out->k_tipc.key = p->md.frame.addrs.tipckey;
		break;
	}

	if (flags & CORE_F_HASH)
		out->k_hash.hash = panda_parser_big_hash_frame(&p->md.frame);

	return 0;
}

static void core_panda_done(void *pv)
{
	free(pv);
}

CORE_DECL(panda)
