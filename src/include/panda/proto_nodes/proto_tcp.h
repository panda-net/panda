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

#ifndef __PANDA_PROTO_TCP_H__
#define __PANDA_PROTO_TCP_H__

#include <linux/tcp.h>

#include "panda/parser.h"

/* TCP node definitions */

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM	4	/* SACK Permitted */
#define TCPOPT_SACK		5	/* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN		34	/* Fast open (RFC7413) */
#define TCPOPT_EXP		254	/* Experimental */

struct tcp_opt {
	__u8 type;
	__u8 len;
	__u8 data[0];
};

struct tcp_timestamp_option_data {
	__be32 value;
	__be32 echo;
};

struct tcp_sack_option_data {
	__be32 left_edge;
	__be32 right_edge;
};

#define TCP_MAX_SACKS	4

struct tcp_opt_union {
	struct tcp_opt opt;
	union {
		__be16 mss;
		__u8 window_scaling;
		struct tcp_timestamp_option_data timestamp;
		struct tcp_sack_option_data sack[TCP_MAX_SACKS];
	} __attribute__((packed));
} __attribute__((packed));

static inline ssize_t tcp_len(const void *vtcp)
{
	return ((struct tcphdr *)vtcp)->doff * 4;
}

static inline ssize_t tcp_tlv_len(const void *hdr)
{
	return ((struct tcp_opt *)hdr)->len;
}

static inline int tcp_tlv_type(const void *hdr)
{
	return ((struct tcp_opt *)hdr)->type;
}

static inline size_t tcp_tlvs_start_offset(const void *hdr)
{
	return sizeof(struct tcphdr);
}

/* Functions to check length of TCP options */

static inline int tcp_option_mss_check_length(const void *hdr, void *frame)
{
	const struct tcp_opt_union *opt = hdr;

	if (opt->opt.len != sizeof(struct tcp_opt) + sizeof(__be16))
		return PANDA_STOP_TLV_LENGTH;

	return PANDA_OKAY;
}

static inline int tcp_option_window_scaling_check_length(const void *hdr,
							 void *frame)
{
	const struct tcp_opt_union *opt = hdr;

	if (opt->opt.len != sizeof(struct tcp_opt) + sizeof(__u8))
		return PANDA_STOP_TLV_LENGTH;

	return PANDA_OKAY;
}

static inline int tcp_option_timestamp_check_length(const void *hdr,
						    void *frame)
{
	const struct tcp_opt_union *opt = hdr;

	if (opt->opt.len != sizeof(struct tcp_opt) +
				sizeof(struct tcp_timestamp_option_data))
		return PANDA_STOP_TLV_LENGTH;

	return PANDA_OKAY;
}

#endif /* __PANDA_PROTO_TCP_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* PANDA protocol node for TCP
 *
 * There are two variants:
 *   - Parse TCP header and TLVs
 *   - Just parse header without parsing TLVs
 */

/* panda_parse_tcp_tlvs protocol node
 *
 * Parse TCP header and any TLVs
 */
static const struct panda_proto_tlvs_node panda_parse_tcp_tlvs __unused() = {
	.proto_node.node_type = PANDA_NODE_TYPE_TLVS,
	.proto_node.name = "TCP with TLVs",
	.proto_node.min_len = sizeof(struct tcphdr),
	.proto_node.ops.len = tcp_len,
	.ops.len = tcp_tlv_len,
	.ops.type = tcp_tlv_type,
	.ops.start_offset = tcp_tlvs_start_offset,
	.pad1_val = TCPOPT_NOP,
	.pad1_enable = 1,
	.eol_val = TCPOPT_EOL,
	.eol_enable = 1,
};

/* panda_parse_tcp_no_tlvs protocol node
 *
 * Parse TCP header without considering TLVs
 */
static const struct panda_proto_node panda_parse_tcp_notlvs __unused() = {
	.name = "TCP without TLVs",
	.min_len = sizeof(struct tcphdr),
	.ops.len = tcp_len,
};

#endif /* PANDA_DEFINE_PARSE_NODE */
