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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "panda/parser.h"
#include "panda/proto_nodes_def.h"
#include "@!filename!@"

static inline __attribute__((always_inline)) int check_pkt_len(const void* hdr,
		const struct panda_proto_node *pnode, size_t len, ssize_t* hlen)
{
	*hlen = pnode->min_len;

	/* Protocol node length checks */
	if (len < *hlen)
		return PANDA_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr);
		if (len < *hlen)
			return PANDA_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return *hlen < 0 ? *hlen : PANDA_STOP_LENGTH;
	} else {
		*hlen = pnode->min_len;
	}

	return PANDA_OKAY;
}

static inline __attribute__((always_inline)) int panda_encap_layer(
		struct panda_metadata *metadata, unsigned max_encaps,
		void **frame, unsigned *frame_num)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	if (++metadata->encaps > max_encaps)
		return PANDA_STOP_ENCAP_DEPTH;

	if (metadata->max_frame_num > *frame_num) {
		*frame += metadata->frame_size;
		*frame_num = (*frame_num) + 1;
	}

	return PANDA_OKAY;
}

static inline __attribute__((always_inline)) int panda_parse_tlv(
		const struct panda_parse_tlvs_node *parse_node,
		const struct panda_parse_tlv_node *parse_tlv_node,
		const __u8 *cp, void *frame, struct panda_ctrl_data tlv_ctrl) {
	const struct panda_parse_tlv_node_ops *ops = &parse_tlv_node->tlv_ops;
	const struct panda_proto_tlv_node *proto_tlv_node =
					parse_tlv_node->proto_tlv_node;

	if (proto_tlv_node && (tlv_ctrl.hdr_len < proto_tlv_node->min_len)) {
		/* Treat check length error as an unrecognized TLV */
		if (parse_node->tlv_wildcard_node)
			return panda_parse_tlv(parse_node,
					parse_node->tlv_wildcard_node,
					cp, frame, tlv_ctrl);
		else
			return parse_node->unknown_tlv_type_ret;
	}

	if (ops->extract_metadata)
		ops->extract_metadata(cp, frame, tlv_ctrl);

	if (ops->handle_tlv)
		ops->handle_tlv(cp, frame, tlv_ctrl);

	return PANDA_OKAY;
}

<!--(for node in graph)-->
@!generate_protocol_parse_function_decl(name=node)!@
<!--(end)-->
<!--(for node in graph)-->
@!generate_protocol_parse_function(name=node)!@
<!--(end)-->
<!--(for parser_name,root_name,parser_add,parser_ext in roots)-->
@!generate_entry_parse_function(parser_name=parser_name,root_name=root_name,parser_add=parser_add,parser_ext=parser_ext)!@
<!--(end)-->
