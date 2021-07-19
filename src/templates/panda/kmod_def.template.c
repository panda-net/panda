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

#include "panda/parser.h"
#include "panda/parser_metadata.h"
#include "panda/proto_nodes_def.h"

#include "@!filename!@"

#ifndef PANDA_LOOP_COUNT
#define PANDA_LOOP_COUNT 8
#endif

#define PANDA_MAX_ENCAPS (PANDA_LOOP_COUNT + 32)
enum {
<!--(for node in graph)-->
CODE_@!node!@,
<!--(end)-->
CODE_IGNORE
};

/* Parser control */
static long next = CODE_IGNORE;

static inline __attribute__((always_inline)) int check_pkt_len(const void *hdr,
		const struct panda_proto_node *pnode, size_t len, ssize_t *hlen)
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
		struct panda_metadata *metadata, unsigned int max_encaps,
		void **frame, unsigned int *frame_num)
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

<!--(macro generate_entry_parse_function)-->
static inline int @!parser_name!@_panda_parse_@!root_name!@(
		const struct panda_parser *parser,
		const struct panda_parse_node *parse_node,
		const void *hdr, size_t len,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps)
{
	void *frame = metadata->frame_data;
	unsigned int frame_num = 0;
	int ret = PANDA_STOP_OKAY;
	int i;

	ret = __@!root_name!@_panda_parse(parser, &hdr,
		len, 0, metadata, flags, max_encaps, frame, frame_num);

	for (i = 0; i < PANDA_LOOP_COUNT; i++) {
		if (ret != PANDA_STOP_OKAY)
			break;
		switch (next) {
		case CODE_IGNORE:
			break;
		<!--(for node in graph)-->
		case CODE_@!node!@:
			ret = __@!node!@_panda_parse(parser, &hdr, len, 0,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		<!--(end)-->
		default:
			return PANDA_STOP_UNKNOWN_PROTO;
		}
	}

	return ret;
}

PANDA_PARSER_KMOD(
      @!parser_name!@,
      "",
      &@!root_name!@,
      @!parser_name!@_panda_parse_@!root_name!@
    );
<!--(end)-->

<!--(macro generate_protocol_parse_function)-->
	<!--(if len(graph[name]['tlv_nodes']) != 0)-->
@!generate_protocol_tlvs_parse_function(name=name)!@
	<!--(end)-->
	<!--(if len(graph[name]['flag_fields_nodes']) != 0)-->
@!generate_protocol_fields_parse_function(name=name)!@
	<!--(end)-->
static __always_inline int __@!name!@_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&@!name!@;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);

	<!--(if len(graph[name]['tlv_nodes']) != 0)-->
	ret = __@!name!@_panda_parse_tlvs(parse_node, *hdr, frame, ctrl);
	if (ret != PANDA_OKAY)
		return ret;
	<!--(end)-->

	<!--(if len(graph[name]['flag_fields_nodes']) != 0)-->
	ret = __@!name!@_panda_parse_flag_fields(
					parse_node, *hdr, frame, ctrl);
	if (ret != PANDA_OKAY)
		return ret;
	<!--(end)-->

	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	<!--(if len(graph[name]['out_edges']) != 0)-->
	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
		<!--(for edge_target in graph[name]['out_edges'])-->
			<!--(for e in graph[name]['out_edges'][edge_target])-->
	case @!e['macro_name']!@:
		next = CODE_@!edge_target!@;
		return PANDA_STOP_OKAY;
			<!--(end)-->
		<!--(end)-->
	}
	/* Unknown protocol */
		<!--(if len(graph[name]['wildcard_proto_node']) != 0)-->
	return __@!graph[name]['wildcard_proto_node']!@_panda_parse(
		parser, *hdr, len, offset, metadata, flags, max_encaps,
		frame, frame_num);
		<!--(else)-->
	return PANDA_STOP_UNKNOWN_PROTO;
		<!--(end)-->
	}
	<!--(else)-->
	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
	<!--(end)-->
}
<!--(end)-->

<!--(macro generate_protocol_parse_function_decl)-->
static __always_inline int __@!name!@_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
<!--(end)-->

<!--(for node in graph)-->
@!generate_protocol_parse_function_decl(name=node)!@
<!--(end)-->

<!--(for node in graph)-->
@!generate_protocol_parse_function(name=node)!@
<!--(end)-->

<!--(for parser_name,root_name,parser_add,parser_ext in roots)-->
@!generate_entry_parse_function(parser_name=parser_name,root_name=root_name,parser_add=parser_add,parser_ext=parser_ext)!@
<!--(end)-->
