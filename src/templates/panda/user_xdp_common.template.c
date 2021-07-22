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

<!--(macro generate_entry_parse_function)-->
static inline int @!parser_name!@_panda_parse_@!root_name!@(
		const struct panda_parser *parser,
		const void *hdr, size_t len,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps)
{
	void *frame = metadata->frame_data;
	unsigned frame_num = 0;

	return __@!root_name!@_panda_parse(parser, hdr,
		len, 0, metadata, flags, max_encaps, frame, frame_num);
}
	<!--(if parser_add and parser_ext)-->
PANDA_PARSER_OPT_ADD_EXT(
	<!--(elif parser_add and not parser_ext)-->
PANDA_PARSER_OPT_ADD(
	<!--(elif not parser_add and parser_ext)-->
PANDA_PARSER_OPT_EXT(
	<!--(elif not parser_add and not parser_ext)-->
PANDA_PARSER_OPT(
	<!--(end)-->
      @!parser_name!@_opt,
      "",
      &@!root_name!@,
      @!parser_name!@_panda_parse_@!root_name!@
    );
<!--(end)-->
<!--(macro generate_protocol_fields_parse_function)-->
static inline __attribute__((always_inline)) int
	__@!name!@_panda_parse_flag_fields(
		const struct panda_parse_node *parse_node,
		const void *hdr, void *frame, struct panda_ctrl_data ctrl)
{
	const struct panda_proto_flag_fields_node *proto_flag_fields_node;
	const struct panda_flag_field *flag_fields;
	const struct panda_flag_field *flag_field;
	__u32 flags, mask;
	const __u8 *cp;

	proto_flag_fields_node =
		(struct panda_proto_flag_fields_node *)parse_node->proto_node;
	cp = (__u8 const*)hdr +
			proto_flag_fields_node->ops.start_fields_offset(hdr);
	flag_fields = proto_flag_fields_node->flag_fields->fields;
	flags = proto_flag_fields_node->ops.get_flags(hdr);

	if (flags) {
	<!--(for flag in graph[name]['flag_fields_nodes'])-->
		flag_field = &flag_fields[@!flag['index']!@];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((flags & mask) == flag_field->flag) {
			ctrl.hdr_len = flag_field->size;
			if (@!flag['name']!@.ops.extract_metadata)
				@!flag['name']!@.ops.extract_metadata(
						cp, frame, ctrl);
			if(@!flag['name']!@.ops.handle_flag_field)
				@!flag['name']!@.ops.handle_flag_field(
						cp, frame, ctrl);
			cp += flag_field->size;
			ctrl.hdr_offset += flag_field->size;
		}
	<!--(end)-->
	}
	return PANDA_OKAY;
}
<!--(end)-->
<!--(macro generate_protocol_tlvs_parse_function)-->
static inline __attribute__((always_inline)) int __@!name!@_panda_parse_tlvs(
		const struct panda_parse_node *parse_node,
		const void *hdr, void *frame, struct panda_ctrl_data ctrl)
{
	const struct panda_proto_tlvs_node *proto_tlvs_node =
		(const struct panda_proto_tlvs_node*)parse_node->proto_node;
	const struct panda_parse_tlvs_node *parse_tlvs_node =
		(const struct panda_parse_tlvs_node*)&@!name!@;
	const struct panda_parse_tlv_node *parse_tlv_node;
	const struct panda_parse_tlv_node_ops *ops;
	const __u8 *cp = hdr;
	size_t offset, len;
	ssize_t tlv_len;
	int type;

	(void)ops;

	offset = proto_tlvs_node->ops.start_offset (hdr);
	/* Assume hdr_len marks end of TLVs */
	len = ctrl.hdr_len - offset;
	cp += offset;

	while (len > 0) {
		if (proto_tlvs_node->pad1_enable &&
		    *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			ctrl.hdr_offset++;
			len--;
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
			ctrl.hdr_offset++;
			len--;
			break;
		}

		if (len < proto_tlvs_node->min_len)
			return PANDA_STOP_TLV_LENGTH;

		if (proto_tlvs_node->ops.len) {
			tlv_len = proto_tlvs_node->ops.len(cp);
			if (!tlv_len || len < tlv_len)
				return PANDA_STOP_TLV_LENGTH;
			if (tlv_len < proto_tlvs_node->min_len)
				return tlv_len < 0 ? tlv_len :
							PANDA_STOP_TLV_LENGTH;
		} else {
			tlv_len = proto_tlvs_node->min_len;
		}

		type = proto_tlvs_node->ops.type (cp);
		switch (type) {
	<!--(for tlv in graph[name]['tlv_nodes'])-->
		case @!tlv['type']!@:
		{
			int ret;
			struct panda_ctrl_data tlv_ctrl = {
					tlv_len, ctrl.hdr_offset };
			parse_tlv_node = &@!tlv['name']!@;
		<!--(if len(tlv['overlay_nodes']) != 0)-->
			ops = &parse_tlv_node->tlv_ops;
		<!--(end)-->
			ret = panda_parse_tlv(parse_tlvs_node, parse_tlv_node,
					      cp, frame, tlv_ctrl);
			if (ret != PANDA_OKAY)
				return ret;

			break;
		<!--(if len(tlv['overlay_nodes']) != 0)-->
			if (ops->overlay_type)
				type = ops->overlay_type(cp);
			else
				type = tlv_ctrl.hdr_len;

			switch (type) {
			<!--(for overlay in tlv['overlay_nodes'])-->
			case @!overlay['type']!@:
				parse_tlv_node = &@!overlay['name']!@;
				ret = panda_parse_tlv(parse_tlvs_node,
						      parse_tlv_node, cp,
						      frame, tlv_ctrl);
				if (ret != PANDA_OKAY)
					return ret;
				break;
			<!--(end)-->
			default:
				break;
			 }

			break;
		<!--(end)-->
		}
	<!--(end)-->
		default:
		{
			struct panda_ctrl_data tlv_ctrl =
						{ tlv_len, ctrl.hdr_offset };

			if (parse_tlvs_node->tlv_wildcard_node)
				return panda_parse_tlv(parse_tlvs_node,
						       parse_tlvs_node->
							    tlv_wildcard_node,
						       cp, frame, tlv_ctrl);
			else if (parse_tlvs_node->unknown_tlv_type_ret != PANDA_OKAY)
				return parse_tlvs_node->unknown_tlv_type_ret;
		}
		}

		/* Move over current header */
		cp += tlv_len;
		ctrl.hdr_offset += tlv_len;
		len -= tlv_len;
	}
	return PANDA_OKAY;
}
<!--(end)-->

<!--(macro generate_protocol_parse_function_decl)-->
static inline int __@!name!@_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
<!--(end)-->

<!--(macro generate_protocol_parse_function)-->
	<!--(if len(graph[name]['tlv_nodes']) != 0)-->
@!generate_protocol_tlvs_parse_function(name=name)!@
	<!--(end)-->
	<!--(if len(graph[name]['flag_fields_nodes']) != 0)-->
@!generate_protocol_fields_parse_function(name=name)!@
	<!--(end)-->
static inline int __@!name!@_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&@!name!@;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);

	<!--(if len(graph[name]['tlv_nodes']) != 0)-->
	ret = __@!name!@_panda_parse_tlvs(parse_node, hdr, frame, ctrl);
	if (ret != PANDA_OKAY)
		return ret;
	<!--(end)-->

	<!--(if len(graph[name]['flag_fields_nodes']) != 0)-->
	ret = __@!name!@_panda_parse_flag_fields(
					parse_node, hdr, frame, ctrl);
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
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
		<!--(for edge_target in graph[name]['out_edges'])-->
			<!--(for e in graph[name]['out_edges'][edge_target])-->
	case @!e['macro_name']!@:
		return __@!edge_target!@_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
			<!--(end)-->
		<!--(end)-->
	}
		<!--(if len(graph[name]['wildcard_proto_node']) != 0)-->
	return __@!graph[name]['wildcard_proto_node']!@_panda_parse(
		parser, hdr, len, offset, metadata, flags, max_encaps,
		frame, frame_num);
		<!--(else)-->
	return PANDA_STOP_UNKNOWN_PROTO;
		<!--(end)-->
	}
	<!--(else)-->

		<!--(if len(graph[name]['wildcard_proto_node']) != 0)-->
	return __@!graph[name]['wildcard_proto_node']!@_panda_parse(
		parser, hdr, len, offset, metadata, flags, max_encaps,
		frame, frame_num);
		<!--(else)-->
	return PANDA_STOP_OKAY;
		<!--(end)-->
	<!--(end)-->
}
<!--(end)-->
<!--(macro generate_panda_parse_tlv_function)-->
static inline __attribute__((always_inline)) int panda_parse_wildcard_tlv(
		const struct panda_parse_tlvs_node *parse_node,
		const struct panda_parse_tlv_node *wildcard_parse_tlv_node,
		const __u8 *cp, void *frame, struct panda_ctrl_data tlv_ctrl) {
	const struct panda_parse_tlv_node_ops *ops =
					&wildcard_parse_tlv_node->tlv_ops;
	const struct panda_proto_tlv_node *proto_tlv_node =
					wildcard_parse_tlv_node->proto_tlv_node;

	if (proto_tlv_node && (tlv_ctrl.hdr_len < proto_tlv_node->min_len))
		return parse_node->unknown_tlv_type_ret;

	if (ops->extract_metadata)
		ops->extract_metadata(cp, frame, tlv_ctrl);

	if (ops->handle_tlv)
		ops->handle_tlv(cp, frame, tlv_ctrl);

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
			return panda_parse_wildcard_tlv(parse_node,
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
<!--(end)-->
