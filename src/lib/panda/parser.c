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

/* PANDA main parsing logic */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "panda/parser.h"
#include "siphash/siphash.h"

/* Lookup a type in a node table*/
static const struct panda_parse_node *lookup_node(int type,
				    const struct panda_proto_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].value)
			return table->entries[i].node;

	return NULL;
}

/* Lookup up a protocol for the table associated with a parse node */
const struct panda_parse_node *panda_parse_lookup_by_proto(
		const struct panda_parse_node *node, int proto)
{
	return lookup_node(proto, node->proto_table);
}

/* Lookup a type in a node TLV table */
static const struct panda_parse_tlv_node *lookup_tlv_node(int type,
				const struct panda_proto_tlvs_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].type)
			return table->entries[i].node;

	return NULL;
}

/* Lookup up a protocol for the table associated with a parse node */
const struct panda_parse_tlv_node *panda_parse_lookup_tlv(
		const struct panda_parse_tlvs_node *node,
		unsigned int type)
{
	return lookup_tlv_node(type, node->tlv_proto_table);
}

/* Lookup a flag-fields index in a protocol node flag-fields table */
static const struct panda_parse_flag_field_node *lookup_flag_field_node(int idx,
				const struct panda_proto_flag_fields_table
								*table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (idx == table->entries[i].index)
			return table->entries[i].node;

	return NULL;
}

static int panda_parse_one_tlv(
		const struct panda_parse_tlvs_node *parse_tlvs_node,
		const struct panda_parse_tlv_node *parse_tlv_node,
		const void *hdr, void *frame, int type,
		struct panda_ctrl_data tlv_ctrl, unsigned int flags)
{
	const struct panda_proto_tlv_node *proto_tlv_node =
					parse_tlv_node->proto_tlv_node;
	const struct panda_parse_tlv_node_ops *ops;
	int ret;

parse_again:

	if (flags & PANDA_F_DEBUG)
		printf("PANDA parsing TLV %s\n", parse_tlv_node->name);

	if (proto_tlv_node && (tlv_ctrl.hdr_len < proto_tlv_node->min_len)) {
		/* Treat check length error as an unrecognized TLV */
		parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
		if (parse_tlv_node)
			goto parse_again;
		else
			return parse_tlvs_node->unknown_tlv_type_ret;
	}

	ops = &parse_tlv_node->tlv_ops;

	if (ops->extract_metadata)
		ops->extract_metadata(hdr, frame, tlv_ctrl);

	if (ops->handle_tlv) {
		ret = ops->handle_tlv(hdr, frame, tlv_ctrl);
		if (ret != PANDA_OKAY)
			return ret;
	}

	if (!parse_tlv_node->overlay_table)
		return PANDA_OKAY;

	/* We have an TLV overlay  node */

	if (parse_tlv_node->tlv_ops.overlay_type)
		type = parse_tlv_node->tlv_ops.overlay_type(hdr);
	else
		type = tlv_ctrl.hdr_len;

	/* Get TLV node */
	parse_tlv_node = lookup_tlv_node(type, parse_tlv_node->overlay_table);
	if (parse_tlv_node)
		goto parse_again;

	/* Unknown TLV overlay node */
	parse_tlv_node = parse_tlv_node->overlay_wildcard_node;
	if (parse_tlv_node)
		goto parse_again;

	return parse_tlv_node->unknown_overlay_ret;
}

static int panda_parse_tlvs(const struct panda_parse_node *parse_node,
			    const void *hdr, void *frame,
			    const struct panda_ctrl_data ctrl,
			    unsigned int flags)
{
	const struct panda_parse_tlvs_node *parse_tlvs_node;
	const struct panda_proto_tlvs_node *proto_tlvs_node;
	const struct panda_parse_tlv_node *parse_tlv_node;
	size_t off, len, offset = ctrl.hdr_offset;
	struct panda_ctrl_data tlv_ctrl;
	const __u8 *cp = hdr;
	ssize_t tlv_len;
	int type, ret;

	parse_tlvs_node = (struct panda_parse_tlvs_node *)parse_node;
	proto_tlvs_node = (struct panda_proto_tlvs_node *)
						parse_node->proto_node;

	/* Assume hlen marks end of TLVs */
	off = proto_tlvs_node->ops.start_offset(hdr);

	/* We assume start offset is less than or equal to minimal length */
	len = ctrl.hdr_len - off;

	cp += off;
	offset += off;

	while (len > 0) {
		if (proto_tlvs_node->pad1_enable &&
		   *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			offset++;
			len--;
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
			offset++;
			len--;

			/* Hit EOL, we're done */
			break;
		}

		if (len < proto_tlvs_node->min_len) {
			/* Length error */
			return PANDA_STOP_TLV_LENGTH;
		}

		/* If the len function is not set this degenerates to an
		 * array of fixed sized values (which maybe be useful in
		 * itself now that I think about it)
		 */
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

		tlv_ctrl.hdr_len = tlv_len;
		tlv_ctrl.hdr_offset = offset;

		type = proto_tlvs_node->ops.type(cp);

		/* Get TLV node */
		parse_tlv_node = lookup_tlv_node(type,
				parse_tlvs_node->tlv_proto_table);
		if (parse_tlv_node) {
parse_one_tlv:
			ret = panda_parse_one_tlv(parse_tlvs_node,
						  parse_tlv_node, cp, frame,
						  type, tlv_ctrl, flags);
			if (ret != PANDA_OKAY)
				return ret;
		} else {
			/* Unknown TLV */
			parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
			if (parse_tlv_node) {
				/* If a wilcard node is present parse that
				 * node as an overlay to this one. The
				 * wild card node can perform error processing
				 */
				goto parse_one_tlv;
			} else {
				/* Return default error code. Returning
				 * PANDA_OKAY means skip
				 */
				return parse_tlvs_node->unknown_tlv_type_ret;
			}
		}

		/* Move over current header */
		cp += tlv_len;
		offset += tlv_len;
		len -= tlv_len;
	}

	return PANDA_OKAY;
}

static int panda_parse_flag_fields(const struct panda_parse_node *parse_node,
				   const void *hdr, void *frame,
				   struct panda_ctrl_data ctrl,
				   unsigned int pflags)
{
	const struct panda_parse_flag_fields_node *parse_flag_fields_node;
	const struct panda_proto_flag_fields_node *proto_flag_fields_node;
	const struct panda_parse_flag_field_node *parse_flag_field_node;
	const struct panda_flag_fields *flag_fields;
	size_t offset = ctrl.hdr_offset, ioff;
	ssize_t off;
	__u32 flags;
	int i;

	parse_flag_fields_node =
			(struct panda_parse_flag_fields_node *)parse_node;
	proto_flag_fields_node =
			(struct panda_proto_flag_fields_node *)
						parse_node->proto_node;
	flag_fields = proto_flag_fields_node->flag_fields;

	flags = proto_flag_fields_node->ops.get_flags(hdr);

	/* Position at start of field data */
	ioff = proto_flag_fields_node->ops.start_fields_offset(hdr);
	hdr += ioff;
	offset += ioff;

	for (i = 0; i < flag_fields->num_idx; i++) {
		off = panda_flag_fields_offset(i, flags, flag_fields);
		if (off < 0)
			continue;

		/* Flag field is present, try to find in the parse node
		 * table based on index in proto flag-fields
		 */
		parse_flag_field_node = lookup_flag_field_node(i,
			parse_flag_fields_node->flag_fields_proto_table);
		if (parse_flag_field_node) {
			const struct panda_parse_flag_field_node_ops
				*ops = &parse_flag_field_node->ops;
			struct panda_ctrl_data flag_ctrl;
			const __u8 *cp = hdr + off;

			flag_ctrl.hdr_len = flag_fields->fields[i].size;
			flag_ctrl.hdr_offset = offset + off;

			if (pflags & PANDA_F_DEBUG)
				printf("PANDA parsing flag-field %s\n",
				      parse_flag_field_node->name);

			if (ops->extract_metadata)
				ops->extract_metadata(cp, frame, flag_ctrl);

			if (ops->handle_flag_field)
				ops->handle_flag_field(cp, frame, flag_ctrl);
		}
	}

	return PANDA_OKAY;
}

/* Parse a packet
 *
 * Arguments:
 *   - parser: Parser being invoked
 *   - node: start root node (may be different than parser->root_node)
 *   - hdr: pointer to start of packet
 *   - len: length of packet
 *   - metadata: metadata structure
 *   - start_node: first node (typically node_ether)
 *   - flags: allowed parameterized parsing
 */
int __panda_parse(const struct panda_parser *parser,
		  const struct panda_parse_node *parse_node, const void *hdr,
		  size_t len, struct panda_metadata *metadata,
		  unsigned int flags, unsigned int max_encaps)
{
	const struct panda_parse_node *next_parse_node;
	void *frame = metadata->frame_data;
	struct panda_ctrl_data ctrl;
	unsigned int frame_num = 0;
	const void *base_hdr = hdr;
	int type, ret;

	/* Main parsing loop. The loop normal teminates when we encounter a
	 * leaf protocol node, an error condition, hitting limit on layers of
	 * encapsulation, protocol condition to stop (i.e. flags that
	 * indicate to stop at flow label or hitting fragment), or
	 * unknown protocol result in table lookup for next node.
	 */

	do {
		const struct panda_proto_node *proto_node =
						parse_node->proto_node;
		ssize_t hlen = proto_node->min_len;

		/* Protocol node length checks */

		if (flags & PANDA_F_DEBUG)
			printf("PANDA parsing %s\n", proto_node->name);

		if (len < hlen)
			return PANDA_STOP_LENGTH;

		if (proto_node->ops.len) {
			hlen = proto_node->ops.len(hdr);
			if (len < hlen)
				return PANDA_STOP_LENGTH;

			if (hlen < proto_node->min_len)
				return hlen < 0 ? hlen : PANDA_STOP_LENGTH;
		} else {
			hlen = proto_node->min_len;
		}

		ctrl.hdr_len = hlen;
		ctrl.hdr_offset = hdr - base_hdr;

		/* Callback processing order
		 *    1) Extract Metadata
		 *    2) Process TLVs
		 *	2.a) Extract metadata from TLVs
		 *	2.b) Process TLVs
		 *    3) Process protocol
		 */

		/* Extract metadata, per node processing */

		if (parse_node->ops.extract_metadata)
			parse_node->ops.extract_metadata(hdr, frame, ctrl);

		switch (parse_node->node_type) {
		case PANDA_NODE_TYPE_PLAIN:
		default:
			break;
		case PANDA_NODE_TYPE_TLVS:
			/* Process TLV nodes */
			if (parse_node->proto_node->node_type ==
			    PANDA_NODE_TYPE_TLVS) {
				/* Need error in case parse_node is TLVs type
				 * but proto_node is not TLVs type
				 */
				ret = panda_parse_tlvs(parse_node, hdr, frame,
						       ctrl, flags);
				if (ret != PANDA_OKAY)
					return ret;
			}
			break;
		case PANDA_NODE_TYPE_FLAG_FIELDS:
			/* Process flag-fields */
			if (parse_node->proto_node->node_type ==
						PANDA_NODE_TYPE_FLAG_FIELDS) {
				/* Need error in case parse_node is flag-fields
				 * type but proto_node is not flag-fields type
				 */
				ret = panda_parse_flag_fields(parse_node, hdr,
							      frame, ctrl,
							      flags);
				if (ret != PANDA_OKAY)
					return ret;
			}
			break;
		}

		/* Process protocol */
		if (parse_node->ops.handle_proto)
			parse_node->ops.handle_proto(hdr, frame, ctrl);

		/* Proceed to next protocol layer */

		if (!parse_node->proto_table && !parse_node->wildcard_node) {
			/* Leaf parse node */

			return PANDA_STOP_OKAY;
		}

		if (proto_node->encap) {
			/* New encapsulation leyer. Check against
			 * number of encap layers allowed and also
			 * if we need a new metadata frame.
			 */
			if (++metadata->encaps > max_encaps)
				return PANDA_STOP_ENCAP_DEPTH;

			if (metadata->max_frame_num > frame_num) {
				frame += metadata->frame_size;
				frame_num++;
			}
		}

		if (proto_node->ops.next_proto && parse_node->proto_table) {
			/* Lookup next proto */

			type = proto_node->ops.next_proto(hdr);
			if (type < 0)
				return type;

			/* Get next node */
			next_parse_node = lookup_node(type,
						parse_node->proto_table);

			if (next_parse_node)
				goto found_next;
		}

		/* Try wildcard node. Either table lookup failed to find a node
		 * or there is only a wildcard
		 */
		if (parse_node->wildcard_node) {
			/* Perform default processing in a wildcard node */

			next_parse_node = parse_node->wildcard_node;
		} else {
			/* Return default code. Parsing will stop
			 * with the inidicated code
			 */

			return parse_node->unknown_ret;
		}

found_next:
		/* Found next protocol node, set up to process */

		if (!proto_node->overlay) {
			/* Move over current header */
			hdr += hlen;
			len -= hlen;
		}

		parse_node = next_parse_node;

	} while (1);
}

struct panda_parser *panda_parser_create(const char *name,
					 const struct panda_parse_node
								*root_node)
{
	struct panda_parser *parser;

	parser = calloc(1, sizeof(*parser));
	if (!parser)
		return NULL;

	parser->name = name;
	parser->root_node = root_node;

	return parser;
}

static
struct panda_parser *panda_parser_opt_create(const char *name,
				const struct panda_parse_node *root_node,
				panda_parser_opt_entry_point parser_entry_point)
{
	struct panda_parser *parser;

	parser = calloc(1, sizeof(*parser));
	if (!parser)
		return NULL;

	parser->name = name;
	parser->root_node = root_node;
	parser->parser_type = PANDA_OPTIMIZED;
	parser->parser_entry_point = parser_entry_point;

	return parser;
}

void panda_parser_destroy(struct panda_parser *parser)
{
	free(parser);
}

siphash_key_t __panda_hash_key;
void panda_hash_secret_init(siphash_key_t *init_key)
{
	if (init_key) {
		__panda_hash_key = *init_key;
	} else {
		__u8 *bytes = (__u8 *)&__panda_hash_key;
		int i;

		for (i = 0; i < sizeof(__panda_hash_key); i++)
			bytes[i] = rand();
	}
}

void panda_print_hash_input(const void *start, size_t len)
{
	const __u8 *data = start;
	int i;

	printf("Hash input (size %lu): ", len);
	for (i = 0; i < len; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

/* Create a dummy parser to ensure that the section is defined */
static struct panda_parser_def PANDA_SECTION_ATTR(panda_parsers) dummy_parser;

int panda_parser_init(void)
{
	const struct panda_parser_def *def_base =
					panda_section_base_panda_parsers();
	int i, j;

	for (i = 0; i < panda_section_array_size_panda_parsers(); i++) {
		const struct panda_parser_def *def = &def_base[i];

		if (!def->name && !def->root_node)
			continue;

		switch (def->parser_type) {
		case  PANDA_GENERIC:
			*def->parser = panda_parser_create(def->name,
							   def->root_node);
			if (!def->parser) {
				fprintf(stderr, "Create parser \"%s\" failed\n",
					def->name);
				goto fail;
			}
			break;
		case PANDA_OPTIMIZED:
			*def->parser = panda_parser_opt_create(def->name,
						def->root_node,
						def->parser_entry_point);
			if (!def->parser) {
				fprintf(stderr, "Create parser \"%s\" failed\n",
					def->name);
				goto fail;
			}
			break;
		default:
			goto fail;
		}
	}

	return 0;

fail:
	for (j = 0; j < i; j++) {
		const struct panda_parser_def *def = &def_base[i];

		panda_parser_destroy(*def->parser);
		*def->parser = NULL;
	}
	return -1;
}
