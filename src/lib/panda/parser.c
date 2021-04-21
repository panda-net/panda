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


static int panda_parse_tlvs(const struct panda_parse_node *parse_node,
			    const void *hdr, void *frame, size_t hlen)
{
	const struct panda_parse_tlvs_node *parse_tlvs_node;
	const struct panda_proto_tlvs_node *proto_tlvs_node;
	const struct panda_parse_tlv_node *parse_tlv_node;
	const __u8 *cp = hdr;
	size_t offset, len;
	ssize_t tlv_len;
	int type;

	parse_tlvs_node = (struct panda_parse_tlvs_node *)parse_node;
	proto_tlvs_node = (struct panda_proto_tlvs_node *)
						parse_node->proto_node;

	/* Assume hlen marks end of TLVs */
	offset = proto_tlvs_node->ops.start_offset(hdr);

	/* We assume start offset is less than or equal to minimal length */
	len = hlen - offset;

	cp += offset;

	while (len > 0) {
		if (proto_tlvs_node->pad1_enable &&
		   *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			len--;
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
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

		type = proto_tlvs_node->ops.type(cp);

		/* Get TLV node */
		parse_tlv_node = lookup_tlv_node(type,
				parse_tlvs_node->tlv_proto_table);
		if (parse_tlv_node) {
			const struct panda_parse_tlv_node_ops *ops =
						&parse_tlv_node->tlv_ops;

			if (ops->check_length) {
				int ret = ops->check_length(cp, frame);

				if (ret != PANDA_OKAY) {
					if (!parse_tlvs_node->ops.unknown_type)
						goto next_tlv;

					ret = parse_tlvs_node->ops.unknown_type(
							hdr, frame, type, ret);

					if (ret == PANDA_OKAY)
						goto next_tlv;
				}
			}

			if (ops->extract_metadata)
				ops->extract_metadata(cp, frame);

			if (ops->handle_tlv)
				ops->handle_tlv(cp, frame);
		} else {
			int ret;

			/* Unknown TLV */

			if (parse_tlvs_node->ops.unknown_type)
				goto next_tlv;

			ret = parse_tlvs_node->ops.unknown_type(hdr, frame,
						type, PANDA_STOP_UNKNOWN_TLV);
			if (ret != PANDA_OKAY)
				return ret;
		}

next_tlv:
		/* Move over current header */
		cp += tlv_len;
		len -= tlv_len;
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
	unsigned int frame_num = 0;
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

		/* Callback processing order
		 *    1) Extract Metadata
		 *    2) Process TLVs
		 *	2.a) Extract metadata from TLVs
		 *	2.b) Process TLVs
		 *    3) Process protocol
		 */

		/* Extract metadata, per node processing */

		if (parse_node->ops.extract_metadata)
			parse_node->ops.extract_metadata(hdr, frame);

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
						       hlen);
				if (ret != PANDA_OKAY)
					return ret;
			}
			break;
		}

		/* Process protocol */
		if (parse_node->ops.handle_proto)
			parse_node->ops.handle_proto(hdr, frame);

		/* Proceed to next protocol layer */

		if (!proto_node->ops.next_proto)
			return PANDA_STOP_OKAY;

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

		/* Lookup next proto */

		type = proto_node->ops.next_proto(hdr);
		if (type < 0)
			return type;

		assert(parse_node->proto_table);

		/* Get next node */
		next_parse_node = lookup_node(type, parse_node->proto_table);
		if (!next_parse_node) {
			/* Unknown protocol */

			if (parse_node->ops.unknown_next_proto)
				return parse_node->ops.unknown_next_proto(
						hdr, frame, type,
						PANDA_STOP_UNKNOWN_PROTO);
			else
				return PANDA_STOP_UNKNOWN_PROTO;
		}

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
