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

#ifndef __PANDA_TLV_H__
#define __PANDA_TLV_H__

/* Definitions and functions for processing and parsing TLVs */

#ifndef __KERNEL__
#include <stddef.h>
#include <sys/types.h>
#endif

#include <linux/types.h>

#include "panda/parser_types.h"

/* Definitions for parsing TLVs
 *
 * TLVs are a common protocol header structure consisting of Type, Length,
 * Value tuple (e.g. for handling TCP or IPv6 HBH options TLVs)
 */

/* Descriptor for parsing operations of one type of TLV. Fields are:
 *
 * len: Return length of a TLV. Must be set. If the return value < 0 (a
 *	PANDA_STOP_* return code value) this indicates an error and parsing
 *	is stopped. A the return value greater than or equal to zero then
 *	gives the protocol length. If the returned length is less than the
 *	minimum TLV option length, indicated by min_len by the TLV protocol
 *	node, then this considered and error.
 * type: Return the type of the TLV. If the return value is less than zero
 *	(PANDA_STOP_* value) then this indicates and error and parsing stops
 */
struct panda_proto_tlvs_opts {
	size_t (*start_offset)(const void *hdr);
	ssize_t (*len)(const void *hdr);
	int (*type)(const void *hdr);
};

/* TLV parse node operations
 *
 * Operations to process a sigle TLV parsenode
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_tlv: Per TLV type handler which allows arbitrary processing
 *	of a TLV. Input is the TLV data and a parser defined metadata
 *	structure for the current frame. Return value is a parser
 *	return code: PANDA_OKAY indicates no errors, PANDA_STOP* return
 *	values indicate to stop parsing
 */
struct panda_parse_tlv_node_ops {
	void (*extract_metadata)(const void *hdr, void *frame,
				 const struct panda_ctrl_data ctrl);
	int (*handle_tlv)(const void *hdr, void *frame,
			  const struct panda_ctrl_data ctrl);
	int (*overlay_type)(const void *hdr);
};

/* Parse node for a single TLV. Use common parse node operations
 * (extract_metadata and handle_proto)
 */
struct panda_parse_tlv_node {
	const struct panda_proto_tlv_node *proto_tlv_node;
	const struct panda_parse_tlv_node_ops tlv_ops;
	const struct panda_proto_tlvs_table *overlay_table;
	const struct panda_parse_tlv_node *overlay_wildcard_node;
	int unknown_overlay_ret;
	const char *name;
};

/* One entry in a TLV table:
 *	value: TLV type
 *	node: associated TLV parse structure for the type
 */
struct panda_proto_tlvs_table_entry {
	int type;
	const struct panda_parse_tlv_node *node;
};

/* TLV table
 *
 * Contains a table that maps a TLV type to a TLV parse node
 */
struct panda_proto_tlvs_table {
	int num_ents;
	const struct panda_proto_tlvs_table_entry *entries;
};

/* Parse node for parsing a protocol header that contains TLVs to be
 * parser:
 *
 * parse_node: Node for main protocol header (e.g. IPv6 node in case of HBH
 *	options) Note that node_type is set in parse_node to
 *	PANDA_NODE_TYPE_TLVS and that the parse node can then be cast to a
 *	parse_tlv_node
 * tlv_proto_table: Lookup table for TLV type
 * max_tlvs: Maximum number of TLVs that are to be parseed in one list
 * max_tlv_len: Maximum length allowed for any TLV in a list
 *	one type of TLVS.
 */
struct panda_parse_tlvs_node {
	const struct panda_parse_node parse_node;
	const struct panda_proto_tlvs_table *tlv_proto_table;
	size_t max_tlvs;
	size_t max_tlv_len;
	int unknown_tlv_type_ret;
	const struct panda_parse_tlv_node *tlv_wildcard_node;
};

/* A protocol node for parsing proto with TLVs
 *
 * proto_node: proto node
 * ops: Operations for parsing TLVs
 * pad1_val: Type value indicating one byte of TLV padding (e.g. would be
 *	for IPv6 HBH TLVs)
 * pad1_enable: Pad1 value is used to detect single byte padding
 * eol_val: Type value that indicates end of TLV list
 * eol_enable: End of list value in eol_val is used
 * start_offset: When there TLVs start relative the enapsulating protocol
 *	(e.g. would be twenty for TCP)
 * min_len: Minimal length of a TLV option
 */
struct panda_proto_tlvs_node {
	struct panda_proto_node proto_node;
	struct panda_proto_tlvs_opts ops;
	__u8 pad1_val;
	__u8 eol_val;
	__u8 pad1_enable;
	__u8 eol_enable;
	size_t min_len;
};

/* A protocol node for parsing proto with TLVs
 *
 * min_len: Minimal length of TLV
 */
struct panda_proto_tlv_node {
	size_t min_len;
};

/* Look up a TLV parse node given
 *
 * Arguments:
 *	- node: A TLVs parse node containing lookup table
 *	- type: TLV type to lookup
 *
 * Returns pointer to parse node if the protocol is matched else returns
 * NULL if the parse node isn't found
 */
const struct panda_parse_tlv_node *panda_parse_lookup_tlv(
				const struct panda_parse_tlvs_node *node,
				unsigned int type);

/* Helper to create a TLV protocol table */
#define PANDA_MAKE_TLV_TABLE(NAME, ...)					\
	static const struct panda_proto_tlvs_table_entry __##NAME[] =	\
						{ __VA_ARGS__ };	\
	static const struct panda_proto_tlvs_table NAME = {		\
		.num_ents = sizeof(__##NAME) /				\
			sizeof(struct panda_proto_tlvs_table_entry),	\
		.entries = __##NAME,					\
	}

/* Forward declarations for TLV parser nodes */
#define PANDA_DECL_TLVS_PARSE_NODE(TLVS_PARSE_NODE)			\
	static const struct panda_parse_tlvs_node TLVS_PARSE_NODE

/* Forward declarations for TLV type tables */
#define PANDA_DECL_TLVS_TABLE(TLVS_TABLE)				\
	static const struct panda_proto_tlvs_table TLVS_TABLE

/* Helper to create a parse node with a next protocol table */
#define __PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				     EXTRACT_METADATA, HANDLER,		\
				     UNKNOWN_RET, WILDCARD_NODE,	\
				     UNKNOWN_TLV_TYPE_RET,		\
				     TLV_WILDCARD_NODE,			\
				     PROTO_TABLE, TLV_TABLE)		\
	static const struct panda_parse_tlvs_node PARSE_TLV_NODE = {	\
		.parse_node.node_type = PANDA_NODE_TYPE_TLVS,		\
		.parse_node.proto_node = &PROTO_TLV_NODE.proto_node,	\
		.parse_node.ops.extract_metadata = EXTRACT_METADATA,	\
		.parse_node.ops.handle_proto = HANDLER,			\
		.parse_node.unknown_ret = UNKNOWN_RET,			\
		.parse_node.wildcard_node = WILDCARD_NODE,		\
		.parse_node.proto_table = PROTO_TABLE,			\
		.tlv_proto_table = TLV_TABLE,				\
		.unknown_tlv_type_ret = UNKNOWN_TLV_TYPE_RET,		\
		.tlv_wildcard_node = TLV_WILDCARD_NODE,			\
	}

/* Helper to create a TLVs parse node with default unknown next proto
 * function that returns parse failure code and default unknown TLV
 * function that ignores unknown TLVs
 */
#define PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				   EXTRACT_METADATA, HANDLER,		\
				   PROTO_TABLE, TLV_TABLE)		\
	PANDA_DECL_TLVS_TABLE(TLV_TABLE);				\
	PANDA_DECL_PROTO_TABLE(PROTO_TABLE)				\
	__PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE,			\
				    (PROTO_NODE).pnode,			\
				    EXTRACT_METADATA, HANDLER,		\
				    PANDA_STOP_UNKNOWN_PROTO, NULL,	\
				    PANDA_OKAY, NULL,			\
				    &PROTO_TABLE, &TLV_TABLE)

/* Helper to create a TLVs parse node with default unknown next proto
 * function that returns parse failure code and default unknown TLV
 * function that ignores unknown TLVs
 */
#define PANDA_MAKE_TLVS_OVERLAY_PARSE_NODE(PARSE_TLV_NODE,		\
					   PROTO_TLV_NODE,		\
					   EXTRACT_METADATA, HANDLER,	\
					   OVERLAY_NODE, TLV_TABLE)	\
	PANDA_DECL_TLVS_TABLE(TLV_TABLE);				\
	__PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE,			\
				    (PROTO_NODE).pnode,			\
				    EXTRACT_METADATA, HANDLER,		\
				    PANDA_STOP_UNKNOWN_PROTO,		\
				    OVERLAY_NODE, PANDA_OKAY, NULL,	\
				    &PROTO_TABLE, &TLV_TABLE)

/* Helper to create a leaf TLVs parse node with default unknown TLV
 * function that ignores unknown TLVs
 */
#define PANDA_MAKE_LEAF_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
					EXTRACT_METADATA, HANDLER,	\
					TLV_TABLE)			\
	PANDA_DECL_TLVS_TABLE(TLV_TABLE);				\
	__PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				     EXTRACT_METADATA, HANDLER,		\
				     PANDA_STOP_UNKNOWN_PROTO, NULL,	\
				     PANDA_OKAY, NULL,			\
				     NULL, &TLV_TABLE)

#define PANDA_MAKE_TLV_PARSE_NODE(NODE_NAME, PROTO_TLV_NODE,		\
				  METADATA_FUNC, HANDLER_FUNC)		\
	static const struct panda_parse_tlv_node NODE_NAME = {		\
		.proto_tlv_node = &PROTO_TLV_NODE,			\
		.tlv_ops.extract_metadata = METADATA_FUNC,		\
		.tlv_ops.handle_tlv = HANDLER_FUNC,			\
		.name = #NODE_NAME,					\
	}

#define PANDA_MAKE_TLV_OVERLAY_PARSE_NODE(NODE_NAME,			\
					  METADATA_FUNC, HANDLER_FUNC,	\
					  OVERLAY_TABLE,		\
					  OVERLAY_TYPE_FUNC,		\
					  UNKNOWN_OVERLAY_RET,		\
					  OVERLAY_WILDCARD_NODE)	\
	PANDA_DECL_TLVS_TABLE(OVERLAY_TABLE);				\
	static const struct panda_parse_tlv_node NODE_NAME = {		\
		.tlv_ops.extract_metadata = METADATA_FUNC,		\
		.tlv_ops.handle_tlv = HANDLER_FUNC,			\
		.tlv_ops.overlay_type = OVERLAY_TYPE_FUNC,		\
		.unknown_overlay_ret = UNKNOWN_OVERLAY_RET,		\
		.overlay_wildcard_node = OVERLAY_WILDCARD_NODE,		\
		.overlay_table = &OVERLAY_TABLE,			\
		.name = #NODE_NAME,					\
	}

#endif /* __PANDA_TLV_H__ */
