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

#ifndef __PANDA_TYPES_H__
#define __PANDA_TYPES_H__

/* Type definitions for PANDA parser */

#include <stddef.h>
#include <stdbool.h>

#include <linux/types.h>

#include "panda/compiler_helpers.h"

/* Panda parser type codes */
enum panda_parser_type {
	/* Use non-optimized loop panda parser algorithm */
	PANDA_GENERIC = 0,
	/* Use optimized, generated, parser algorithm  */
	PANDA_OPTIMIZED = 1,
	/* XDP parser */
	PANDA_XDP = 2,
	/* Kernel module parser */
	PANDA_KMOD = 3,
};

/* Parse and protocol node types */
enum panda_parser_node_type {
	/* Plain node, no super structure */
	PANDA_NODE_TYPE_PLAIN,
	/* TLVs node with super structure for TLVs */
	PANDA_NODE_TYPE_TLVS,
	/* Flag-fields with super structure for flag-fields */
	PANDA_NODE_TYPE_FLAG_FIELDS,
};

/* Protocol parsing operations:
 *
 * len: Return length of protocol header. If value is NULL then the length of
 *	the header is taken from the min_len in the protocol node. If the
 *	return value < 0 (a PANDA_STOP_* return code value) this indicates an
 *	error and parsing is stopped. A the return value greater than or equal
 *	to zero then gives the protocol length. If the returned length is less
 *	than the minimum protocol length, indicated in min_len by the protocol
 *	node, then this considered and error.
 * next_proto: Return next protocol. If value is NULL then there is no
 *	next protocol. If return value is greater than or equal to zero
 *	this indicates a protocol number that is used in a table lookup
 *	to get the next layer protocol node.
 */
struct panda_parse_ops {
	ssize_t (*len)(const void *hdr);
	int (*next_proto)(const void *hdr);
};

/* Protocol node
 *
 * This structure contains the definitions to describe parsing of one type
 * of protocol header. Fields are:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * encap: Indicates an encapsulation protocol (e.g. IPIP, GRE)
 * overlay: Indicates an overlay protocol. This is used, for example, to
 *	switch on version number of a protocol header (e.g. IP version number
 *	or GRE version number)
 * name: Text name of protocol node for debugging
 * min_len: Minimum length of the protocol header
 * ops: Operations to parse protocol header
 */
struct panda_proto_node {
	enum panda_parser_node_type node_type;
	__u8 encap;
	__u8 overlay;
	const char *name;
	size_t min_len;
	const struct panda_parse_ops ops;
};

/* Panda generic metadata
 *
 * Contains an array of parser specific (user defined) metadata structures.
 * Meta data structures are defined specifically for each parser. An
 * instance of this metadata is a frame. One frame is used for each
 * level of encapulation. When the number of encapsulation layers exceeds
 * max_num_frame then last frame is reused
 *	encaps: Number of encapsulation protocol encountered.
 *	max_frame_num: Maximum number of frames. One frame is used for each
 *		level of encapulation. When the number of encapsulation
 *		layers exceeds this value the last frame is reuse used
 *	frame_size: The size in bytes of each metadata frame
 *	frame_data: Contains max_frame_num metadata frames
 */
struct panda_metadata {
	unsigned int encaps;
	unsigned int max_frame_num;
	size_t frame_size;

	/* Application specific metadata frames */
	__u8 frame_data[0] __aligned(8);
};

struct panda_ctx {
	__u32 frame_num;
	__u32 next;
	__u32 offset;
	struct panda_metadata metadata;
};

struct panda_ctrl_data {
	size_t hdr_len;
	size_t hdr_offset;
};

/* Parse node operations
 *
 * Operations to process a parsing node
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_proto: Per protocol handler which allows arbitrary processing
 *	of a protocol layer. Input is the header data and a parser defined
 *	metadata structure for the current frame. Return value is a parser
 *	return code: PANDA_OKAY indicates no errors, PANDA_STOP* return
 *	values indicate to stop parsing
 */
struct panda_parse_node_ops {
	void (*extract_metadata)(const void *hdr, void *frame,
				 const struct panda_ctrl_data ctrl);
	int (*handle_proto)(const void *hdr, void *frame,
			    const struct panda_ctrl_data ctrl);
};

/* Protocol node and parse node operations ordering. When processing a
 * layer, operations are called in following order:
 *
 * protoop.len
 * parseop.extract_metadata
 * parseop.handle_proto
 * protoop.next_proto
 */

struct panda_parse_node;

/* One entry in a protocol table:
 *	value: protocol number
 *	node: associated parse node for the protocol number
 */
struct panda_proto_table_entry {
	int value;
	const struct panda_parse_node *node;
};

/* Protocol table
 *
 * Contains a protocol table that maps a protocol number to a parse
 * node
 */
struct panda_proto_table {
	int num_ents;
	const struct panda_proto_table_entry *entries;
};

/* Parse node definition. Defines parsing and processing for one node in
 * the parse graph of a parser. Contains:
 *
 * node_type: The type of the node (plain, TLVs, flag-fields)
 * proto_node: Protocol node
 * ops: Parse node operations
 * proto_table: Protocol table for next protocol. This must be non-null if
 * next_proto is not NULL
 */
struct panda_parse_node {
	enum panda_parser_node_type node_type;
	int unknown_ret;
	const struct panda_proto_node *proto_node;
	const struct panda_parse_node_ops ops;
	const struct panda_proto_table *proto_table;
	const struct panda_parse_node *wildcard_node;
};

/* Declaration of a PANDA parser */
struct panda_parser;

/* Panda entry-point for optimized parsers */
typedef int (*panda_parser_opt_entry_point)(const struct panda_parser *parser,
					    const void *hdr, size_t len,
					    struct panda_metadata *metadata,
					    unsigned int flags,
					    unsigned int max_encaps);

/* Panda entry-point for XDP parsers */
typedef int (*panda_parser_xdp_entry_point)(struct panda_ctx *ctx,
					    const void **hdr,
					    const void *hdr_end,
					    bool tailcall);

/* Definition of a PANDA parser. Fields are:
 *
 * name: Text name for the parser
 * root_node: Root parse node of the parser. When the parser is invoked
 *	parsing commences at this parse node
 */
struct panda_parser {
	const char *name;
	const struct panda_parse_node *root_node;
	enum panda_parser_type parser_type;
	panda_parser_opt_entry_point parser_entry_point;
	panda_parser_xdp_entry_point parser_xdp_entry_point;
};

/* One entry in a parser table:
 *	value: key vlaue
 *	parser: parser associated with the key value
 */
struct panda_parser_table_entry {
	int value;
	struct panda_parser **parser;
};

/* Parser table
 *
 * Contains a parser table that maps a key value, which could be a protocol
 * number, to a parser
 */
struct panda_parser_table {
	int num_ents;
	const struct panda_parser_table_entry *entries;
};

#endif /* __PANDA_TYPES_H__ */
