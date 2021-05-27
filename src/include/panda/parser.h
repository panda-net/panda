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

#ifndef __PANDA_PARSER_H__
#define __PANDA_PARSER_H__

/* Parser interface for PANDA
 *
 * Definitions and functions for PANDA parser.
 */

#include <linux/ipv6.h>
#include <linux/types.h>
#include <string.h>
#include <unistd.h>

#include "panda/utility.h"
#include "siphash/siphash.h"

/* Panda parser return codes */
enum {
	PANDA_OKAY = 0,			/* Okay and continue */
	PANDA_STOP_OKAY = -1,		/* Okay and stop parsing */

	/* Parser failure */
	PANDA_STOP_FAIL = -2,
	PANDA_STOP_LENGTH = -3,
	PANDA_STOP_UNKNOWN_PROTO = -4,
	PANDA_STOP_ENCAP_DEPTH = -5,
	PANDA_STOP_UNKNOWN_TLV = -6,
	PANDA_STOP_TLV_LENGTH = -7,
	PANDA_STOP_BAD_FLAG = -8,
};

/* Panda parser type codes */
enum panda_parser_type {
	/* Use non-optimized loop panda parser algorithm */
	PANDA_GENERIC = 0,
	/* Use optimized, generated, parser algorithm  */
	PANDA_OPTIMIZED = 1,
	/* XDP parser */
	PANDA_XDP = 2,
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
	char *name;
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
	int (*unknown_next_proto)(const void *hdr, void *frame, int type,
				  int err);
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
	const struct panda_proto_node *proto_node;
	const struct panda_parse_node_ops ops;
	const struct panda_proto_table *proto_table;
};

/* Declaration of a PANDA parser */
struct panda_parser;

/* Panda entry-point for optimized parsers */
typedef int (*panda_parser_opt_entry_point)(const struct panda_parser *parser,
					    const struct panda_parse_node
								*parse_node,
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

/* Helper to create a parser */
#define __PANDA_PARSER(PARSER, NAME, ROOT_NODE)				\
static const struct panda_parser __##PARSER = {				\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_GENERIC,					\
	.parser_entry_point = NULL					\
};									\

#define PANDA_PARSER(PARSER, NAME, ROOT_NODE)				\
	__PANDA_PARSER(PARSER, NAME, ROOT_NODE)				\
	static const struct panda_parser *PARSER __unused() =		\
							&__##PARSER;

#define PANDA_PARSER_EXT(PARSER, NAME, ROOT_NODE)			\
	__PANDA_PARSER(PARSER, NAME, ROOT_NODE)				\
	const struct panda_parser *PARSER __unused() = &__##PARSER;

/* Helper to create an optimized parser vairant */
#define __PANDA_PARSER_OPT(PARSER, NAME, ROOT_NODE, FUNC)		\
static const struct panda_parser __##PARSER = {				\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_OPTIMIZED,					\
	.parser_entry_point = &FUNC					\
};

#define PANDA_PARSER_OPT(PARSER, NAME, ROOT_NODE, FUNC)			\
	__PANDA_PARSER_OPT(PARSER, NAME, ROOT_NODE, FUNC)		\
	static const struct panda_parser *PARSER __unused() =		\
							&__##PARSER;

#define PANDA_PARSER_OPT_EXT(PARSER, NAME, ROOT_NODE, FUNC)		\
	__PANDA_PARSER_OPT(PARSER, NAME, ROOT_NODE, FUNC)		\
	const struct panda_parser *PARSER __unused() = &__##PARSER;

/* Helper to create an XDP parser vairant */
#define __PANDA_PARSER_XDP(PARSER, NAME, ROOT_NODE, FUNC)		\
static const struct panda_parser __##PARSER = {				\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_XDP,					\
	.parser_xdp_entry_point = &FUNC					\
};

#define PANDA_PARSER_XDP(PARSER, NAME, ROOT_NODE, FUNC)			\
	__PANDA_PARSER_XDP(PARSER, NAME, ROOT_NODE, FUNC)		\
	static const struct panda_parser *__##PARSER##_ext =		\
							&__##PARSER;

#define PANDA_PARSER_XDP_EXT(PARSER, NAME, ROOT_NODE, FUNC)		\
	__PANDA_PARSER_XDP(PARSER, NAME, ROOT_NODE, FUNC)		\
	const struct panda_parser *__##PARSER##_ext = &__##PARSER;

/* Helper to create a protocol table */
#define PANDA_MAKE_PROTO_TABLE(NAME, ...)				\
	static const struct panda_proto_table_entry __##NAME[] =	\
						{ __VA_ARGS__ };	\
	static const struct panda_proto_table NAME =	{		\
		.num_ents = sizeof(__##NAME) /				\
				sizeof(struct panda_proto_table_entry),	\
		.entries = __##NAME,					\
	}

/* Forward declarations for parse nodes */
#define PANDA_DECL_PARSE_NODE(PARSE_NODE)				\
	static const struct panda_parse_node PARSE_NODE

/* Forward declarations for protocol tables */
#define PANDA_DECL_PROTO_TABLE(PROTO_TABLE)				\
	static const struct panda_proto_table PROTO_TABLE

/* Helper to create a parse node with a next protocol table */
#define __PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
				EXTRACT_METADATA, HANDLER,		\
				UNKNOWN_NEXT_PROTO, PROTO_TABLE)	\
	static const struct panda_parse_node PARSE_NODE = {		\
		.proto_node = &PROTO_NODE,				\
		.ops.extract_metadata = EXTRACT_METADATA,		\
		.ops.handle_proto = HANDLER,				\
		.ops.unknown_next_proto = UNKNOWN_NEXT_PROTO,		\
		.proto_table = PROTO_TABLE,				\
	}

/* Helper to create a parse node with default unknown next proto function
 * that returns parser failure code
 */
#define PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
			      EXTRACT_METADATA, HANDLER, PROTO_TABLE)	\
	PANDA_DECL_PROTO_TABLE(PROTO_TABLE);				\
	__PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
				EXTRACT_METADATA, HANDLER,		\
				panda_unknown_next_proto_fail,		\
				&PROTO_TABLE)

/* Helper to create a leaf parse node with no next protocol table */
#define PANDA_MAKE_LEAF_PARSE_NODE(PARSE_NODE, PROTO_NODE,		\
				   EXTRACT_METADATA, HANDLER)		\
	__PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
				EXTRACT_METADATA, HANDLER,		\
				panda_unknown_next_proto_fail, NULL)

/* Definitions for parsing flag-fields
 *
 * Flag-fields is a common networking protocol construct that encodes optional
 * data in a set of flags and data fields. The flags indicate whether or not a
 * corresponding data field is present. The data fields are fixed length per
 * each flag-field definition and ordered by the ordering of the flags
 * indicating the presence of the fields (e.g. GRE and GUE employ flag-fields)
 */

/* Flag-fields descriptors and tables
 *
 * A set of flag-fields is defined in a table of type struct panda_flag_fields.
 * Each entry in the table is a descriptor for one flag-field in a protocol and
 * includes a flag value, mask (for the case of a multi-bit flag), and size of
 * the cooresponding field. A flag is matched if "(flags & mask) == flag"
 */

/* One descriptor for a flag
 *
 * flag: protocol value
 * mask: mask to apply to field
 * size: size for associated field data
 */
struct panda_flag_field {
	__u32 flag;
	__u32 mask;
	size_t size;
};

/* Descriptor for a protocol field with flag fields
 *
 * Defines the flags and their data fields for one instance a flag field in
 * in a protocol header (e.g. GRE v0 flags):
 *
 * num_idx: Number of flag_field structures
 * fields: List of defined flag fields
 */
struct panda_flag_fields {
	size_t num_idx;
	struct panda_flag_field fields[];
};

/* Compute the length of optional fields present in a flags field */
static inline size_t panda_flag_fields_length(__u32 flags,
					      const struct panda_flag_fields
							*flag_fields)
{
	size_t len = 0;
	__u32 mask;
	int i;

	for (i = 0; i < flag_fields->num_idx; i++) {
		mask = flag_fields->fields[i].mask ? :
						flag_fields->fields[i].flag;

		if ((flags & mask) == flag_fields->fields[i].flag)
			len += flag_fields->fields[i].size;
	}

	return len;
}

static inline ssize_t __panda_flag_fields_offset(__u32 targ_idx, __u32 flags,
						 const struct panda_flag_fields
							*flag_fields)
{
	size_t offset = 0;
	__u32 mask;
	int i;

	for (i = 0; i < targ_idx; i++) {
		mask = flag_fields->fields[i].mask ? :
						flag_fields->fields[i].flag;

		if ((flags & mask) == flag_fields->fields[i].flag)
			offset += flag_fields->fields[i].size;
	}

	return offset;
}

/* Determine offset of a field given a set of flags */
static inline ssize_t panda_flag_fields_offset(__u32 targ_idx, __u32 flags,
					       const struct panda_flag_fields
							*flag_fields)
{
	__u32 mask;

	mask = flag_fields->fields[targ_idx].mask ? :
				flag_fields->fields[targ_idx].flag;
	if ((flags & mask) != flag_fields->fields[targ_idx].flag) {
		/* Flag not set */
		return -1;
	}

	return __panda_flag_fields_offset(targ_idx, flags, flag_fields);
}

/* Check flags are legal */
static inline bool panda_flag_fields_check_invalid(__u32 flags, __u32 mask)
{
	return !!(flags & ~mask);
}

/* Retrieve a byte value from a flag field */
static inline __u8 panda_flag_fields_get8(const __u8 *fields, __u32 targ_idx,
					  __u32 flags,
					  const struct panda_flag_fields
							*flag_fields)
{
	ssize_t offset = panda_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u8 *)&fields[offset];
}

/* Retrieve a short value from a flag field */
static inline __u16 panda_flag_fields_get16(const __u8 *fields,
					    __u32 targ_idx,
					    __u32 flags,
					    const struct panda_flag_fields
							*flag_fields)
{
	ssize_t offset = panda_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u16 *)&fields[offset];
}

/* Retrieve a 32 bit value from a flag field */
static inline __u32 panda_get_flag_field32(const __u8 *fields, __u32 targ_idx,
					   __u32 flags,
					   const struct panda_flag_fields
							*flag_fields)
{
	ssize_t offset = panda_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u32 *)&fields[offset];
}

/* Retrieve a 64 bit value from a flag field */
static inline __u64 panda_get_flag_field64(const __u8 *fields, __u32 targ_idx,
					   __u32 flags,
					   const struct panda_flag_fields
							*flag_fields)
{
	ssize_t offset = panda_flag_fields_offset(targ_idx, flags, flag_fields);

	if (offset < 0)
		return 0;

	return *(__u64 *)&fields[offset];
}


/* Structure or parsing operations for flag-fields
 *
 * flags_offset: Offset of flags in the protocol header
 * start_fields_offset: Return the offset in the header of the start of the
 *	flag fields data
 */
struct panda_proto_flag_fields_ops {
	__u32 (*get_flags)(const void *hdr);
	size_t (*start_fields_offset)(const void *hdr);
};

/* Flag-field parse node operations
 *
 * Operations to process a single flag-field
 *
 * extract_metadata: Extract metadata for the node. Input is the meta
 *	data frame which points to a parser defined metadata structure.
 *	If the value is NULL then no metadata is extracted
 * handle_flag_field: Per flag-field handler which allows arbitrary processing
 *	of a flag-field. Input is the flag-field data and a parser defined
 *	metadata structure for the current frame. Return value is a parser
 *	return code: PANDA_OKAY indicates no errors, PANDA_STOP* return
 *	values indicate to stop parsing
 */
struct panda_parse_flag_field_node_ops {
	void (*extract_metadata)(const void *hdr, void *frame,
				 struct panda_ctrl_data ctrl);
	int (*handle_flag_field)(const void *hdr, void *frame,
				 struct panda_ctrl_data ctrl);
};

/* A parse node for a single flag field */
struct panda_parse_flag_field_node {
	const struct panda_parse_flag_field_node_ops ops;
};

/* One entry in a flag-fields protocol table:
 *	index: flag-field index (index in a flag-fields table)
 *	node: associated TLV parse structure for the type
 */
struct panda_proto_flag_fields_table_entry {
	int index;
	const struct panda_parse_flag_field_node *node;
};

/* Flag-fields table
 *
 * Contains a table that maps a flag-field index to a flag-field parse node.
 * Note that the index correlates to an entry in a flag-fields table that
 * describes the flag-fields of a protocol
 */
struct panda_proto_flag_fields_table {
	int num_ents;
	const struct panda_proto_flag_fields_table_entry *entries;
};

/* Flag-fields specific operations for flag-fields parse node */
struct panda_parse_flag_fields_ops {
	int (*post_flag_fields_handle_proto)(const void *hdr, void *frame,
					     size_t len);
};

/* A flag-fields parse node. Note this is a super structure for a PANDA parse
 * node and tyoe is PANDA_NODE_TYPE_FLAG_FIELDS
 */
struct panda_parse_flag_fields_node {
	const struct panda_parse_node parse_node;
	const struct panda_parse_flag_fields_ops ops;
	const struct panda_proto_flag_fields_table *flag_fields_proto_table;
};

/* A flag-fields protocol node. Note this is a super structure for a PANDA
 * protocol node and tyoe is PANDA_NODE_TYPE_FLAG_FIELDS
 */
struct panda_proto_flag_fields_node {
	struct panda_proto_node proto_node;
	struct panda_proto_flag_fields_ops ops;
	const struct panda_flag_fields *flag_fields;
};

/* Helper to create a flag-fields protocol table */
#define PANDA_MAKE_FLAG_FIELDS_TABLE(NAME, ...)				\
	static const struct panda_proto_flag_fields_table_entry		\
					__##NAME[] =  { __VA_ARGS__ };	\
	static const struct panda_proto_flag_fields_table NAME = {	\
		.num_ents = sizeof(__##NAME) /				\
			sizeof(struct					\
				panda_proto_flag_fields_table_entry),	\
		.entries = __##NAME,					\
	}

/* Forward declarations for flag-fields parse nodes */
#define PANDA_DECL_FLAG_FIELDS_PARSE_NODE(FLAG_FIELDS_PARSE_NODE)	\
	static const struct panda_parse_flag_fields_node		\
						FLAG_FIELDS_PARSE_NODE

/* Forward declarations for flag-field proto tables */
#define PANDA_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE)			\
	static const struct panda_proto_flag_fields_table		\
						FLAG_FIELDS_TABLE


/* Helper to create a parse node with a next protocol table */
#define __PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    PROTO_TABLE,		\
					    FLAG_FIELDS_TABLE,		\
					    POST_FLAG_FIELDS_HANDLER)	\
	static const struct panda_parse_flag_fields_node		\
					PARSE_FLAG_FIELDS_NODE = {	\
		.flag_fields_proto_table = FLAG_FIELDS_TABLE,		\
		.parse_node.node_type = PANDA_NODE_TYPE_FLAG_FIELDS,	\
		.parse_node.proto_node =				\
				&PROTO_FLAG_FIELDS_NODE.proto_node,	\
		.parse_node.ops.extract_metadata = EXTRACT_METADATA,	\
		.parse_node.ops.handle_proto = HANDLER,			\
		.parse_node.proto_table = PROTO_TABLE,			\
		.ops.post_flag_fields_handle_proto =			\
					POST_FLAG_FIELDS_HANDLER,	\
	}

/* Helper to create a flag-fields parse node */
#define PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					  PROTO_FLAG_FIELDS_NODE,	\
					  EXTRACT_METADATA, HANDLER,	\
					  PROTO_TABLE,			\
					  FLAG_FIELDS_TABLE,		\
					  POST_FLAG_FIELDS_HANDLER)	\
	PANDA_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE);		\
	PANDA_DECL_PROTO_TABLE(PROTO_TABLE);				\
	__PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    &PROTO_TABLE,		\
					    &FLAG_FIELDS_TABLE,		\
					    POST_FLAG_FIELDS_HANDLER)

/* Helper to create a leaf flag-fields parse node */
#define PANDA_MAKE_LEAF_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					       PROTO_FLAG_FIELDS_NODE,	\
					       EXTRACT_METADATA,	\
					       HANDLER,			\
					       FLAG_FIELDS_TABLE,	\
					       POST_FLAG_FIELDS_HANDLER)\
	PANDA_DECL_FLAG_FIELDS_TABLE(FLAG_FIELDS_TABLE);		\
	__PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(PARSE_FLAG_FIELDS_NODE,	\
					    PROTO_FLAG_FIELDS_NODE,	\
					    EXTRACT_METADATA, HANDLER,	\
					    NULL, &FLAG_FIELDS_TABLE)

/* Helper to create a parse node for a single flag-field */
#define PANDA_MAKE_FLAG_FIELD_PARSE_NODE(NODE_NAME, METADATA_FUNC,	\
					 HANDLER_FUNC)			\
	static const struct panda_parse_flag_field_node NODE_NAME = {	\
		.ops.extract_metadata = METADATA_FUNC,			\
		.ops.handle_flag_field = HANDLER_FUNC,			\
	}

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
 * data_offset: Return the offset of the data in a TLV
 */
struct panda_proto_tlvs_opts {
	size_t (*start_offset)(const void *hdr);
	ssize_t (*len)(const void *hdr);
	int (*type)(const void *hdr);
	size_t (*data_offset)(const void *hdr);
};

/* TLV parse node operations
 *
 * Operations to process a sigle TLV parsenode
 *
 * check_length: Check the length of a TLV is appropriate for the type (may
 *	also perform other validations for proper format)
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
	int (*check_length)(const void *hdr, void *frame);
	void (*extract_metadata)(const void *hdr, void *frame,
				 const struct panda_ctrl_data ctrl);
	int (*handle_tlv)(const void *hdr, void *frame,
			  const struct panda_ctrl_data ctrl);
	int (*overlay_type)(const void *hdr);
	int (*unknown_overlay_type)(const void *hdr, void *frame, int type);
};

/* Parse node for a single TLV. Use common parse node operations
 * (extract_metadata and handle_proto)
 */
struct panda_parse_tlv_node {
	const struct panda_parse_tlv_node_ops tlv_ops;
	const struct panda_proto_tlvs_table *overlay_table;
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

/* TLV specific operations for TLVs parse node */
struct panda_parse_tlvs_ops {
	int (*post_tlv_handle_proto)(const void *hdr, void *frame,
				     struct panda_ctrl_data ctrl);
	int (*unknown_type)(const void *hdr, void *frame, int type,
			    int err);
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
	const struct panda_parse_tlvs_ops ops;
	const struct panda_proto_tlvs_table *tlv_proto_table;
	size_t max_tlvs;
	size_t max_tlv_len;
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
				     UNKNOWN_NEXT_PROTO,		\
				     UNKNOWN_TLV_TYPE,			\
				     POST_TLV_HANDLER,			\
				     PROTO_TABLE, TLV_TABLE)		\
	static const struct panda_parse_tlvs_node PARSE_TLV_NODE = {	\
		.parse_node.node_type = PANDA_NODE_TYPE_TLVS,		\
		.parse_node.proto_node = &PROTO_TLV_NODE.proto_node,	\
		.parse_node.ops.extract_metadata = EXTRACT_METADATA,	\
		.parse_node.ops.handle_proto = HANDLER,			\
		.parse_node.ops.unknown_next_proto = UNKNOWN_NEXT_PROTO,\
		.parse_node.proto_table = PROTO_TABLE,			\
		.tlv_proto_table = TLV_TABLE,				\
		.ops.unknown_type = UNKNOWN_TLV_TYPE,			\
		.ops.post_tlv_handle_proto = POST_TLV_HANDLER,		\
	}

/* Helper to create a TLVs parse node with default unknown next proto
 * function that returns parse failure code and default unknown TLV
 * function that ignores unknown TLVs
 */
#define PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				   EXTRACT_METADATA, HANDLER,		\
				   POST_TLV_HANDLER, PROTO_TABLE,	\
				   TLV_TABLE)				\
	PANDA_DECL_TLVS_TABLE(TLV_TABLE);				\
	PANDA_DECL_PROTO_TABLE(PROTO_TABLE)				\
	__PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE,			\
				    (PROTO_NODE).pnode,			\
				    EXTRACT_METADATA, HANDLER,		\
				    panda_unknown_next_proto_fail,	\
				    panda_unknown_tlv_ignore,		\
				    POST_TLV_HANDLER,			\
				    &PROTO_TABLE, &TLV_TABLE)

/* Helper to create a leaf TLVs parse node with default unknown TLV
 * function that ignores unknown TLVs
 */
#define PANDA_MAKE_LEAF_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
					EXTRACT_METADATA, HANDLER,	\
					POST_TLV_HANDLER, TLV_TABLE)	\
	PANDA_DECL_TLVS_TABLE(TLV_TABLE);				\
	__PANDA_MAKE_TLVS_PARSE_NODE(PARSE_TLV_NODE, PROTO_TLV_NODE,	\
				     EXTRACT_METADATA, HANDLER,		\
				     panda_unknown_next_proto_fail,	\
				     panda_unknown_tlv_ignore,		\
				     POST_TLV_HANDLER,			\
				     NULL, &TLV_TABLE)

#define PANDA_MAKE_TLV_PARSE_NODE(NODE_NAME, CHECK_LENGTH,		\
				  METADATA_FUNC, HANDLER_FUNC)		\
	static const struct panda_parse_tlv_node NODE_NAME = {		\
		.tlv_ops.check_length = CHECK_LENGTH,			\
		.tlv_ops.extract_metadata = METADATA_FUNC,		\
		.tlv_ops.handle_tlv = HANDLER_FUNC,			\
	}

#define PANDA_MAKE_TLV_OVERLAY_PARSE_NODE(NODE_NAME, CHECK_LENGTH,	\
					  METADATA_FUNC, HANDLER_FUNC,	\
					  OVERLAY_TABLE,		\
					  OVERLAY_TYPE_FUNC,		\
					  UNKNOWN_OVERLAY_TYPE_FUNC)	\
	PANDA_DECL_TLVS_TABLE(OVERLAY_TABLE);				\
	static const struct panda_parse_tlv_node NODE_NAME = {		\
		.tlv_ops.check_length = CHECK_LENGTH,			\
		.tlv_ops.extract_metadata = METADATA_FUNC,		\
		.tlv_ops.handle_tlv = HANDLER_FUNC,			\
		.tlv_ops.overlay_type = OVERLAY_TYPE_FUNC,		\
		.tlv_ops.unknown_overlay_type =				\
					UNKNOWN_OVERLAY_TYPE_FUNC,	\
		.overlay_table = &OVERLAY_TABLE,			\
	}

/* Parsing functions */

/* Flags to Panda parser functions */
#define PANDA_F_DEBUG			(1 << 0)

/* Parse starting at the provided root node */
int __panda_parse(const struct panda_parser *parser,
		  const struct panda_parse_node *node, const void *hdr,
		  size_t len, struct panda_metadata *metadata,
		  unsigned int flags, unsigned int max_encaps);

/* Parse packet starting from a parser node
 *
 * Arguments:
 *	- parser: Parser being invoked
 *	- hdr: pointer to start of packet
 *	- len: length of packet
 *	- metadata: metadata structure
 *	- flags: allowed parameterized parsing
 *	- max_encaps: maximum layers of encapsulation to parse
 *
 * Returns PANDA return code value.
 */
static inline int panda_parse(const struct panda_parser *parser,
			      const void *hdr, size_t len,
			      struct panda_metadata *metadata,
			      unsigned int flags, unsigned int max_encaps)
{
	switch (parser->parser_type) {
	case PANDA_GENERIC:
		return __panda_parse(parser, parser->root_node, hdr, len,
				     metadata, flags, max_encaps);
	case PANDA_OPTIMIZED:
		return (parser->parser_entry_point)(parser, parser->root_node,
			hdr, len, metadata, flags, max_encaps);
	default:
		return PANDA_STOP_FAIL;
	}
}

static inline int panda_parse_xdp(const struct panda_parser *parser,
				  struct panda_ctx *ctx, const void **hdr,
				  const void *hdr_end, bool tailcall)
{
	if (parser->parser_type != PANDA_XDP)
		return PANDA_STOP_FAIL;

	return (parser->parser_xdp_entry_point)(ctx, hdr, hdr_end, tailcall);
}

#define PANDA_PARSE_XDP(PARSER, CTX, HDR, HDR_END, TAILCALL)		\
	panda_xdp_parser_##PARSER(CTX, HDR, HDR_END, TAILCALL)

struct panda_parser_def {
	struct panda_parser **parser;
	const char *name;
	const struct panda_parse_node *root_node;
	enum panda_parser_type parser_type;
	panda_parser_opt_entry_point parser_entry_point;
} PANDA_ALIGN_SECTION;

/* Helper to make an extern for a parser */
#define PANDA_PARSER_EXTERN(NAME)					\
	extern struct panda_parser *NAME

/* Helper to make forward declaration for a const parser */
#define PANDA_PARSER_DECL(NAME)						\
	static const struct panda_parser *NAME

#define PANDA_PARSER_EXT_DECL(NAME)					\
	extern const struct panda_parser *NAME

PANDA_DEFINE_SECTION(panda_parsers, struct panda_parser_def)

/* Helper to add parser to list of parser at initialization */
#define PANDA_PARSER_ADD(PARSER, NAME, ROOT_NODE)			\
struct panda_parser *PARSER;						\
static const struct panda_parser_def PANDA_SECTION_ATTR(panda_parsers)	\
			PANDA_UNIQUE_NAME(__panda_parsers_,) = {	\
	.parser = &PARSER,						\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_GENERIC,					\
}

/* Helper to add parser to list of parser at initialization */
#define PANDA_PARSER_OPT_ADD(PARSER, NAME, ROOT_NODE, FUNC)		\
struct panda_parser *PARSER;						\
static const struct panda_parser_def PANDA_SECTION_ATTR(panda_parsers)	\
			PANDA_UNIQUE_NAME(__panda_parsers_,) = {	\
	.parser = &PARSER,						\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_OPTIMIZED,					\
	.parser_entry_point = &FUNC					\
}

struct panda_parser *panda_parser_create(const char *name,
					 const struct panda_parse_node
								*root_node);
void panda_parser_destroy(struct panda_parser *parser);
int panda_parser_init(void);

/* Look up a parse node given
 *
 * Arguments:
 *	- node: Parse node containing look up table
 *	- proto: Protocol number to lookup
 *
 * Returns pointer to parse node if the protocol is matched else returns
 * NULL if the parse node isn't found
 */
const struct panda_parse_node *panda_parse_lookup_by_proto(
		const struct panda_parse_node *node, int proto);

#define PANDA_SWAP(a, b)						\
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

extern siphash_key_t __panda_hash_key;

/* Helper functions to compute the siphash from start pointer
 * through len bytes. Note that siphash library expects start to
 * be aligned to 64 bits
 */
static inline __u32 panda_compute_hash(const void *start, size_t len)
{
	__u32 hash;

	hash = siphash(start, len, &__panda_hash_key);
	if (!hash)
		hash = 1;

	return hash;
}

/* Helper macro to compute a hash from a metadata structure. METADATA
 * is a pointer to a metadata structure and HASH_START_FIELD is the offset
 * within the structure to start the hash. This macro requires that the
 * common metadata for IP addresses is defined in the metadata structure,
 * that is there is an addrs field of type PANDA_METADATA_addrs in the
 * metadata structure. The end offset of the hash area is the last byte
 * of the addrs structure which can be different depending on the type
 * of address (for instance, IPv6 addresses have more bytes than IPv4
 * addresses so the length of the bytes hashed area will be greater).
 */
#define PANDA_COMMON_COMPUTE_HASH(METADATA, HASH_START_FIELD) ({	\
	__u32 hash;							\
	const void *start = PANDA_HASH_START(METADATA,			\
					     HASH_START_FIELD);		\
	size_t olen = PANDA_HASH_LENGTH(METADATA,			\
				offsetof(typeof(*METADATA),		\
				HASH_START_FIELD));			\
									\
	hash = panda_compute_hash(start, olen);				\
	hash;								\
})

/* Initialization function for hash key. If the argument is NULL the
 * hash key is randomly set
 */
void panda_hash_secret_init(siphash_key_t *init_key);

/* Function to print the raw bytesused in a hash */
void panda_print_hash_input(const void *start, size_t len);

/* Helper function to define a function to print common metadata */
#define PANDA_PRINT_METADATA(FRAME) do {				\
	char a4buf[INET_ADDRSTRLEN];					\
	char a6buf[INET6_ADDRSTRLEN];					\
									\
	switch ((FRAME)->addr_type) {					\
	case PANDA_ADDR_TYPE_IPV4:					\
		printf("IPv4 source address: %s\n",			\
		inet_ntop(AF_INET, &(FRAME)->addrs.v4_addrs[0],		\
			  a4buf, sizeof(a4buf)));			\
		printf("IPv4 destination address: %s\n",		\
		       inet_ntop(AF_INET, &(FRAME)->addrs.v4_addrs[1],	\
		       a4buf, sizeof(a4buf)));				\
		break;							\
	case PANDA_ADDR_TYPE_IPV6:					\
		printf("IPv6 source address: %s\n",			\
		       inet_ntop(AF_INET6, &(FRAME)->addrs.v6_addrs[0],	\
				 a6buf, sizeof(a6buf)));		\
		printf("IPv6 destination address: %s\n",		\
		       inet_ntop(AF_INET6, &(FRAME)->addrs.v6_addrs[1],	\
				 a6buf, sizeof(a6buf)));		\
		break;							\
	}								\
	printf("Source port %04x\n", ntohs((FRAME)->port16[0]));	\
	printf("Destination port %04x\n", ntohs((FRAME)->port16[1]));	\
} while (0)

/* Default functions that can be set for various call backs */

static inline int panda_unknown_next_proto_fail(const void *hdr, void *frame,
						int type, int err)
{
	return PANDA_STOP_UNKNOWN_PROTO;
}

static inline int panda_unknown_next_proto_ignore(const void *hdr, void *frame,
						  int type, int err)
{
	return PANDA_STOP_OKAY;
}

static inline int panda_unknown_tlv_fail(const void *hdr, void *frame,
					 int type, int err)
{
	return PANDA_STOP_UNKNOWN_TLV;
}

static inline int panda_unknown_tlv_ignore(const void *hdr, void *frame,
					   int type, int err)
{
	return PANDA_OKAY;
}

/* Null flag-field node for filling out flag-fields table */
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(PANDA_FLAG_NODE_NULL, NULL, NULL);

#endif /* __PANDA_PARSER_H__ */
