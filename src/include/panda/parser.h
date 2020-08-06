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
 * encap: Indicates an encapsulation protocol (e.g. IPIP, GRE)
 * overlay: Indicates an overlay protocol. This is used, for example, to
 *	switch on version number of a protocol header (e.g. IP version number
 *	or GRE version number)
 * name: Text name of protocol node for debugging
 * min_len: Minimum length of the protocol header
 * ops: Operations to parse protocol header
 */
struct panda_proto_node {
	__u8 encap: 1;
	__u8 overlay: 1;
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
	void (*extract_metadata)(const void *hdr, void *frame);
	int (*handle_proto)(const void *hdr, void *frame);
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
 * proto_node: Protocol node
 * ops: Parse node operations
 * proto_table: Protocol table for next protocol. This must be non-null if
 * next_proto is not NULL
 */
struct panda_parse_node {
	const struct panda_proto_node *proto_node;
	const struct panda_parse_node_ops ops;
	const struct panda_proto_table *proto_table;
};

/* Definition of a PANDA parser. Fields are:
 *
 * name: Text name for the parser
 * root_node: Root parse node of the parser. When the parser is invoked
 *	parsing commences at this parse node
 */
struct panda_parser {
	const char *name;
	const struct panda_parse_node *root_node;
};

/* Helper to create a parser */
#define PANDA_PARSER(PARSER, NAME, ROOT_NODE)				\
struct panda_parser __##PARSER = {					\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
};									\
struct panda_parser *PARSER = &__##PARSER;

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
	static const struct panda_proto_table PROTO_TABLE;

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

/* Definitions for parsing flag fields
 *
 * Flag fields are a common protocol header structure consisting of
 * a set of flags and optional fields for which flags indicate their
 * presence (e.g. for handling GRE or GUE flag fields)
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

	for (i = 0; i < targ_idx - 1; i++) {
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
	return __panda_parse(parser, parser->root_node, hdr, len, metadata,
			     flags, max_encaps);
}

struct panda_parser_def {
	struct panda_parser **parser;
	const char *name;
	const struct panda_parse_node *root_node;
} PANDA_ALIGN_SECTION;

/* Helper to make an extern for a parser */
#define PANDA_PARSER_EXTERN(NAME)					\
	extern struct panda_parser *NAME

PANDA_DEFINE_SECTION(panda_parsers, struct panda_parser_def)

/* Helper to add parser to list of parser at initialization */
#define PANDA_PARSER_ADD(PARSER, NAME, ROOT_NODE)			\
struct panda_parser *PARSER;						\
static struct panda_parser_def PANDA_SECTION_ATTR(panda_parsers)	\
			PANDA_UNIQUE_NAME(__panda_parsers_,) = {	\
	.parser = &PARSER,						\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
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
} while (0)

/* Default functions that can be set for various call backs */

static inline void panda_null_extract_metadata(const void *hdr, void *frame)
{
}

static inline int panda_null_handle_proto(const void *hdr, void *frame)
{
	return PANDA_OKAY;
}

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

#endif /* __PANDA_PARSER_H__ */