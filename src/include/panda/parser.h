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

#include <linux/types.h>

#include "panda/compiler_helpers.h"
#include "panda/flag_fields.h"
#include "panda/parser_types.h"
#include "panda/tlvs.h"
#include "panda/utility.h"

#ifndef __KERNEL__
#include "siphash/siphash.h"
#endif

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

/* Helper to create an optimized parservairant */
#define __PANDA_PARSER_OPT(PARSER, NAME, ROOT_NODE, FUNC)		\
static const struct panda_parser __##PARSER = {				\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_OPTIMIZED,					\
	.parser_entry_point = &FUNC					\
};

/* Helpers to create and use Kmod parser vairant */
#define __PANDA_PARSER_KMOD(PARSER, NAME, ROOT_NODE, FUNC)		\
const struct panda_parser __##PARSER##_kmod = {				\
	.name = NAME,							\
	.root_node = ROOT_NODE,						\
	.parser_type = PANDA_KMOD,					\
	.parser_entry_point = &FUNC					\
};

#define PANDA_PARSER_KMOD(PARSER, NAME, ROOT_NODE, FUNC)		\
	__PANDA_PARSER_KMOD(PARSER, NAME, ROOT_NODE, FUNC)		\
	const struct panda_parser *PARSER##_kmod = &__##PARSER##_kmod;

#define PANDA_PARSER_KMOD_EXTERN(NAME)					\
	extern struct panda_parser *NAME##_kmod

#define PANDA_PARSER_KMOD_NAME(NAME) NAME##_kmod

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
				UNKNOWN_RET, WILDCARD_NODE,		\
				PROTO_TABLE)				\
	static const struct panda_parse_node PARSE_NODE = {		\
		.proto_node = &PROTO_NODE,				\
		.ops.extract_metadata = EXTRACT_METADATA,		\
		.ops.handle_proto = HANDLER,				\
		.unknown_ret = UNKNOWN_RET,				\
		.wildcard_node = WILDCARD_NODE,				\
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
				PANDA_STOP_UNKNOWN_PROTO, NULL,		\
				&PROTO_TABLE)

/* Helper to create a parse node single overlay node */
#define PANDA_MAKE_OVERLAY_PARSE_NODE(PARSE_NODE, PROTO_NODE,		\
			      EXTRACT_METADATA, HANDLER, OVERLAY_NODE)	\
	__PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
				EXTRACT_METADATA, HANDLER,		\
				PANDA_STOP_UNKNOWN_PROTO, OVERLAY_NODE,	\
				NULL)

/* Helper to create a leaf parse node with no next protocol table */
#define PANDA_MAKE_LEAF_PARSE_NODE(PARSE_NODE, PROTO_NODE,		\
				   EXTRACT_METADATA, HANDLER)		\
	__PANDA_MAKE_PARSE_NODE(PARSE_NODE, PROTO_NODE,			\
				EXTRACT_METADATA, HANDLER,		\
				PANDA_STOP_UNKNOWN_PROTO, NULL,		\
				NULL)

/* Parsing functions */

/* Flags to Panda parser functions */
#define PANDA_F_DEBUG			(1 << 0)

#ifndef __KERNEL__
/* Parse starting at the provided root node */
int __panda_parse(const struct panda_parser *parser,
		  const struct panda_parse_node *node, const void *hdr,
		  size_t len, struct panda_metadata *metadata,
		  unsigned int flags, unsigned int max_encaps);
#else
static inline int __panda_parse(const struct panda_parser *parser,
		  const struct panda_parse_node *node, const void *hdr,
		  size_t len, struct panda_metadata *metadata,
		  unsigned int flags, unsigned int max_encaps)
{
	return 0;
}
#endif

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
	case PANDA_KMOD:
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

/* Helper to make an extern for a parser */
#define PANDA_PARSER_EXTERN(NAME)					\
	extern struct panda_parser *NAME

/* Helper to make forward declaration for a const parser */
#define PANDA_PARSER_DECL(NAME)						\
	static const struct panda_parser *NAME

#define PANDA_PARSER_EXT_DECL(NAME)					\
	extern const struct panda_parser *NAME

struct panda_parser_def {
	struct panda_parser **parser;
	const char *name;
	const struct panda_parse_node *root_node;
	enum panda_parser_type parser_type;
	panda_parser_opt_entry_point parser_entry_point;
} PANDA_ALIGN_SECTION;

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

#ifndef __KERNEL__

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

#endif /* __KERNEL__ */

#endif /* __PANDA_PARSER_H__ */
