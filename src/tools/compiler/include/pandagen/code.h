/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
 *
 * Authors: Felipe Magno de Almeida <felipe@expertise.dev>
 *          João Paulo Taylor Ienczak Zanette <joao.tiz@expertise.dev>
 *          Lucas Cavalcante de Sousa <lucas@expertise.dev>
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

#ifndef C_AST_PARSER_GENERATOR_H
#define C_AST_PARSER_GENERATOR_H

#include <sstream>
#include <string>

#include <boost/random.hpp>
#include <boost/spirit/include/karma.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "graph.h"

// workaround for a bug with GCC 6 changesign function
#include <boost/spirit/home/support/detail/sign.hpp>
#include <boost/version.hpp>

#if BOOST_VERSION / 100 % 1000 <= 62
namespace boost::spirit::x3 {
	using boost::spirit::detail::changesign;
}
#endif

#include <pandagen/grammar/identation.h>
#include <pandagen/grammar/length.h>
#include <pandagen/grammar/metadata.h>
#include <pandagen/grammar/next_protocol.h>

namespace pandagen
{

template <typename OutputIterator, typename Graph> void
generate_includes(OutputIterator out, Graph const &graph, std::string filename,
		  std::string header)
{
	karma::generate(out, karma::buffer[tab << "#include <assert.h>\n" <<
				tab << "#include <stdio.h>\n" <<
				tab << "#include <stdlib.h>\n" << tab <<
				"#include \"panda/proto_nodes_def.h\"\n" <<
				tab << "#include \"" << filename << "\"\n" <<
				tab << "#include \"" << header << "\"\n" <<
				tab << "\n" << tab <<
				"#include \"panda/parser.h\"\n\n" <<
				tab << "\n"]);
}

template <typename OutputIterator> void
generate_check_functions(OutputIterator out)
{
	karma::generate(out, karma::buffer[tab <<
	"static inline __attribute__((always_inline)) int "
		"check_pkt_len(const void* hdr,\n" << 2_ident[tab <<
		"const struct panda_proto_node *pnode,\n" << tab <<
		"size_t len,\n" << tab << "ssize_t* hlen)\n"] << tab <<
	"{\n" << 1_ident[tab <<
		"*hlen = pnode->min_len;\n" << tab <<
		"/* Protocol node length checks */\n" << tab <<
		"if (len < *hlen)\n" << 1_ident <<
			"return PANDA_STOP_LENGTH;\n" << tab <<
		"if (pnode->ops.len) {\n" << 1_ident[tab <<
			"*hlen = pnode->ops.len(hdr);\n" << tab <<
			"if (len < *hlen)\n" << 1_ident <<
				"return PANDA_STOP_LENGTH;\n" << tab <<
			"if (*hlen < pnode->min_len)\n" << 1_ident <<
				"return *hlen < 0 ? *hlen : "
				"PANDA_STOP_LENGTH;\n"] << tab <<
		"} else {\n" << 1_ident <<
			"*hlen = pnode->min_len;\n" << tab <<
		"}\n" << tab <<
		"return PANDA_OKAY;\n"] << tab <<
	"}\n"]);
}

template <typename OutputIterator> void
generate_check_encapsulation_layer(OutputIterator out)
{
	karma::generate(out, karma::buffer[tab <<
	"inline static __attribute__((always_inline)) bool "
			"panda_encap_layer(struct panda_metadata "
			"*metadata,\n" << 2_ident[tab <<
		"unsigned max_encaps,\n" << tab <<
		"void** frame,\n" << tab <<
		"unsigned* frame_num)"
	"{\n"] << 1_ident[tab <<
		"/* New encapsulation layer. Check against\n" << tab <<
		" * number of encap layers allowed and also\n" << tab <<
		" * if we need a new metadata frame.\n" << tab <<
		" */\n" << tab <<
		"if (++metadata->encaps > max_encaps) {\n" << 1_ident <<
			"return PANDA_STOP_ENCAP_DEPTH;\n" << tab <<
		"}\n" << tab << "\n" << tab <<
		"if (metadata->max_frame_num > *frame_num) {\n" <<
				1_ident[tab <<
			"*frame += metadata->frame_size;\n" << tab <<
			"*frame_num = (*frame_num) + 1;\n"] << tab <<
		"}\n" << tab <<
		"return 0;\n"] << tab <<
	"}\n"]);
}

template <typename OutputIterator, typename Graph> void
generate_protocol_tlvs_parse_function(OutputIterator out, Graph const &graph,
		typename boost::graph_traits<Graph>::vertex_descriptor v)
{
	std::vector<fusion::vector2<std::string, std::string>> tlvs;
	namespace fusion = boost::fusion;

	for (auto &&t : graph[v].tlv_nodes)
		tlvs.push_back(fusion::vector2<std::string,
			       std::string>(t.type, t.name));

	karma::generate(out,
		karma::buffer[tab << "static inline "
				     "__attribute__((always_inline)) "
				     "int __" << graph[v].name <<
			      "_panda_parse_tlvs(const struct "
			      "panda_parse_node *parse_node,\n" << 2_ident <<
		"const void *hdr, void *frame, size_t hlen)\n" << tab <<
		"{\n" << 1_ident[tab <<
			"const __u8 *cp = hdr;\n" << tab <<
			"size_t offset, len;\n" << tab <<
			"ssize_t tlv_len;\n" << tab <<
			"int type;\n" << tab <<
			"const struct panda_parse_tlvs_node* "
				"parse_tlvs_node = (const struct "
				"panda_parse_tlvs_node*)&" << graph[v].name <<
				";\n" << tab <<
			"const struct panda_proto_tlvs_node "
				"*proto_tlvs_node = "
				"(const struct panda_proto_tlvs_node*)"
				"parse_node->proto_node;\n\n" << tab <<
			"const struct panda_parse_tlv_node "
				"*parse_tlv_node;\n" << tab <<
				"offset = proto_tlvs_node->ops.start_offset "
				"(hdr);\n\n" << tab <<
			"/* Assume hlen marks end of TLVs */\n" << tab <<
			"len = hlen - offset;\n\n" << tab <<
			"cp += offset;\n" << tab <<
			"while (len > 0) {\n" << 1_ident[tab <<
				"if (proto_tlvs_node->pad1_enable &&\n"
						<< 1_ident[tab <<
					"*cp == proto_tlvs_node->pad1_val) "
					"{\n" << 1_ident[tab <<
						"/* One byte padding, just "
						"advance */\n" << tab <<
						"cp++; len--; continue;\n"] <<
									tab <<
					"}\n"] << tab <<
				"if (proto_tlvs_node->eol_enable &&\n"
					<< 1_ident[tab <<
					"*cp == proto_tlvs_node->eol_val) {\n"
							<< 1_ident <<
						"cp++; len--; break;\n"] <<
							tab <<
			"}\n\n" << tab <<
			"if (len < proto_tlvs_node->min_len) {\n" << 1_ident <<
				"return PANDA_STOP_TLV_LENGTH;\n" << tab <<
			"}\n\n" << tab <<
			"if (proto_tlvs_node->ops.len) {\n" << 1_ident <<
				"tlv_len = proto_tlvs_node->ops.len(cp);\n"
						<< tab <<
				"if (!tlv_len || len < tlv_len)\n" << 1_ident <<
					"return PANDA_STOP_TLV_LENGTH;\n" <<
							tab <<
				"if (tlv_len < proto_tlvs_node->min_len)\n" <<
							1_ident <<
					"return tlv_len < 0 ? tlv_len : "
					"PANDA_STOP_TLV_LENGTH;\n" << tab <<
				"} else {\n" << 1_ident <<
					"tlv_len = proto_tlvs_node->min_len;"
					"\n" << tab <<
				"}\n" << tab <<
				"type = proto_tlvs_node->ops.type (cp);\n"
						<< tab <<
				"switch (type) {\n" << *(tab <<
				"case " << karma::string << ":{\n"
						<< 1_ident[tab <<
					"parse_tlv_node = &" <<
						karma::string << ";\n" << tab <<
					"const struct "
					"panda_parse_tlv_node_ops *ops = "
					"&parse_tlv_node->tlv_ops;\n" << tab <<
					"if (ops->check_length) {\n" <<
			// if check_length {
						1_ident[tab <<
						"int ret = ops->check_length"
						"(cp, frame);\n" << tab <<
						"if (ret != PANDA_OKAY) {\n" <<
							1_ident[tab <<
							"if (!parse_tlvs_node"
							"->ops.unknown_type"
							")\n" << 1_ident <<
						"goto next_tlv;\n" << tab <<
						"ret = parse_tlvs_node->"
						"ops.unknown_type(hdr, frame, "
						"type, ret);\n" << tab <<
						"if (ret == PANDA_OKAY)\n" <<
								1_ident <<
							"goto next_tlv;\n"] <<
								tab << "}\n"
			// } if check_length
						] << tab <<
				"}\n" << tab <<
				"if (ops->extract_metadata)\n" << 1_ident <<
					"ops->extract_metadata(cp, frame);\n"
						<< tab <<
					"if (ops->handle_tlv)\n" << 1_ident <<
						"ops->handle_tlv(cp, "
						"frame);\n" << tab <<
						"break;}\n"]) << tab <<
				"default:{\n" << 1_ident[tab <<
					"int ret;\n" << tab <<
					"/* Unknown TLV */\n" << tab <<
					"if (parse_tlvs_node->ops."
					"unknown_type)\n" << 1_ident <<
						"goto next_tlv;\n" << tab <<
					"ret = parse_tlvs_node->ops."
					"unknown_type(hdr, frame, type, "
					"PANDA_STOP_UNKNOWN_TLV);\n" << tab <<
					"if (ret != PANDA_OKAY)\n" << 1_ident <<
						"return ret;"
				"}\n"] <<
			"}\n" << pptab <<
			"next_tlv:\n" << tab <<
			"/* Move over current header */\n" << tab <<
			"cp += tlv_len;\n" << tab <<
			"len -= tlv_len;\n" << tab <<
		"}\n"] << tab <<
		"return PANDA_OKAY;\n"] << tab <<
	"}\n\n"], tlvs);
}

template <typename OutputIterator, typename Graph> void
generate_protocol_parse_function_decl(OutputIterator out, Graph const &graph,
				      typename boost::graph_traits<Graph>::
							vertex_descriptor v)
{
	karma::generate(out, karma::buffer[tab <<
	"static int inline __" << graph[v].name <<
		"_panda_parse(const struct panda_parser *parser,\n" <<
				2_ident[tab <<
		"const void *hdr,\n" << tab <<
		"size_t len,\n" << tab <<
		"struct panda_metadata *metadata,\n" << tab <<
		"unsigned int flags,\n" << tab <<
		"unsigned int max_encaps,\n" << tab <<
		"void *frame,\n" << tab <<
		"unsigned frame_num) __attribute__((unused));\n"]]);
}

template <typename OutputIterator, typename Graph> void
generate_protocol_parse_function(OutputIterator out, Graph const &graph,
				 typename boost::graph_traits<Graph>::
							vertex_descriptor v,
				std::vector<typename
					boost::graph_traits<Graph>::
					vertex_descriptor> specific_protocols)
{
	namespace karma = boost::spirit::karma;

	if (!graph[v].tlv_nodes.empty())
		generate_protocol_tlvs_parse_function(out, graph, v);

	karma::generate (out, karma::buffer[tab <<
	"static inline /*__attribute__((always_inline))*/ int __" <<
	graph[v].name <<
	"_panda_parse/*_inline*/(const struct panda_parser *parser,\n" <<
			2_ident[tab <<
	"const void *hdr,\n" << tab <<
	"size_t len,\n" << tab <<
	"struct panda_metadata *metadata,\n" << tab <<
	"unsigned int flags,\n" << tab <<
	"unsigned int max_encaps,\n" << tab <<
	"void *frame,\n" << tab <<
	"unsigned frame_num)\n"] << tab <<
	"{\n" << 1_ident[tab <<
		"int ret;\n" << tab <<
		"int type; (void)type;\n" << tab <<
		"const struct panda_parse_node* parse_node = "
		"(const struct panda_parse_node*)&" << graph[v].name <<
		";\n" << tab <<
		"const struct panda_proto_node* proto_node = "
		"parse_node->proto_node;\n" << tab <<
		"(void)ret;\n" << tab << "(void)proto_node;\n" <<
		pandagen::length_check << pandagen::metadata]]);

	if (!graph[v].tlv_nodes.empty()) {
		karma::generate (out, karma::buffer[1_ident[tab <<
		"/* Need error in case parse_node TLVs are set but\n" << tab <<
		" * proto_node TLVs are not\n" << tab <<
		" */\n" << tab <<
		"if ((ret = __" << graph[v].name <<
			"_panda_parse_tlvs(parse_node, hdr, frame, hlen)) "
			"!= PANDA_OKAY)\n" << 1_ident <<
			"return ret;\n"]]);
	}
	karma::generate (out, karma::buffer[1_ident[tab <<
		"if (proto_node->encap && (ret = "
		"panda_encap_layer (metadata, max_encaps, &frame, "
		"&frame_num)) != 0)\n" << 1_ident <<
			"return ret;\n\n"]]);

	karma::generate (out, karma::buffer[1_ident [
		pandagen::next_protocol(graph, v, specific_protocols)] <<
	"}\n"]);
}

template <typename OutputIterator> void
generate_generic_decl_parse_function(OutputIterator out)
{
	karma::generate(out, karma::buffer[tab <<
	"static inline int __generic_panda_parse(const struct "
	"panda_parser *parser,\n" << 2_ident[tab <<
	"const struct panda_parse_node *parse_node,\n" << tab <<
	"const void *hdr,\n" << tab <<
	"size_t len,\n" << tab <<
	"struct panda_metadata *metadata,\n" << tab <<
	"unsigned int flags,\n" << tab <<
	"unsigned int max_encaps,\n" << tab <<
	"void* frame,\n" << tab << "unsigned int frame_num);\n\n"]]);
}

template <typename OutputIterator, typename G> void
generate_entry_parse_function(OutputIterator out, G const &graph,
			      std::string parser_name,
			      typename boost::graph_traits<G>::
					vertex_descriptor root,
			      bool parser_add)
{
	namespace karma = boost::spirit::karma;

	karma::generate(out, karma::buffer[tab <<
	"static inline int " << parser_name << "_panda_parse_" <<
	graph[root].name << "(const struct panda_parser "
			    "*parser,\n" << 2_ident[tab <<
	"const struct panda_parse_node *parse_node, const void *hdr,\n" <<
			tab <<
	"size_t len, struct panda_metadata *metadata,\n" << tab <<
	"unsigned int flags, unsigned int max_encaps)\n"] << tab <<
	"{\n" << 1_ident[tab <<
		"void* frame = metadata->frame_data;\n" << tab <<
		"unsigned frame_num = 0;\n"]]);
		karma::generate(out, karma::buffer[1_ident <<
				karma::lit(
		"return __") << graph[root].name <<
		"_panda_parse " /*"_inline"*/ "(parser, hdr, len, metadata, "
		"flags, max_encaps, frame, frame_num);\n" << tab <<
	"}\n"]);
	if (parser_add)
		karma::generate(out, karma::buffer[tab <<
			"PANDA_PARSER_OPT_ADD(" << parser_name <<
			"_opt,\"\", &" << graph[root].name << "," <<
			parser_name << "_panda_parse_" << graph[root].name <<
			");\n"]);
	else
		karma::generate(out, karma::buffer[tab <<
			"PANDA_PARSER_OPT(" << parser_name <<
			"_opt,\"\", &" <<graph[root].name << "," <<
			parser_name << "_panda_parse_" << graph[root].name <<
			");\n"]);
}

template <typename OutputIterator, typename Graph> void
generate_parsers(OutputIterator out, Graph const &graph,
		 std::string filename, std::string header)
{
	auto vs = vertices(graph);

	generate_includes(out, graph, filename, header);
	generate_check_functions(out);
	generate_check_encapsulation_layer(out);

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second))
		generate_protocol_parse_function_decl(out, graph, v);

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second))
		generate_protocol_parse_function(out, graph, v,
						 { vs.first, vs.second });
}

template <typename OutputIterator, typename Graph,
	   typename HeaderOutputIterator> void
generate_root_parser(OutputIterator out, Graph const &graph,
		     typename boost::graph_traits<Graph>::vertex_descriptor
						root, std::string parser_name,
		     std::string filename, HeaderOutputIterator hout,
		     bool doing_add)
{
	generate_entry_parse_function(out, graph, parser_name, root, doing_add);
}

} // namespace pandagen

#endif
