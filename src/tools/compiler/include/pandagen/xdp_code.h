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

#ifndef XDP_PARSER_GENERATOR_H
#define XDP_PARSER_GENERATOR_H

#include <boost/spirit/home/karma/generate.hpp>
#include <sstream>
#include <string>

#include <boost/random.hpp>
#include <boost/spirit/include/karma.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>

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
template <typename OutputIterator, typename Graph>
void xdp_generate_includes(OutputIterator out, Graph const &graph,
			   std::string filename)
{
	karma::generate(
		out,
		karma::buffer
			[tab
			 << "#include <linux/bpf.h>\n"
			 << "#include <bpf/bpf_helpers.h>\n"
			 << "#include \"panda/proto_nodes_def.h\"\n"
			 << "#include \"panda/bpf.h\"\n"
			 << tab << "\n"
			 << tab << "#include \"panda/parser.h\"\n"
			 << "#include \"panda/parser_metadata.h\"\n"
			 << "#include \"" << filename << "\"\n"
			 << "#ifndef PANDA_LOOP_COUNT\n"
			 << "#define PANDA_LOOP_COUNT 8\n"
			 << "#endif\n\n"
			 << "#define PANDA_MAX_ENCAPS (PANDA_LOOP_COUNT + 32)\n"]);
}

template <typename OutputIterator, typename Graph>
void xdp_generate_parser_enum(OutputIterator out, Graph const &graph)
{
	auto vs = vertices(graph);
	std::vector<fusion::vector<std::string> > codes;

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second))
		codes.push_back(fusion::make_vector(graph[v].name));

	karma::generate(
		out,
		karma::buffer[tab << "enum {\n"
				  << *(tab << "CODE_" << karma::string << ",\n")
				  << tab << "CODE_IGNORE,\n};\n"],
		codes);
}

template <typename OutputIterator>
void xdp_generate_check_functions(OutputIterator out)
{
	karma::generate(
		out,
		karma::buffer
			[tab
			 << "static __always_inline int "
			    "check_pkt_len(const void *hdr, const void *hdr_end,\n"
			 << 2_ident[tab << "const struct panda_proto_node *pnode,\n"
					 << tab << "ssize_t* hlen)\n"]
			 << tab << "{\n"
			 << 1_ident[tab
				     << "*hlen = pnode->min_len;\n"
				     << tab << "/* Protocol node length checks */\n"
				     << tab
				     << "if (panda_bpf_check_pkt(hdr, *hlen, hdr_end))\n"
				     << 1_ident << "return PANDA_STOP_LENGTH;\n"
				     << tab << "if (pnode->ops.len) {\n"
				     << 1_ident[tab
						 << "*hlen = pnode->ops.len(hdr);\n"
						 << tab << "if (*hlen < 0)\n"
						 << 1_ident
						 << "return PANDA_STOP_LENGTH;\n"
						 << tab
						 << "if (*hlen < pnode->min_len)\n"
						 << 1_ident
						 << "return PANDA_STOP_LENGTH;\n"
						    "if (panda_bpf_check_pkt(hdr, *hlen, hdr_end))\n"
						 << 1_ident
						 << "return PANDA_STOP_LENGTH;\n"]
				     << tab << "} else {\n"
				     << 1_ident << "*hlen = pnode->min_len;\n"
				     << tab << "}\n"
				     << tab << "return PANDA_OKAY;\n"]
			 << tab << "}\n"]);
}

template <typename OutputIterator>
void xdp_generate_check_encapsulation_layer(OutputIterator out)
{
	karma::generate(
		out,
		karma::buffer
			[tab
			 << "static __always_inline bool "
			    "panda_encap_layer(struct panda_metadata "
			    "*metadata,\n"
			 << 2_ident[tab << "void** frame,\n"
					 << tab
					 << "__u32* frame_num)"
					    "{\n"]
			 << 1_ident[tab
				     << "/* New encapsulation layer. Check against\n"
				     << tab
				     << " * number of encap layers allowed and also\n"
				     << tab
				     << " * if we need a new metadata frame.\n"
				     << tab << " */\n"
				     << tab
				     << "if (++metadata->encaps > PANDA_MAX_ENCAPS) {\n"
				     << 1_ident
				     << "return PANDA_STOP_ENCAP_DEPTH;\n"
				     << tab << "}\n"
				     << "\n"
				     << tab
				     << "if (metadata->max_frame_num > *frame_num) {\n"
				     << 1_ident[tab
						 << "*frame += metadata->frame_size;\n"
						 << tab
						 << "*frame_num = (*frame_num) + 1;\n"]
				     << tab << "}\n"
				     << tab << "return 0;\n"]
			 << tab << "}\n"]);
}

template <typename OutputIterator, typename Graph>
void xdp_generate_protocol_tlvs_parse_function(
	OutputIterator out, Graph const &graph,
	typename boost::graph_traits<Graph>::vertex_descriptor v)
{
	std::vector<fusion::vector<std::string, fusion::vector<std::string, std::string>> > tlvs;
	namespace fusion = boost::fusion;

	for (auto &&t : graph[v].tlv_nodes)
		tlvs.push_back(fusion::make_vector(t.type, fusion::make_vector(t.name, t.type)));

	karma::generate(
		out,
		karma::buffer
			[tab
			 << "static int __" << graph[v].name
			 << "_panda_parse_tlvs(const struct panda_parse_node *parse_node,\n"
			 << 2_ident
			 << "const void *hdr, const void *hdr_end, void *frame, volatile size_t hlen)\n"
			 << tab << "{\n"
			 << 1_ident[tab
				     << "const __u8 *cp = hdr;\n"
				     << tab << "size_t offset, len;\n"
				     << tab << "ssize_t tlv_len;\n"
				     << tab << "int type;\n"
				     << tab
				     << "const struct panda_parse_tlvs_node* parse_tlvs_node = (const struct "
					"panda_parse_tlvs_node*)&"
				     << graph[v].name << ";\n"
				     << tab
				     << "const struct panda_proto_tlvs_node *proto_tlvs_node = (const struct panda_proto_tlvs_node*)"
					"parse_node->proto_node;\n\n"
				     << tab
				     << "const struct panda_parse_tlv_node *parse_tlv_node;\n"
				     << tab
				     << "offset = proto_tlvs_node->ops.start_offset (cp);\n\n"
				     << tab
				     << "/* Assume hlen marks end of TLVs */\n"
				     << tab << "len = hlen - offset;\n\n"
				     << tab << "cp += offset;\n"
				     << tab << "#pragma unroll\n"
				     << tab << "for (int i = 0; i < 8; i++) {\n"
				     << 1_ident[tab
						 << "if (panda_bpf_check_pkt(cp, 1, hdr_end))\n"
						 << 1_ident
						 << "return PANDA_STOP_LENGTH;\n"
						 << tab
						 << "if (proto_tlvs_node->pad1_enable &&\n"
						 << 1_ident[tab
							     << "*cp == proto_tlvs_node->pad1_val) {\n"
							     << 1_ident[tab
									 << "/* One byte padding, just advance */\n"
									 << tab
									 << "cp++; len--; continue;\n"]
							     << tab << "}\n"]
						 << tab
						 << "if (proto_tlvs_node->eol_enable &&\n"
						 << 1_ident[tab
							     << "*cp == proto_tlvs_node->eol_val) {\n"
							     << 1_ident
							     << "cp++; len--; break;\n"]
						 << tab << "}\n\n"
						 << tab
						 << "if (len < proto_tlvs_node->min_len) {\n"
						 << 1_ident
						 << "return PANDA_STOP_TLV_LENGTH;\n"
						 << tab << "}\n\n"
						 << tab
						 << "if (panda_bpf_check_pkt(cp, proto_tlvs_node->ops.data_offset(cp), hdr_end))\n"
						 << 1_ident
						 << "return PANDA_STOP_LENGTH;\n"
						 << tab
						 << "if (proto_tlvs_node->ops.len) {\n"
						 << 1_ident
						 << "tlv_len = proto_tlvs_node->ops.len(cp);\n"
						 << 1_ident
						 << "if (!tlv_len || len < tlv_len)\n"
						 << 2_ident
						 << "return PANDA_STOP_TLV_LENGTH;\n"
						 << 1_ident
						 << "if (tlv_len < proto_tlvs_node->min_len)\n"
						 << 2_ident
						 << "return tlv_len < 0 ? tlv_len : "
						    "PANDA_STOP_TLV_LENGTH;\n"
						 << tab << "} else {\n"
						 << 1_ident
						 << "tlv_len = proto_tlvs_node->min_len;\n"
						 << tab << "}\n"
						 << tab
						 << "type = proto_tlvs_node->ops.type (cp);\n"
						 << tab << "switch (type) {\n"
						 << *(tab
						      << "case "
						      << karma::string << ":{\n"
						      << 1_ident[tab
								  << "parse_tlv_node = &"
								  << karma::string
								  << ";\n"
								  << tab
								  << "const struct "
								     "panda_parse_tlv_node_ops *ops = "
								     "&parse_tlv_node->tlv_ops;\n"
								  << tab << "if (ops->check_length) {\n"
								  <<
								  // if check_length {
								  1_ident[tab
									   << "int ret = ops->check_length(cp, "
									      "frame);\n"
									   << tab
									   << "if (ret != PANDA_OKAY) {\n"
									   << 1_ident[tab
										       << "if (!parse_tlvs_node->ops.unknown_type)\n"
										       << 1_ident
										       << "goto next_tlv;\n"
										       << tab
										       << "ret = "
											  "parse_tlvs_node->ops.unknown_type(hdr, "
											  "frame, type, "
											  "ret);\n"
										       << tab
										       << "if (ret == PANDA_OKAY)\n"
										       << 1_ident
										       << "goto next_tlv;\n"]
									   << tab
									   << "}\n"
									   // } if check_length
	] << tab << "}\n" << tab << "if (panda_bpf_extract_" << karma::lower[karma::string]
								  << "(ops, hdr, hdr_end, frame, tlv_len) != PANDA_OKAY)\n"
								  << 1_ident
								  << "return PANDA_STOP_FAIL;\n"
								  << tab << "if (ops->handle_tlv)\n"
								  << 1_ident
								  << "ops->handle_tlv(cp, frame, tlv_len);\n"
								  << tab
								  << "break;}\n"])
						 << tab << "default:{\n"
						 << 1_ident[tab
							     << "int ret;\n"
							     << tab << "/* Unknown TLV */\n"
							     << tab << "if (!parse_tlvs_node->ops.unknown_type)\n"
							     << 1_ident
							     << "goto next_tlv;\n"
							     << tab
							     << "ret = "
								"parse_tlvs_node->ops.unknown_type(hdr, frame, type, "
								"PANDA_STOP_UNKNOWN_TLV);\n"
							     << tab << "if (ret != PANDA_OKAY)\n"
							     << 1_ident
							     << "return ret;}\n"]
						 << "}\n"
						 << pptab << "next_tlv:\n"
						 << tab
						 << "/* Move over current header */\n"
						 << tab << "cp += tlv_len;\n"
						 << tab << "len -= tlv_len;\n"
						 << tab << "if (len == 0)\n"
						 << tab << "break;\n"
						 << tab << "}\n"]
				     << tab << "return PANDA_OKAY;\n"]
			 << tab << "}\n\n"],
		tlvs);
}

template <typename OutputIterator, typename Graph>
void xdp_generate_protocol_parse_function_decl(
	OutputIterator out, Graph const &graph,
	typename boost::graph_traits<Graph>::vertex_descriptor v)
{
	karma::generate(
		out,
		karma::buffer
			[tab
			 << "static int __always_inline __" << graph[v].name
			 << "_panda_parse(struct panda_ctx *ctx, const void **hdr, const void *hdr_end, void *frame) __attribute__((unused));\n"]);
}

template <typename OutputIterator, typename Graph>
void xdp_generate_protocol_parse_function(
	OutputIterator out, Graph const &graph,
	typename boost::graph_traits<Graph>::vertex_descriptor v,
	std::vector<typename boost::graph_traits<Graph>::vertex_descriptor>
		specific_protocols)
{
	namespace karma = boost::spirit::karma;

	if (!graph[v].tlv_nodes.empty())
		xdp_generate_protocol_tlvs_parse_function(out, graph, v);

	karma::generate(
		out,
		karma::buffer[tab
			      << "static __always_inline int __" << graph[v].name
			      << "_panda_parse(struct panda_ctx *ctx, const void **hdr, const void *hdr_end, void *frame)"]
			<< tab << "{\n"
			<< 1_ident[tab
				    << "int ret;\n"
				    << tab << "int type; (void)type;\n"
				    << tab
				    << "const struct panda_parse_node* parse_node = "
				       "(const struct panda_parse_node*)&"
				    << graph[v].name << ";\n"
				    << tab
				    << "const struct panda_proto_node* proto_node = "
				       "parse_node->proto_node;\n"
				    << tab << "(void)ret;\n"
				    << tab << "(void)proto_node;\n"
				    << pandagen::xdp_length_check
				    << pandagen::xdp_metadata]);

	if (!graph[v].tlv_nodes.empty()) {
		karma::generate(
			out,
			karma::buffer
				[1_ident[tab
					  << "/* Need error in case parse_node TLVs are set but\n"
					  << tab << " * proto_node TLVs are not\n"
					  << tab << " */\n"
					  << tab << "if ((ret = __" << graph[v].name
					  << "_panda_parse_tlvs(parse_node, *hdr, hdr_end, frame, hlen)) "
					     "!= PANDA_OKAY)\n"
					  << 1_ident << "return ret;\n"]]);
	}

	karma::generate(
		out,
		karma::buffer[1_ident[tab << "if (proto_node->encap && (ret = "
					      "panda_encap_layer (&ctx->metadata, &frame, "
					      "&ctx->frame_num)) != 0)\n"
					   << 1_ident << "return ret;\n\n"]]);

	karma::generate(out,
			karma::buffer[1_ident[pandagen::xdp_next_protocol(
					      graph, v, specific_protocols)]
				      << "}\n"]);
}

template <typename OutputIterator, typename G>
void xdp_generate_entry_parse_function(
	OutputIterator out, G const &graph, std::string parser_name,
	typename boost::graph_traits<G>::vertex_descriptor root)
{
	namespace karma = boost::spirit::karma;

	auto vs = vertices(graph);

	karma::generate(
		out,
		karma::buffer
			[tab
			 << "static __always_inline int " << parser_name
			 << "_panda_parse_" << graph[root].name
			 << "(struct panda_ctx *ctx, const void **hdr, const void *hdr_end, bool tailcall)\n"]);

	karma::generate(
		out,
		karma::buffer
			[tab
			 << "{\n"
			 << 1_ident[tab
				     << "int rc = PANDA_OKAY;\n"
				     << tab << "void *frame = "
					       "ctx->metadata.frame_data;\n"
				     << tab << "if (!tailcall)\n"
				     << tab << "	rc = __" << graph[root].name
				     << "_panda_parse(ctx, hdr, hdr_end, frame);\n"
				     << tab << "#pragma unroll\n"
				     << tab
				     << "for (int i = 0; i < (tailcall ? 1 : PANDA_LOOP_COUNT); i++) {\n"
				     << tab
				     << "	if (ctx->next == CODE_IGNORE || rc != PANDA_OKAY) {\n"
				     << tab << "		break;\n"
				     << tab << "	}"]]);

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second)) {
		karma::generate(
			out, karma::buffer[tab << " else if (ctx->next == CODE_"
					       << graph[v].name << ") {\n"]);

		// TLVs trigger a tailcall
		if (!graph[v].tlv_nodes.empty()) {
			karma::generate(
				out,
				karma::buffer
					[3_ident[tab
						  << "if (tailcall)\n"
						  << 1_ident << "rc = __"
						  << graph[v].name
						  << "_panda_parse(ctx, hdr, hdr_end, frame);\n"
						  << tab << "else\n"
						  << 1_ident
						  << "return PANDA_OKAY;\n"]]);
		} else {
			karma::generate(
				out,
				karma::buffer
					[3_ident[tab
						  << "rc = __" << graph[v].name
						  << "_panda_parse(ctx, hdr, hdr_end, frame);\n"]]);
		}

		karma::generate(out, karma::buffer[2_ident[tab << "}"]]);
	}

	karma::generate(
		out,
		karma::buffer[tab
			      << 2_ident[" else {\n"
					  << tab
					  << "		return PANDA_STOP_UNKNOWN_PROTO;\n"
					  << tab << "}\n"]
			      << tab << "	}\n"
			      << tab << "	return rc;\n"
			      << tab << "}\n"]);

	karma::generate(
		out,
		karma::buffer
			[tab <<
			 "static __always_inline int panda_xdp_parser_" <<
			 parser_name <<
			 "(struct panda_ctx *ictx, const void **hdr, "
			    "const void *hdr_end, bool tailcall)\n"]);
	karma::generate(
		out,
		karma::buffer
			[tab << "{\n" <<
			 1_ident[tab << "return " << parser_name <<
				 "_panda_parse_" << graph[root].name <<
				 "(ictx, hdr, hdr_end, tailcall);\n"] <<
				 tab << "}\n"]);
}

template <typename OutputIterator, typename Graph>
void xdp_generate_parsers(OutputIterator out, Graph const &graph,
			  std::string filename)
{
	auto vs = vertices(graph);

	xdp_generate_includes(out, graph, filename);
	xdp_generate_parser_enum(out, graph);
	xdp_generate_check_functions(out);
	xdp_generate_check_encapsulation_layer(out);

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second))
		xdp_generate_protocol_parse_function_decl(out, graph, v);

	for (auto &&v : boost::make_iterator_range(vs.first, vs.second))
		xdp_generate_protocol_parse_function(out, graph, v,
						     { vs.first, vs.second });
}

template <typename OutputIterator, typename Graph>
void xdp_generate_root_parser(
	OutputIterator out, Graph const &graph,
	typename boost::graph_traits<Graph>::vertex_descriptor root,
	std::string parser_name)
{
	xdp_generate_entry_parse_function(out, graph, parser_name, root);
}

} // namespace pandagen

#endif
