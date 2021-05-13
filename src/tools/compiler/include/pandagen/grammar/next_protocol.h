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

#ifndef PANDAGEN_INCLUDE_PANDAGEN_NEXT_PROTOCOL_HPP
#define PANDAGEN_INCLUDE_PANDAGEN_NEXT_PROTOCOL_HPP

#include <boost/spirit/include/karma.hpp>

namespace pandagen
{

namespace karma = boost::spirit::karma;

template <typename G, typename V, typename C>
struct next_protocol_generator : karma::primitive_generator<
					next_protocol_generator<G, V, C> > {
	C const *specifics;
	V const *vertex;
	G const *graph;

	next_protocol_generator(G const *g, V const *v, C const *c) :
					graph(g), vertex(v), specifics(c) {}

	template <typename A0, typename A1> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context> bool
	generate(OutputIterator sink, Context &ctx, karma::unused_type,
		 karma::unused_type) const
	{
		namespace spirit = boost::spirit;
		namespace fusion = boost::fusion;
		auto oedges = out_edges(*vertex, *graph);

		if (oedges.first != oedges.second) {
			std::vector<fusion::vector<std::string,
						   std::string>> generic_vs;
			std::vector<fusion::vector<std::string,
						   fusion::vector<std::string,
								 std::string>>>
							specific_vs;
			for (auto &&e : boost::make_iterator_range(oedges)) {
				auto &&t = target(e, *graph);
				if (std::find(specifics->begin(),
				    specifics->end(), t) == specifics->end())
					generic_vs.push_back(
						fusion::make_vector((*graph)[e].
						macro_name, (*graph)[t].name));
				else
					specific_vs.push_back(
						fusion::make_vector(
							(*graph)[e].macro_name,
						    fusion::make_vector(
							(*graph)[t].name, ""
					/* (*graph)[e].back ? "" : "_inline"*/
					)));
			}
			spirit::compile<karma::domain>(tab <<
				"type = proto_node->ops.next_proto "
				"(hdr);\n" << tab <<
				"if (type < 0)\n" << 1_ident <<
					"return type;\n" << tab <<
				"if (!proto_node->overlay) {\n" <<
						1_ident[tab <<
					"hdr += hlen;\n" << tab <<
					"len -= hlen;\n"] << tab <<
				"}\n" << tab <<

				"switch (type) {\n")
			.generate(sink, ctx, karma::unused, karma::unused);
                        spirit::compile<karma::domain>((*(tab <<
				"case " << karma::string << ":\n"
						<< 1_ident[tab <<
					"return __" << karma::string <<
					"_panda_parse" << karma::string <<
					" (parser, hdr, len, metadata, flags, "
					"max_encaps, frame, frame_num);\n"]
				)))
				.generate (sink, ctx, karma::unused,
					   specific_vs);
			spirit::compile<karma::domain>(tab << "};\n" << tab <<
			"/* Unknown protocol */\n" << tab <<
			"if (parse_node->ops.unknown_next_proto)\n" <<
								1_ident <<
				"return parse_node->ops."
				"unknown_next_proto(\n" << 2_ident <<
				"hdr, frame, type, "
				"PANDA_STOP_UNKNOWN_PROTO);\n" << tab <<
			"else\n" << 1_ident <<
				"return PANDA_STOP_UNKNOWN_PROTO;\n")
			.generate(sink, ctx, karma::unused, karma::unused);
			if (!generic_vs.empty()) {
				return spirit::compile<karma::domain>(
					pptab << "call_generic:\n" << tab <<
					"return __generic_panda_parse (parser, "
					"parse_node, hdr, len, metadata, flags,"
					" max_encaps, frame, frame_num);\n")
				.generate(sink, ctx, karma::unused,
					  karma::unused);
			}
		} else {
			return spirit::compile<karma::domain>(tab <<
						"return PANDA_STOP_OKAY;\n")
			.generate(sink, ctx, karma::unused, karma::unused);
		}
		return true;
	}
};

struct next_protocol_terminal {
	template <typename G, typename V, typename C>
	constexpr next_protocol_generator<G, V, C>
	operator()(G const &g, V const &v, C const &c) const
	{
		return { &g, &v, &c };
	}
} const next_protocol = {};

template <typename G, typename V, typename C>
struct xdp_next_protocol_generator
	: karma::primitive_generator<xdp_next_protocol_generator<G, V, C> > {
	C const *specifics;
	V const *vertex;
	G const *graph;

	xdp_next_protocol_generator(G const *g, V const *v, C const *c)
		: graph(g), vertex(v), specifics(c)
	{
	}

	template <typename A0, typename A1> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context>
	bool generate(OutputIterator sink, Context &ctx, karma::unused_type,
		      karma::unused_type) const
	{
		namespace spirit = boost::spirit;
		namespace fusion = boost::fusion;
		auto oedges = out_edges(*vertex, *graph);

		if (oedges.first != oedges.second) {
			std::vector<fusion::vector<std::string, std::string> >
				generic_vs;
			std::vector<fusion::vector<std::string, std::string> >
				specific_vs;
			for (auto &&e : boost::make_iterator_range(oedges)) {
				auto &&t = target(e, *graph);
				if (std::find(specifics->begin(),
					      specifics->end(),
					      t) == specifics->end())
					generic_vs.push_back(
						fusion::make_vector(
							(*graph)[e].macro_name,
							(*graph)[t].name));
				else
					specific_vs.push_back(
						fusion::make_vector(
							(*graph)[e].macro_name,
							(*graph)[t].name));
			}
			spirit::compile<karma::domain>(
				tab << "type = proto_node->ops.next_proto "
				       "(*hdr);\n"
				    << tab << "if (type < 0)\n"
				    << 1_ident << "return type;\n"
				    << tab << "if (!proto_node->overlay) {\n"
				    << 1_ident [tab << "*hdr += hlen;\n"
						    << tab << "}\n"]
				    << tab <<

				"switch (type) {\n")
				.generate(sink, ctx, karma::unused,
					  karma::unused);
			spirit::compile<karma::domain>(
				(*(tab
				   << "case " << karma::string << ":\n"
				   << 1_ident [tab << "ctx->next = CODE_"
						   << karma::string << ";\n"
						   << tab
						   << "return PANDA_OKAY;\n"])))
				.generate(sink, ctx, karma::unused,
					  specific_vs);
			spirit::compile<karma::domain>(
				tab
				<< "};\n"
				<< tab << "/* Unknown protocol */\n"
				<< tab
				<< "if (parse_node->ops.unknown_next_proto)\n"
				<< 1_ident
				<< "return parse_node->ops."
				   "unknown_next_proto(\n"
				<< 2_ident
				<< "*hdr, frame, type, "
				   "PANDA_STOP_UNKNOWN_PROTO);\n"
				<< tab << "else\n"
				<< 1_ident
				<< "return PANDA_STOP_UNKNOWN_PROTO;\n")
				.generate(sink, ctx, karma::unused,
					  karma::unused);
		} else {
			return spirit::compile<karma::domain>(
				       tab << "ctx->next = CODE_IGNORE;\n"
					   << tab
					   << "return PANDA_STOP_OKAY;\n")
				.generate(sink, ctx, karma::unused,
					  karma::unused);
		}
		return true;
	}
};

struct xdp_next_protocol_terminal {
	template <typename G, typename V, typename C>
	constexpr xdp_next_protocol_generator<G, V, C>
	operator()(G const &g, V const &v, C const &c) const
	{
		return { &g, &v, &c };
	}
} const xdp_next_protocol = {};

} // namespace pandagen

#endif
