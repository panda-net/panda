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

#ifndef PANDAGEN_INCLUDE_PANDAGEN_LENGTH_HPP
#define PANDAGEN_INCLUDE_PANDAGEN_LENGTH_HPP

#include <boost/spirit/include/karma.hpp>

#include <pandagen/grammar/identation.h>

namespace pandagen
{

namespace karma = boost::spirit::karma;

struct length_generator : karma::primitive_generator<length_generator> {
	template <typename C, typename I> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context, typename D> bool
	generate(OutputIterator sink, Context const &ctx, D const &d,
		 karma::unused_type) const
	{
		namespace spirit = boost::spirit;

		return spirit::compile<karma::domain>(tab <<
			"ssize_t hlen;\n" << tab <<
			"if ((ret = check_pkt_len(hdr, "
			"parse_node->proto_node, len, &hlen)) "
			"!= PANDA_OKAY)\n" << 1_ident <<
			"return ret;\n")
		.generate(sink, ctx, d, karma::unused);
	}

} const length_check = {};

struct xdp_length_generator : karma::primitive_generator<xdp_length_generator> {
	template <typename C, typename I> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context, typename D>
	bool generate(OutputIterator sink, Context const &ctx, D const &d,
		      karma::unused_type) const
	{
		namespace spirit = boost::spirit;

		return spirit::compile<karma::domain>(
			       tab << "ssize_t hlen;\n"
				   << tab
				   << "if ((ret = check_pkt_len(*hdr, hdr_end, "
				      "parse_node->proto_node, &hlen)) "
				      "!= PANDA_OKAY)\n"
				   << 1_ident << "return ret;\n")
			.generate(sink, ctx, d, karma::unused);
	}

} const xdp_length_check = {};

} // namespace pandagen

#endif
