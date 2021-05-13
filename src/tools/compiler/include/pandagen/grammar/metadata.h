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

#ifndef PANDAGEN_INCLUDE_PANDAGEN_METADATA_HPP
#define PANDAGEN_INCLUDE_PANDAGEN_METADATA_HPP

#include <boost/spirit/include/karma.hpp>

namespace pandagen
{

namespace karma = boost::spirit::karma;

struct metadata_generator : karma::primitive_generator<metadata_generator> {
	template <typename C, typename I> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context> bool
	generate(OutputIterator sink, Context const &ctx, karma::unused_type,
		 karma::unused_type) const
	{
		namespace spirit = boost::spirit;

		return spirit::compile<karma::domain>(tab <<
			"if (parse_node->ops.extract_metadata)\n" << 1_ident <<
			"parse_node->ops.extract_metadata (hdr, frame, "
			"hlen);\n")
				.generate(sink, ctx, karma::unused,
					  karma::unused);
	}
} const metadata = {};

struct xdp_metadata_generator
	: karma::primitive_generator<xdp_metadata_generator> {
	template <typename C, typename I> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator, typename Context>
	bool generate(OutputIterator sink, Context const &ctx,
		      karma::unused_type, karma::unused_type) const
	{
		namespace spirit = boost::spirit;

		return spirit::compile<karma::domain>(
			       tab
			       << "if (parse_node->ops.extract_metadata)\n"
			       << 1_ident
			       << "parse_node->ops.extract_metadata"
				  "(*hdr, frame, hlen);\n")
			.generate(sink, ctx, karma::unused, karma::unused);
	}
} const xdp_metadata = {};

} // namespace pandagen

#endif
