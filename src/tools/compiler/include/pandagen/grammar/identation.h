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

#ifndef PANDAGEN_INCLUDE_PANDAGEN_IDENTATION_HPP
#define PANDAGEN_INCLUDE_PANDAGEN_IDENTATION_HPP

#include <boost/fusion/algorithm/transformation/replace.hpp>
#include <boost/spirit/include/karma.hpp>

namespace pandagen
{

namespace karma = boost::spirit::karma;
namespace spirit = boost::spirit;
namespace fusion = boost::fusion;

namespace detail
{

template <unsigned int V> constexpr unsigned int make_unsigned()
{
	return V;
}

template <unsigned int V, char C, char... Cs> constexpr
						unsigned int make_unsigned()
{
	static_assert(C >= '0' || C <= '9', "invalid number");

	return make_unsigned<10 * V + C - '0', Cs...>();
}
} // namespace detail

struct identation_info {
	unsigned int tabs;
};

inline bool operator== (identation_info const &l, identation_info const &r)
{
	return l.tabs == r.tabs;
}

template <typename G, unsigned I> struct identation_scope_generator :
		karma::unary_generator<identation_scope_generator<G, I> > {
	identation_scope_generator(G g) : g{ g } {}
	G g;

	template <typename Context, typename Iterator> struct attribute {
		typedef typename spirit::traits::attribute_of<G,
					Context, Iterator>::type type;
	};

	template <typename OutputIterator, typename D, typename A> bool
	generate(OutputIterator sink, karma::unused_type,
		 D const &d, A &a) const
	{
		namespace fusion = boost::fusion;
		auto cattr = fusion::as_list(fusion::push_back(fusion::nil{},
					     identation_info{ I }));
		spirit::context<decltype(cattr), karma::unused_type>
								nctx{ cattr };
		bool r = g.generate(sink, nctx, d, a);
		return r;
	}

	template <typename OutputIterator, typename Context, typename D,
		  typename A> bool
	generate_info(OutputIterator sink, Context const &ctx, D const &d,
		      A &a, boost::fusion::cons_iterator<const
						boost::fusion::nil_>) const
	{
	namespace fusion = boost::fusion;
	auto cattr = fusion::as_list(fusion::push_back(ctx.attributes,
				     identation_info{ I }));
		spirit::context<decltype(cattr),
					 typename Context::locals_type>
								nctx{ cattr };
		nctx.locals = ctx.locals;
		bool r = g.generate(sink, nctx, d, a);
		// ctx.locals = nctx.locals;
		return r;
	}

	template <typename OutputIterator, typename Context, typename D,
		  typename A, typename It> bool
	generate_info(OutputIterator sink, Context const &ctx, D const &d,
		      A &a, It it) const
	{
		namespace fusion = boost::fusion;
		auto info = fusion::deref(it);
		identation_info new_info = { info.tabs + I };
		auto cattr = fusion::as_list(fusion::replace(ctx.attributes,
							     info, new_info));
		spirit::context<decltype(cattr),
				typename Context::locals_type> nctx{ cattr };
		nctx.locals = ctx.locals;
		bool r = g.generate(sink, nctx, d, a);
		return r;
	}

	template <typename OutputIterator, typename Context, typename D,
		  typename A> bool
	generate(OutputIterator sink, Context const &ctx, D const &d,
		      A &a) const
	{
		namespace fusion = boost::fusion;

		return generate_info(sink, ctx, d, a,
				     fusion::find<identation_info>(
							ctx.attributes));
	}
};

struct tab_placeholder_generator :
			karma::primitive_generator<tab_placeholder_generator> {
	template <typename C, typename X> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator> bool
	generate(OutputIterator sink, karma::unused_type,
		 karma::unused_type, karma::unused_type) const
	{
		return true;
	}

        template <typename OutputIterator, typename Context, typename It> bool
	generate_info(OutputIterator sink, Context const &ctx,
		      karma::unused_type, karma::unused_type, It it) const
	{
		auto info = boost::fusion::deref(it);

		for (int i = 0; i != info.tabs; ++i)
			*sink++ = '\t';
		return true;
	}

	template <typename OutputIterator, typename Context>
	bool generate_info(OutputIterator sink, Context const &ctx,
			   karma::unused_type, karma::unused_type,
			   boost::fusion::cons_iterator<const
						boost::fusion::nil_>) const
	{
		return true;
	}

	template <typename OutputIterator, typename Context> bool
	generate(OutputIterator sink, Context const &ctx, karma::unused_type,
		 karma::unused_type) const
	{
		return generate_info(sink, ctx, karma::unused, karma::unused,
				     fusion::find<identation_info>
							(ctx.attributes));
	}
};

BOOST_SPIRIT_TERMINAL_EX(tab);
boost::proto::terminal<boost::spirit::tag::eps>::type pptab = { {} };

template <unsigned I> struct identation_generator :
			karma::primitive_generator<identation_generator<I> > {
	template <typename C, typename X> struct attribute {
		typedef karma::unused_type type;
	};

	template <typename OutputIterator> bool
	generate(OutputIterator sink, karma::unused_type, karma::unused_type,
		 karma::unused_type) const
	{
		for (int i = 0; i != I; ++i)
			*sink++ = '\t';
		return true;
	}

	template <typename OutputIterator, typename Context, typename It> bool
	generate_info(OutputIterator sink, Context const &ctx,
		      karma::unused_type, karma::unused_type, It it) const
	{
		namespace fusion = boost::fusion;
		auto info = fusion::deref(it);
		for (int i = 0; i != I + info.tabs; ++i)
			*sink++ = '\t';
		return true;
	}

	template <typename OutputIterator, typename Context> bool
	generate_info(OutputIterator sink, Context const &ctx,
		      karma::unused_type unused, karma::unused_type,
		      boost::fusion::cons_iterator<const
						boost::fusion::nil_>) const
	{
		return generate(sink, unused, unused, unused);
	}

	template <typename OutputIterator, typename Context> bool
	generate(OutputIterator sink, Context const &ctx,
		 karma::unused_type unused, karma::unused_type) const
	{
		return generate_info(sink, ctx, unused, unused,
				     boost::fusion::find<identation_info>
							(ctx.attributes));
	}
};

namespace tag
{
	template <unsigned I> struct identation {};
}

template <char... Cs>
constexpr typename boost::proto::terminal<tag::identation<detail::
			make_unsigned<0, Cs...>()> >::type operator"" _ident()
{
	return {};
}

} // namespace tag

namespace boost::spirit
{

template <> struct use_terminal<karma::domain, pandagen::tag::tab> :
								mpl::true_ {};
template <unsigned I> struct use_terminal<karma::domain,
				pandagen::tag::identation<I> > : mpl::true_ {};

template <unsigned I> struct use_directive<karma::domain,
				pandagen::tag::identation<I> > : mpl::true_ {};

namespace karma
{
template <typename Modifiers> struct make_primitive<pandagen::tag::tab,
								Modifiers> {
	typedef pandagen::tab_placeholder_generator result_type;
	result_type operator()(unused_type, unused_type) const { return {}; }
};

template <unsigned int I, typename Modifiers>
		struct make_primitive<pandagen::tag::identation<I>, Modifiers> {
	typedef pandagen::identation_generator<I> result_type;
	result_type operator()(unused_type, unused_type) const { return {}; }
};

template <unsigned int I, typename Subject, typename Modifiers>
struct make_directive<pandagen::tag::identation<I>, Subject, Modifiers> {
	typedef pandagen::identation_scope_generator<Subject, I> result_type;
	result_type

	operator()(spirit::unused_type, Subject const &subject,
		   boost::spirit::unused_type) const
	{
		return result_type{ subject };
	}
};
} // namespace karma

namespace traits
{

template <unsigned int I, typename Subject, typename Attribute,
	  typename Context, typename Iterator>
struct handles_container<pandagen::identation_scope_generator<Subject, I>,
				Attribute, Context, Iterator> : mpl::true_ {};

}
}

#endif
