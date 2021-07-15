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

#ifndef __PANDA_COMPILER_HELPERS_H__
#define __PANDA_COMPILER_HELPERS_H__

/* Various helper defintions and functions that are compiler specific
 * (e.g. they use __attribute__
 */

/* Define the __defaligned macro if it's not already defined */
#ifndef __defaligned
#define __defaligned() __attribute__ ((__aligned__))
#endif

/* Define the __aligned macro if it's not already defined */
#ifndef __aligned
#define __aligned(size) __attribute__((__aligned__(size)))
#endif

/* Define the __unused macro if it's not already defined */
#ifndef __unused
#define __unused() __attribute__((unused))
#endif

/* Define the __always_inline macro if it's not already defined */
#ifndef __always_inline
#define __always_inline __attribute__((always_inline)) inline
#endif

/* Utilities for dynamic arrays in sections */

#define PANDA_DEFINE_SECTION(NAME, TYPE)				\
extern TYPE __start_##NAME[];						\
extern TYPE __stop_##NAME[];						\
static inline unsigned int panda_section_array_size_##NAME(void)	\
{									\
	return (unsigned int)(__stop_##NAME - __start_##NAME);		\
}									\
static inline TYPE *panda_section_base_##NAME(void)			\
{									\
	return __start_##NAME;						\
}

#ifndef __bpf__
#define PANDA_SECTION_ATTR(NAME) __attribute__((__used__, __section__(#NAME)))
#else
#define PANDA_SECTION_ATTR(NAME)
#endif

/* Assume cache line size of 64 for purposes of section alignment */
#ifndef PANDA_ALIGN_SECTION
#define PANDA_ALIGN_SECTION  __aligned(64)
#endif

#endif /* __PANDA_COMPILER_HELPERS_H__ */
