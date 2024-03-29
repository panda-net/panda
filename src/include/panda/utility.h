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

#ifndef __PANDA_UTILITY_H__
#define __PANDA_UTILITY_H__

/* Main API definitions for PANDA
 *
 * Definitions and functions for PANDA library.
 */

#ifndef __KERNEL__
#include <arpa/inet.h>
#include <err.h>
#include <linux/types.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#else
/* To get ARRAY_SIZE, container_of, etc. */
#include <linux/kernel.h>
#endif /* __KERNEL__ */

#include "panda/compiler_helpers.h"

/* Utilities that work in kernel or userspace */

/* Define the common ARRAY_SIZE macro if it's not already defined */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

/* Define the common container_of macro if it's not already defined */
#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member)*__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member));	\
})

#endif

static inline bool panda_is_power_of_two(unsigned long long x)
{
	return x && (!(x & (x - 1)));
}

static inline unsigned long long panda_round_pow_two(unsigned long long x)
{
	unsigned long long ret = 1;

	if (!x)
		return 1;

	x = (x - 1) * 2;

	while (x >>= 1)
		ret <<= 1;

	return ret;
}

static inline unsigned int panda_get_log(unsigned long long x)
{
	unsigned int ret = 0;

	while ((x >>= 1))
		ret++;

	return ret;
}

static inline unsigned int panda_get_log_round_up(unsigned long long x)
{
	unsigned long long orig = x;
	unsigned int ret = 0;

	while ((x >>= 1))
		ret++;

	if (orig % (1ULL << ret))
		ret++;

	return ret;
}

#define panda_max(a, b)						\
({								\
	__typeof__(a) _a = (a);					\
	__typeof__(b) _b = (b);					\
	_a > _b ? _a : _b;					\
})

#define panda_min(a, b)						\
({								\
	__typeof__(a) _a = (a);					\
	__typeof__(b) _b = (b);					\
	_a < _b ? _a : _b;					\
})

#ifndef htonll
#if defined(__BIG_ENDIAN)
#define htonll(x) (x)
#elif defined(__LITTLE_ENDIAN)
#define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#else
#error "Cannot determine endianness"
#endif
#endif

#ifndef ntohll
#if defined(__BIG_ENDIAN)
#define ntohll(x) (x)
#elif defined(__LITTLE_ENDIAN)
#define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else
#error "Cannot determine endianness"
#endif
#endif

#define PANDA_SWAP(a, b) do {					\
	typeof(a) __tmp = (a); (a) = (b); (b) = __tmp;		\
} while (0)

#define __PANDA_COMBINE1(X, Y, Z) X##Y##Z
#define __PANDA_COMBINE(X, Y, Z) __PANDA_COMBINE1(X, Y, Z)

#ifdef __COUNTER__
#define PANDA_UNIQUE_NAME(PREFIX, SUFFIX)				\
			__PANDA_COMBINE(PREFIX, __COUNTER__, SUFFIX)
#else
#define PANDA_UNIQUE_NAME(PREFIX, SUFFIX)				\
			__PANDA_COMBINE(PREFIX, __LINE__, SUFFIX)
#endif

/* Debug error and warning macros that call errx and warnx. If PANDA_NO_DEBUG
 * is set then macros are null definitons
 */

#ifdef PANDA_NO_DEBUG

#define PANDA_WARN(...)
#define PANDA_ERR(RET, ...)
#define PANDA_WARN_ONCE(...)
#define PANDA_ASSERT(...)

#elif defined(__KERNEL__)

#define PANDA_WARN(...)
#define PANDA_ERR(RET, ...)
#define PANDA_WARN_ONCE(...)
#define PANDA_ASSERT(...)

#elif defined(__KERNEL__)

#define PANDA_WARN(...)
#define PANDA_ERR(RET, ...)
#define PANDA_WARN_ONCE(...)

#else

#define PANDA_WARN(...) warnx(__VA_ARGS__)
#define PANDA_ERR(RET, ...) errx((RET), __VA_ARGS__)
#define PANDA_WARN_ONCE(...) do {					\
	static bool warned;						\
									\
	if (!warned) {							\
		PANDA_WARN(__VA_ARGS__);				\
		warned = true;						\
	}								\
} while (0)

#define PANDA_ASSERT(COND, ...) do {					\
	if (!COND)							\
		PANDA_ERR(-1, __VA_ARGS__);				\
} while (0)

#endif

#ifndef __KERNEL__

/* Userspace only defines */

#define PANDA_NSEC_PER_SEC 1000000000

static inline void
panda_timespec_add_nsec(struct timespec *r, const struct timespec *a, __u64 b)
{
	r->tv_sec = a->tv_sec + (b / PANDA_NSEC_PER_SEC);
	r->tv_nsec = a->tv_nsec + (b % PANDA_NSEC_PER_SEC);

	if (r->tv_nsec >= PANDA_NSEC_PER_SEC) {
		r->tv_sec++;
		r->tv_nsec -= PANDA_NSEC_PER_SEC;
	} else if (r->tv_nsec < 0) {
		r->tv_sec--;
		r->tv_nsec += PANDA_NSEC_PER_SEC;
	}
}

#endif /* __KERNEL__ */

#endif /* __PANDA_UTILITY_H__ */
