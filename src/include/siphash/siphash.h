/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-or-later */

/* Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 */

#ifndef __SIPHASH_H__
#define __SIPHASH_H__

/* Adapted from kernel include/linux/siphash.h */

#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#endif

#define SIPHASH_ALIGNMENT __alignof__(__u64)
typedef struct {
	__u64 key[2];
} siphash_key_t;

static inline bool siphash_key_is_zero(const siphash_key_t *key)
{
	return !(key->key[0] | key->key[1]);
}

__u64 __siphash_aligned(const void *data, size_t len, const siphash_key_t *key);
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
__u64 __siphash_unaligned(const void *data, size_t len,
			  const siphash_key_t *key);
#endif

__u64 siphash_1u64(const __u64 a, const siphash_key_t *key);
__u64 siphash_2u64(const __u64 a, const __u64 b, const siphash_key_t *key);
__u64 siphash_3u64(const __u64 a, const __u64 b, const __u64 c,
		 const siphash_key_t *key);
__u64 siphash_4u64(const __u64 a, const __u64 b, const __u64 c, const __u64 d,
		 const siphash_key_t *key);
__u64 siphash_1u32(const __u32 a, const siphash_key_t *key);
__u64 siphash_3u32(const __u32 a, const __u32 b, const __u32 c,
		 const siphash_key_t *key);

static inline __u64 siphash_2u32(const __u32 a, const __u32 b,
			       const siphash_key_t *key)
{
	return siphash_1u64((__u64)b << 32 | a, key);
}
static inline __u64 siphash_4u32(const __u32 a, const __u32 b, const __u32 c,
			       const __u32 d, const siphash_key_t *key)
{
	return siphash_2u64((__u64)b << 32 | a, (__u64)d << 32 | c, key);
}


static inline __u64 ___siphash_aligned(const __le64 *data, size_t len,
				     const siphash_key_t *key)
{
	if (__builtin_constant_p(len) && len == 4)
		return siphash_1u32(__le32_to_cpup((const __le32 *)data), key);
	if (__builtin_constant_p(len) && len == 8)
		return siphash_1u64(__le64_to_cpu(data[0]), key);
	if (__builtin_constant_p(len) && len == 16)
		return siphash_2u64(__le64_to_cpu(data[0]),
				    __le64_to_cpu(data[1]),
				    key);
	if (__builtin_constant_p(len) && len == 24)
		return siphash_3u64(__le64_to_cpu(data[0]),
				    __le64_to_cpu(data[1]),
				    __le64_to_cpu(data[2]), key);
	if (__builtin_constant_p(len) && len == 32)
		return siphash_4u64(__le64_to_cpu(data[0]),
				    __le64_to_cpu(data[1]),
				    __le64_to_cpu(data[2]),
				    __le64_to_cpu(data[3]), key);
	return __siphash_aligned(data, len, key);
}

/**
 * siphash - compute 64-bit siphash PRF value
 * @data: buffer to hash
 * @size: size of @data
 * @key: the siphash key
 */
static inline __u64 siphash(const void *data, size_t len,
			  const siphash_key_t *key)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (!IS_ALIGNED((unsigned long)data, SIPHASH_ALIGNMENT))
		return __siphash_unaligned(data, len, key);
#endif
	return ___siphash_aligned(data, len, key);
}

#define HSIPHASH_ALIGNMENT __alignof__(unsigned long)
typedef struct {
	unsigned long key[2];
} hsiphash_key_t;

__u32 __hsiphash_aligned(const void *data, size_t len,
		       const hsiphash_key_t *key);
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
__u32 __hsiphash_unaligned(const void *data, size_t len,
			 const hsiphash_key_t *key);
#endif

__u32 hsiphash_1u32(const __u32 a, const hsiphash_key_t *key);
__u32 hsiphash_2u32(const __u32 a, const __u32 b, const hsiphash_key_t *key);
__u32 hsiphash_3u32(const __u32 a, const __u32 b, const __u32 c,
		  const hsiphash_key_t *key);
__u32 hsiphash_4u32(const __u32 a, const __u32 b, const __u32 c,
		    const __u32 d, const hsiphash_key_t *key);

static inline __u32 ___hsiphash_aligned(const __le32 *data, size_t len,
					const hsiphash_key_t *key)
{
	if (__builtin_constant_p(len) && len == 4)
		return hsiphash_1u32(__le32_to_cpu(data[0]), key);
	if (__builtin_constant_p(len) && len == 8)
		return hsiphash_2u32(__le32_to_cpu(data[0]),
				     __le32_to_cpu(data[1]), key);
	if (__builtin_constant_p(len) && len == 12)
		return hsiphash_3u32(__le32_to_cpu(data[0]),
				     __le32_to_cpu(data[1]),
				     __le32_to_cpu(data[2]), key);
	if (__builtin_constant_p(len) && len == 16)
		return hsiphash_4u32(__le32_to_cpu(data[0]),
				     __le32_to_cpu(data[1]),
				     __le32_to_cpu(data[2]),
				     __le32_to_cpu(data[3]), key);
	return __hsiphash_aligned(data, len, key);
}

/**
 * hsiphash - compute 32-bit hsiphash PRF value
 * @data: buffer to hash
 * @size: size of @data
 * @key: the hsiphash key
 */
static inline __u32 hsiphash(const void *data, size_t len,
			   const hsiphash_key_t *key)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (!IS_ALIGNED((unsigned long)data, HSIPHASH_ALIGNMENT))
		return __hsiphash_unaligned(data, len, key);
#endif
	return ___hsiphash_aligned(data, len, key);
}

#endif /* __FLOWDIS_SIPHASH_H __*/
