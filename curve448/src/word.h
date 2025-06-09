/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 * Modifications Copyright 2020 David Schatz
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef WORD_H
#define WORD_H

#include "arch32_intrinsics.h"
#include "curve448utils.h"

#if (ARCH_WORD_BITS == 64)
typedef uint64_t word_t, mask_t;
typedef __uint128_t dword_t;
typedef int32_t hsword_t;
typedef int64_t sword_t;
typedef __int128_t dsword_t;
#elif (ARCH_WORD_BITS == 32)
typedef uint32_t word_t, mask_t;
typedef uint64_t dword_t;
typedef int16_t hsword_t;
typedef int32_t sword_t;
typedef int64_t dsword_t;
#else
#error "For now, we only support 32- and 64-bit architectures."
#endif

/*
 * Scalar limbs are keyed off of the API word size instead of the arch word
 * size.
 */
#if C448_WORD_BITS == 64
#define SC_LIMB(x) (x)
#elif C448_WORD_BITS == 32
#define SC_LIMB(x) ((uint32_t)(x)), ((x) >> 32)
#else
#error "For now we only support 32- and 64-bit architectures."
#endif

/*
 * The plan on booleans: The external interface uses c448_bool_t, but this
 * might be a different size than our particular arch's word_t (and thus
 * mask_t).  Also, the caller isn't guaranteed to pass it as nonzero.  So
 * bool_to_mask converts word sizes and checks nonzero. On the flip side,
 * mask_t is always -1 or 0, but it might be a different size than
 * c448_bool_t. On the third hand, we have success vs boolean types, but
 * that's handled in common.h: it converts between c448_bool_t and
 * c448_error_t.
 */
static inline c448_bool_t mask_to_bool(mask_t m)
{
	return (c448_word_t)(sword_t)m;
}

static inline mask_t bool_to_mask(c448_bool_t m)
{
	/* On most arches this will be optimized to a simple cast. */
	mask_t ret = 0;
	unsigned int i;
	unsigned int limit = sizeof(c448_bool_t) / sizeof(mask_t);

	if (limit < 1)
		limit = 1;
	for (i = 0; i < limit; i++)
		ret |= ~word_is_zero((uint32_t)(m >> (i * 8 * sizeof(word_t))));

	return ret;
}

#endif /* WORD_H */
