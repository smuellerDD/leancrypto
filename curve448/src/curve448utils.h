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

#ifndef CURVE448UTILS_H
#define CURVE448UTILS_H

#include "ext_headers.h"

/*
 * Internal word types. Somewhat tricky.  This could be decided separately per
 * platform.  However, the structs do need to be all the same size and
 * alignment on a given platform to support dynamic linking, since even if you
 * header was built with eg arch_neon, you might end up linking a library built
 * with arch_arm32.
 */
#ifndef C448_WORD_BITS
#if (defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16)) &&               \
	!defined(__sparc__) &&                                                 \
	(!defined(__SIZEOF_LONG__) || (__SIZEOF_LONG__ == 8))

#define C448_WORD_BITS 64 /* The number of bits in a word */
#else
#define C448_WORD_BITS 32 /* The number of bits in a word */
#endif
#endif

#if C448_WORD_BITS == 64
/* Word size for internal computations */
typedef uint64_t c448_word_t;
/* Signed word size for internal computations */
typedef int64_t c448_sword_t;
/* "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint64_t c448_bool_t;
/* Double-word size for internal computations */
typedef __uint128_t c448_dword_t;
/* Signed double-word size for internal computations */
typedef __int128_t c448_dsword_t;
#elif C448_WORD_BITS == 32
/* Word size for internal computations */
typedef uint32_t c448_word_t;
/* Signed word size for internal computations */
typedef int32_t c448_sword_t;
/* "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint32_t c448_bool_t;
/* Double-word size for internal computations */
typedef uint64_t c448_dword_t;
/* Signed double-word size for internal computations */
typedef int64_t c448_dsword_t;
#else
#error "Only supporting C448_WORD_BITS = 32 or 64 for now"
#endif

/* C448_TRUE = -1 so that C448_TRUE & x = x */
#define C448_TRUE (0 - (c448_bool_t)1)

/* C448_FALSE = 0 so that C448_FALSE & x = 0 */
#define C448_FALSE 0

#endif /* __C448_COMMON_H__ */
