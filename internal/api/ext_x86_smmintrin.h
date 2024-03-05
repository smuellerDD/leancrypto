/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from GCC (GPLv3) and the LLVM project (Apache
 * License v2.0).
 *
 * The only reason why this code is duplicated is the fact that the compiler
 * code cannot be included into kernel code code as is. Thus, the functions
 * used by leancrypto are extracted - I wished this would not have been
 * necessary.
 */

#ifndef EXT_X86_SMMINTRIN_H
#define EXT_X86_SMMINTRIN_H

#include "ext_x86_tmmintrin.h"

#ifdef __clang__

#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__always_inline__, __nodebug__, __target__("sse4.1"),   \
		       __min_vector_width__(128)))

#else

#ifndef __SSE4_1__
#pragma GCC push_options
#pragma GCC target("sse4.1")
#define __DISABLE_SSE4_1__
#endif /* __SSE4_1__ */

#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))

#endif

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_blendv_epi8(__m128i __V1,
							     __m128i __V2,
							     __m128i __M)
{
	return (__m128i)__builtin_ia32_pblendvb128((__v16qi)__V1, (__v16qi)__V2,
						   (__v16qi)__M);
}

#define _mm_blend_epi16(V1, V2, M)                                             \
	((__m128i)__builtin_ia32_pblendw128((__v8hi)(__m128i)(V1),             \
					    (__v8hi)(__m128i)(V2), (int)(M)))

#undef __DEFAULT_FN_ATTRS

#endif /* EXT_X86_SMMINTRIN_H */
