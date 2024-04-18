/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef EXT_X86_AVX512FINTRIN_H
#define EXT_X86_AVX512FINTRIN_H

#ifndef __AVX512F__
#pragma GCC push_options
#pragma GCC target("avx512f")
#define __DISABLE_AVX512F__
#endif /* __AVX512F__ */

typedef unsigned char __mmask8;
typedef long long __v8di __attribute__((__vector_size__(64)));
typedef long long __m512i __attribute__((__vector_size__(64), __may_alias__));

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_setzero_si512(void)
{
	return __extension__(__m512i)(__v8di){ 0, 0, 0, 0, 0, 0, 0, 0 };
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_undefined_epi32(void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winit-self"
	__m512i __Y = __Y;
#pragma GCC diagnostic pop
	return __Y;
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_set_epi64(long long __A, long long __B, long long __C,
			 long long __D, long long __E, long long __F,
			 long long __G, long long __H)
{
	return __extension__(__m512i)(__v8di){ __H, __G, __F, __E,
					       __D, __C, __B, __A };
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_maskz_permutexvar_epi64(__mmask8 __M, __m512i __X, __m512i __Y)
{
	return (__m512i)__builtin_ia32_permvardi512_mask(
		(__v8di)__Y, (__v8di)__X, (__v8di)_mm512_setzero_si512(), __M);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_permutexvar_epi64(__m512i __X, __m512i __Y)
{
	return (__m512i)__builtin_ia32_permvardi512_mask(
		(__v8di)__Y, (__v8di)__X, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_rorv_epi64(__m512i __A, __m512i __B)
{
	return (__m512i)__builtin_ia32_prorvq512_mask(
		(__v8di)__A, (__v8di)__B, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)-1);
}

#define _mm512_ternarylogic_epi64(A, B, C, I)                                  \
	((__m512i)__builtin_ia32_pternlogq512_mask(                            \
		(__v8di)(__m512i)(A), (__v8di)(__m512i)(B),                    \
		(__v8di)(__m512i)(C), (unsigned char)(I), (__mmask8) - 1))

#ifdef __DISABLE_AVX512F__
#undef __DISABLE_AVX512F__
#pragma GCC pop_options
#endif /* __DISABLE_AVX512F__ */

#endif /* EXT_X86_AVX512FINTRIN_H */
