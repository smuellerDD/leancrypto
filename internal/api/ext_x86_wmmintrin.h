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

#ifndef EXT_X86_WMMINTRIN_H
#define EXT_X86_WMMINTRIN_H

/* We need definitions from the SSE2 header file.  */
#include "ext_x86_emmintrin.h"

#ifdef __DISABLE_AES__
#undef __DISABLE_AES__
#pragma GCC pop_options
#endif /* __DISABLE_AES__ */

/* PCLMUL */

#if !defined(__PCLMUL__) || !defined(__SSE2__)
#pragma GCC push_options
#pragma GCC target("pclmul,sse2")
#define __DISABLE_PCLMUL__
#endif /* __PCLMUL__ */


#ifdef __cplusplus
extern "C" {
#endif

/* Performs carry-less integer multiplication of 64-bit halves of
   128-bit input operands.  The third parameter inducates which 64-bit
   haves of the input parameters v1 and v2 should be used. It must be
   a compile time constant.  */
#ifdef __OPTIMIZE__
extern __inline __m128i __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_clmulepi64_si128 (__m128i __X, __m128i __Y, const int __I)
{
  return (__m128i) __builtin_ia32_pclmulqdq128 ((__v2di)__X,
                                                (__v2di)__Y, __I);
}
#else
#define _mm_clmulepi64_si128(X, Y, I)                                   \
  ((__m128i) __builtin_ia32_pclmulqdq128 ((__v2di)(__m128i)(X),         \
                                          (__v2di)(__m128i)(Y), (int)(I)))
#endif

#ifdef __DISABLE_PCLMUL__
#undef __DISABLE_PCLMUL__
#pragma GCC pop_options
#endif /* __DISABLE_PCLMUL__ */

#ifdef __cplusplus
}
#endif

#endif /* EXT_X86_WMMINTRIN_H */
