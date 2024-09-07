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

#ifndef EXT_X86_VPCLMULQDQINTRIN_H
#define EXT_X86_VPCLMULQDQINTRIN_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__VPCLMULQDQ__) || !defined(__AVX512F__)
#pragma GCC push_options
#pragma GCC target("vpclmulqdq,avx512f")
#define __DISABLE_VPCLMULQDQF__
#endif /* __VPCLMULQDQF__ */

#ifdef __OPTIMIZE__
extern __inline __m512i
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm512_clmulepi64_epi128 (__m512i __A, __m512i __B, const int __C)
{
  return (__m512i) __builtin_ia32_vpclmulqdq_v8di ((__v8di)__A,
                                                  (__v8di) __B, __C);
}
#else
#define _mm512_clmulepi64_epi128(A, B, C)                                  \
  ((__m512i) __builtin_ia32_vpclmulqdq_v8di ((__v8di)(__m512i)(A),      \
                                (__v8di)(__m512i)(B), (int)(C)))
#endif

#ifdef __DISABLE_VPCLMULQDQ__
#undef __DISABLE_VPCLMULQDQ__
#pragma GCC pop_options
#endif /* __DISABLE_VPCLMULQDQ__ */

#ifdef __cplusplus
}
#endif

#endif /* EXT_X86_VPCLMULQDQINTRIN_H */
