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

#ifndef EXT_X86_AVX512BWINTRIN_H
#define EXT_X86_AVX512BWINTRIN_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __AVX512BW__
#pragma GCC push_options
#pragma GCC target("avx512bw")
#define __DISABLE_AVX512BW__
#endif /* __AVX512BW__ */

typedef unsigned long long __mmask64;

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_add_epi16 (__m512i __A, __m512i __B)
{
  return (__m512i) ((__v32hu) __A + (__v32hu) __B);
}

extern __inline __mmask32
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_cmp_epu16_mask (__m512i __X, __m512i __Y, const int __P)
{
  return (__mmask32) __builtin_ia32_ucmpw512_mask ((__v32hi) __X,
                                                   (__v32hi) __Y, __P,
                                                   (__mmask32) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_mask_sub_epi16 (__m512i __W, __mmask32 __U, __m512i __A,
                       __m512i __B)
{
  return (__m512i) __builtin_ia32_psubw512_mask ((__v32hi) __A,
                                                 (__v32hi) __B,
                                                 (__v32hi) __W,
                                                 (__mmask32) __U);
}

extern __inline __mmask64
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_cmp_epu8_mask (__m512i __X, __m512i __Y, const int __P)
{
  return (__mmask64) __builtin_ia32_ucmpb512_mask ((__v64qi) __X,
                                                   (__v64qi) __Y, __P,
                                                   (__mmask64) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_maskz_set1_epi8 (__mmask64 __M, char __A)
{
  return (__m512i)
         __builtin_ia32_pbroadcastb512_gpr_mask (__A,
                                                 (__v64qi)
                                                 _mm512_setzero_si512 (),
                                                 __M);
}

#ifdef __DISABLE_AVX512BW__
#undef __DISABLE_AVX512BW__
#pragma GCC pop_options
#endif /* __DISABLE_AVX512BW__ */

#ifdef __cplusplus
}
#endif

#endif /* EXT_X86_AVX512BWINTRIN_H */
