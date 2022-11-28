/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef EXT_X86_AVX2INTRIN_H
#define EXT_X86_AVX2INTRIN_H

typedef unsigned int __v8su __attribute__ ((__vector_size__ (32)));

#ifdef __clang__

#define __DEFAULT_FN_ATTRS256 __attribute__((__always_inline__, __nodebug__, __target__("avx2"), __min_vector_width__(256)))

#else

#ifndef __AVX2__
#pragma GCC push_options
#pragma GCC target("avx2")
#define __DISABLE_AVX2__
#endif /* __AVX2__ */

#define __DEFAULT_FN_ATTRS256 __attribute__ ((__gnu_inline__, __always_inline__, __artificial__))

#endif

#define _mm256_permute4x64_epi64(V, M) \
  ((__m256i)__builtin_ia32_permdi256((__v4di)(__m256i)(V), (int)(M)))

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_shuffle_epi8(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_pshufb256((__v32qi)__a, (__v32qi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srli_epi16(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_psrlwi256((__v16hi)__a, __count);
}

#define _mm256_blend_epi16(V1, V2, M) \
  ((__m256i)__builtin_ia32_pblendw256((__v16hi)(__m256i)(V1), \
                                      (__v16hi)(__m256i)(V2), (int)(M)))

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_and_si256(__m256i __a, __m256i __b)
{
  return (__m256i)((__v4du)__a & (__v4du)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cmpgt_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)((__v16hi)__a > (__v16hi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_packs_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_packsswb256((__v16hi)__a, (__v16hi)__b);
}

static __inline__ int __DEFAULT_FN_ATTRS256
_mm256_movemask_epi8(__m256i __a)
{
  return __builtin_ia32_pmovmskb256((__v32qi)__a);
}

#define _mm256_inserti128_si256(V1, V2, M) \
  ((__m256i)__builtin_ia32_insert128i256((__v4di)(__m256i)(V1), \
                                         (__v2di)(__m128i)(V2), (int)(M)))

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_add_epi8(__m256i __a, __m256i __b)
{
  return (__m256i)((__v32qu)__a + (__v32qu)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_unpacklo_epi8(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_shufflevector((__v32qi)__a, (__v32qi)__b, 0, 32+0, 1, 32+1, 2, 32+2, 3, 32+3, 4, 32+4, 5, 32+5, 6, 32+6, 7, 32+7, 16, 32+16, 17, 32+17, 18, 32+18, 19, 32+19, 20, 32+20, 21, 32+21, 22, 32+22, 23, 32+23);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_unpackhi_epi8(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_shufflevector((__v32qi)__a, (__v32qi)__b, 8, 32+8, 9, 32+9, 10, 32+10, 11, 32+11, 12, 32+12, 13, 32+13, 14, 32+14, 15, 32+15, 24, 32+24, 25, 32+25, 26, 32+26, 27, 32+27, 28, 32+28, 29, 32+29, 30, 32+30, 31, 32+31);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_sub_epi8(__m256i __a, __m256i __b)
{
  return (__m256i)((__v32qu)__a - (__v32qu)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cvtepi8_epi16(__m128i __V)
{
  /* This function always performs a signed extension, but __v16qi is a char
     which may be signed or unsigned, so use __v16qs. */
  return (__m256i)__builtin_convertvector((__v16qs)__V, __v16hi);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_mulhi_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_pmulhw256((__v16hi)__a, (__v16hi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_mulhrs_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_pmulhrsw256((__v16hi)__a, (__v16hi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_packus_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_packuswb256((__v16hi)__a, (__v16hi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_maddubs_epi16(__m256i __a, __m256i __b)
{
    return (__m256i)__builtin_ia32_pmaddubsw256((__v32qi)__a, (__v32qi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_madd_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_pmaddwd256((__v16hi)__a, (__v16hi)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_sllv_epi32(__m256i __X, __m256i __Y)
{
  return (__m256i)__builtin_ia32_psllv8si((__v8si)__X, (__v8si)__Y);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srlv_epi64(__m256i __X, __m256i __Y)
{
  return (__m256i)__builtin_ia32_psrlv4di((__v4di)__X, (__v4di)__Y);
}

#define _mm256_extracti128_si256(V, M) \
  ((__m128i)__builtin_ia32_extract128i256((__v4di)(__m256i)(V), (int)(M)))


static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_broadcastsi128_si256(__m128i __X)
{
  return (__m256i)__builtin_shufflevector((__v2di)__X, (__v2di)__X, 0, 1, 0, 1);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_mullo_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)((__v16hu)__a * (__v16hu)__b);
}

#define _mm256_shuffle_epi32(a, imm) \
  ((__m256i)__builtin_ia32_pshufd256((__v8si)(__m256i)(a), (int)(imm)))

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_slli_epi16(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_psllwi256((__v16hi)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srai_epi16(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_psrawi256((__v16hi)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_unpacklo_epi64(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_shufflevector((__v4di)__a, (__v4di)__b, 0, 4+0, 2, 4+2);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_unpackhi_epi64(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_shufflevector((__v4di)__a, (__v4di)__b, 1, 4+1, 3, 4+3);
}

#define _mm256_permute2x128_si256(V1, V2, M) \
  ((__m256i)__builtin_ia32_permti256((__m256i)(V1), (__m256i)(V2), (int)(M)))

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_add_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)((__v16hu)__a + (__v16hu)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_sub_epi16(__m256i __a, __m256i __b)
{
  return (__m256i)((__v16hu)__a - (__v16hu)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_add_epi32(__m256i __a, __m256i __b)
{
  return (__m256i)((__v8su)__a + (__v8su)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_sub_epi32(__m256i __a, __m256i __b)
{
  return (__m256i)((__v8su)__a - (__v8su)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_mulhi_epu16(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_pmulhuw256((__v16hi)__a, (__v16hi)__b);
}

static __inline__  __m256i __DEFAULT_FN_ATTRS256
_mm256_mullo_epi32 (__m256i __a, __m256i __b)
{
  return (__m256i)((__v8su)__a * (__v8su)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cmpgt_epi32(__m256i __a, __m256i __b)
{
  return (__m256i)((__v8si)__a > (__v8si)__b);
}

#ifdef __clang__

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_abs_epi32(__m256i __a)
{
    return (__m256i)__builtin_elementwise_abs((__v8si)__a);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_slli_epi32(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_pslldi256((__v8si)__a, __count);
}

#define _mm256_i64gather_epi64(m, i, s) \
  ((__m256i)__builtin_ia32_gatherq_q256((__v4di)_mm256_undefined_si256(), \
                                        (long long const *)(m), \
                                        (__v4di)(__m256i)(i), \
                                        (__v4di)_mm256_set1_epi64x(-1), (s)))

#else

extern __inline __m256i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm256_abs_epi32 (__m256i __A)
{
  return (__m256i)__builtin_ia32_pabsd256 ((__v8si)__A);
}

extern __inline __m256i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm256_slli_epi32 (__m256i __A, int __B)
{
  return (__m256i)__builtin_ia32_pslldi256 ((__v8si)__A, __B);
}

extern __inline __m256i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm256_i64gather_epi64 (long long int const *__base,
			__m256i __index, const int __scale)
{
  __v4di __src = __extension__ (__v4di){ 0, 0, 0, 0 };
  __v4di __mask = __extension__ (__v4di){ ~0, ~0, ~0, ~0 };

  return (__m256i) __builtin_ia32_gatherdiv4di (__src,
						__base,
						(__v4di)__index,
						__mask,
						__scale);
}

#endif

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_sign_epi32(__m256i __a, __m256i __b)
{
    return (__m256i)__builtin_ia32_psignd256((__v8si)__a, (__v8si)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_or_si256(__m256i __a, __m256i __b)
{
  return (__m256i)((__v4du)__a | (__v4du)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cvtepu8_epi32(__m128i __V)
{
  return (__m256i)__builtin_convertvector(__builtin_shufflevector((__v16qu)__V, (__v16qu)__V, 0, 1, 2, 3, 4, 5, 6, 7), __v8si);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_permutevar8x32_epi32(__m256i __a, __m256i __b)
{
  return (__m256i)__builtin_ia32_permvarsi256((__v8si)__a, (__v8si)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cvtepu8_epi16(__m128i __V)
{
  return (__m256i)__builtin_convertvector((__v16qu)__V, __v16hi);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cvtepi8_epi32(__m128i __V)
{
  /* This function always performs a signed extension, but __v16qi is a char
     which may be signed or unsigned, so use __v16qs. */
  return (__m256i)__builtin_convertvector(__builtin_shufflevector((__v16qs)__V, (__v16qs)__V, 0, 1, 2, 3, 4, 5, 6, 7), __v8si);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srli_epi32(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_psrldi256((__v8si)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_cmpeq_epi32(__m256i __a, __m256i __b)
{
  return (__m256i)((__v8si)__a == (__v8si)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_xor_si256(__m256i __a, __m256i __b)
{
  return (__m256i)((__v4du)__a ^ (__v4du)__b);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srai_epi32(__m256i __a, int __count)
{
  return (__m256i)__builtin_ia32_psradi256((__v8si)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srlv_epi32(__m256i __X, __m256i __Y)
{
  return (__m256i)__builtin_ia32_psrlv8si((__v8si)__X, (__v8si)__Y);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_packus_epi32(__m256i __V1, __m256i __V2)
{
  return (__m256i) __builtin_ia32_packusdw256((__v8si)__V1, (__v8si)__V2);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_slli_epi64(__m256i __a, int __count)
{
  return __builtin_ia32_psllqi256((__v4di)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_srli_epi64(__m256i __a, int __count)
{
  return __builtin_ia32_psrlqi256((__v4di)__a, __count);
}

static __inline__ __m256i __DEFAULT_FN_ATTRS256
_mm256_andnot_si256(__m256i __a, __m256i __b)
{
  return (__m256i)(~(__v4du)__a & (__v4du)__b);
}

#undef __DEFAULT_FN_ATTRS256

#endif /* EXT_X86_AVX2INTRIN_H */
