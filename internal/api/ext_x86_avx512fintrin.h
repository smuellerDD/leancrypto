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

#define _MM_CMPINT_EQ       0x0

typedef unsigned long long __v8du __attribute__ ((__vector_size__ (64)));
typedef short __v32hi __attribute__ ((__vector_size__ (64)));
typedef char __v64qi __attribute__ ((__vector_size__ (64)));
typedef unsigned short __v32hu __attribute__ ((__vector_size__ (64)));
typedef int __v16si __attribute__ ((__vector_size__ (64)));
typedef unsigned int __v16su __attribute__ ((__vector_size__ (64)));
typedef unsigned char __mmask8;
typedef unsigned short __mmask16;
typedef long long __v8di __attribute__((__vector_size__(64)));
typedef long long __m512i __attribute__((__vector_size__(64), __may_alias__));
typedef double __m512d __attribute__ ((__vector_size__ (64), __may_alias__));

typedef long long __m512i_u __attribute__ ((__vector_size__ (64), __may_alias__, __aligned__ (1)));

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

extern __inline __m512d
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_undefined_pd (void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winit-self"
  __m512d __Y = __Y;
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

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_loadu_si512 (void const *__P)
{
  return *(__m512i_u *)__P;
}

extern __inline void
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_storeu_si512 (void *__P, __m512i __A)
{
  *(__m512i_u *)__P = __A;
}

extern __inline void
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_mask_storeu_epi64 (void *__P, __mmask8 __U, __m512i __A)
{
  __builtin_ia32_storedqudi512_mask ((long long *) __P, (__v8di) __A,
                                     (__mmask8) __U);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_set1_epi64 (long long __A)
{
  return (__m512i)(__v8di) { __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_add_epi64 (__m512i __A, __m512i __B)
{
  return (__m512i) ((__v8du) __A + (__v8du) __B);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_permutex2var_epi64 (__m512i __A, __m512i __I, __m512i __B)
{
  return (__m512i) __builtin_ia32_vpermt2varq512_mask ((__v8di) __I
                                                       /* idx */ ,
                                                       (__v8di) __A,
                                                       (__v8di) __B,
                                                       (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_srlv_epi64 (__m512i __X, __m512i __Y)
{
  return (__m512i) __builtin_ia32_psrlv8di_mask ((__v8di) __X,
                                                 (__v8di) __Y,
                                                 (__v8di)
                                                 _mm512_undefined_epi32 (),
                                                 (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_sllv_epi64 (__m512i __X, __m512i __Y)
{
  return (__m512i) __builtin_ia32_psllv8di_mask ((__v8di) __X,
                                                 (__v8di) __Y,
                                                 (__v8di)
                                                 _mm512_undefined_pd (),
                                                 (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_mask_xor_epi64 (__m512i __W, __mmask8 __U, __m512i __A, __m512i __B)
{
  return (__m512i) __builtin_ia32_pxorq512_mask ((__v8di) __A,
                                                 (__v8di) __B,
                                                 (__v8di) __W,
                                                 (__mmask8) __U);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_alignr_epi64 (__m512i __A, __m512i __B, const int __imm)
{
  return (__m512i) __builtin_ia32_alignq512_mask ((__v8di) __A,
                                                  (__v8di) __B, __imm,
                                                  (__v8di)
                                                  _mm512_undefined_epi32 (),
                                                  (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_mask_or_epi64 (__m512i __W, __mmask8 __U, __m512i __A, __m512i __B)
{
  return (__m512i) __builtin_ia32_porq512_mask ((__v8di) __A,
                                                (__v8di) __B,
                                                (__v8di) __W,
                                                (__mmask8) __U);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_set1_epi16 (short __A)
{
  return __extension__ (__m512i)(__v32hi)
         { __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_set1_epi8 (char __A)
{
  return __extension__ (__m512i)(__v64qi)
         { __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A,
           __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_set1_epi32 (int __A)
{
  return (__m512i)(__v16si)
    { __A, __A, __A, __A, __A, __A, __A, __A,
      __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_add_epi32 (__m512i __A, __m512i __B)
{
  return (__m512i) ((__v16su) __A + (__v16su) __B);
}

extern __inline __mmask16
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_cmp_epu32_mask (__m512i __X, __m512i __Y, const int __P)
{
  return (__mmask16) __builtin_ia32_ucmpd512_mask ((__v16si) __X,
                                                   (__v16si) __Y, __P,
                                                   (__mmask16) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_mask_sub_epi32 (__m512i __W, __mmask16 __U, __m512i __A, __m512i __B)
{
  return (__m512i) __builtin_ia32_psubd512_mask ((__v16si) __A,
                                                 (__v16si) __B,
                                                 (__v16si) __W,
                                                 (__mmask16) __U);
}

#ifdef __OPTIMIZE__
extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_slli_epi64 (__m512i __A, unsigned int __B)
{
  return (__m512i) __builtin_ia32_psllqi512_mask ((__v8di) __A, (int)__B,
                                                  (__v8di)
                                                  _mm512_undefined_epi32 (),
                                                  (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_srli_epi64 (__m512i __A, unsigned int __B)
{
  return (__m512i) __builtin_ia32_psrlqi512_mask ((__v8di) __A, (int)__B,
                                                  (__v8di)
                                                  _mm512_undefined_epi32 (),
                                                  (__mmask8) -1);
}

extern __inline __m512i
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_permutex_epi64 (__m512i __X, const int __I)
{
  return (__m512i) __builtin_ia32_permdi512_mask ((__v8di) __X, __I,
                                                  (__v8di)
                                                  _mm512_undefined_epi32 (),
                                                  (__mmask8) (-1));
}

extern __inline __mmask8
__attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
_mm512_cmp_epi64_mask (__m512i __X, __m512i __Y, const int __P)
{
  return (__mmask8) __builtin_ia32_cmpq512_mask ((__v8di) __X,
                                                 (__v8di) __Y, __P,
                                                 (__mmask8) -1);
}

#else

#define _mm512_slli_epi64(X, C)                                            \
  ((__m512i) __builtin_ia32_psllqi512_mask ((__v8di)(__m512i)(X), (int)(C),\
    (__v8di)(__m512i)_mm512_undefined_epi32 (),\
    (__mmask8)-1))

#define _mm512_srli_epi64(X, C)                                            \
  ((__m512i) __builtin_ia32_psrlqi512_mask ((__v8di)(__m512i)(X), (int)(C),\
    (__v8di)(__m512i)_mm512_undefined_epi32 (),\
    (__mmask8)-1))

#define _mm512_permutex_epi64(X, I)                               \
  ((__m512i) __builtin_ia32_permdi512_mask ((__v8di)(__m512i)(X), \
                                            (int)(I),             \
                                            (__v8di)(__m512i)     \
                                            (_mm512_undefined_epi32 ()),\
                                            (__mmask8)(-1)))

#define _mm512_cmp_epi64_mask(X, Y, P)                                  \
  ((__mmask8) __builtin_ia32_cmpq512_mask ((__v8di)(__m512i)(X),        \
                                           (__v8di)(__m512i)(Y), (int)(P),\
                                           (__mmask8)-1))

#endif /* OPTIMIZE */

#ifdef __DISABLE_AVX512F__
#undef __DISABLE_AVX512F__
#pragma GCC pop_options
#endif /* __DISABLE_AVX512F__ */

#endif /* EXT_X86_AVX512FINTRIN_H */
