/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef EXT_X86_EMMINTRIN_H
#define EXT_X86_EMMINTRIN_H

typedef int __v4si __attribute__((__vector_size__(16)));

typedef double __m128d __attribute__((__vector_size__(16), __aligned__(16)));

typedef long long __m128i __attribute__((__vector_size__(16), __aligned__(16)));
typedef long long __m128i_u
	__attribute__((__vector_size__(16), __aligned__(1)));

typedef long long __v2di __attribute__((__vector_size__(16)));

typedef short __v8hi __attribute__((__vector_size__(16)));
typedef char __v16qi __attribute__((__vector_size__(16)));

typedef unsigned long long __v2du __attribute__((__vector_size__(16)));
typedef unsigned char __v16qu __attribute__((__vector_size__(16)));

typedef signed char __v16qs __attribute__((__vector_size__(16)));

/* Create a selector for use with the SHUFPD instruction.  */
#define _MM_SHUFFLE2(fp1, fp0) (((fp1) << 1) | (fp0))

/* Define the default attributes for the functions in this file. */
#ifdef __clang__
#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__always_inline__, __nodebug__, __target__("mmx"),      \
		       __min_vector_width__(64)))
#else

#ifndef __SSE2__
#pragma GCC push_options
#pragma GCC target("sse2")
#define __DISABLE_SSE2__
#endif /* __SSE2__ */

#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
#endif

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_srli_epi16(__m128i __a,
							    int __count)
{
	return (__m128i)__builtin_ia32_psrlwi128((__v8hi)__a, __count);
}

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_and_si128(__m128i __a,
							   __m128i __b)
{
	return (__m128i)((__v2du)__a & (__v2du)__b);
}

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_cmpgt_epi16(__m128i __a,
							     __m128i __b)
{
	return (__m128i)((__v8hi)__a > (__v8hi)__b);
}

static __inline__ int __DEFAULT_FN_ATTRS _mm_movemask_epi8(__m128i __a)
{
	return __builtin_ia32_pmovmskb128((__v16qi)__a);
}

static __inline__ __m128i __DEFAULT_FN_ATTRS
_mm_loadl_epi64(__m128i_u const *__p)
{
	struct __mm_loadl_epi64_struct {
		long long __u;
	} __attribute__((__packed__, __may_alias__));
	return __extension__(__m128i){
		((const struct __mm_loadl_epi64_struct *)__p)->__u, 0
	};
}

#ifdef __clang__

#define _mm_bsrli_si128(a, imm)                                                \
	((__m128i)__builtin_ia32_psrldqi128_byteshift((__v2di)(__m128i)(a),    \
						      (int)(imm)))

#else

#ifdef __OPTIMIZE__
extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_bsrli_si128(__m128i __A, const int __N)
{
	return (__m128i)__builtin_ia32_psrldqi128(__A, __N * 8);
}

#else

#define _mm_bsrli_si128(A, N)                                                  \
	((__m128i)__builtin_ia32_psrldqi128((__m128i)(A), (int)(N) * 8))

#endif

#endif

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_add_epi8(__m128i __a,
							  __m128i __b)
{
	return (__m128i)((__v16qu)__a + (__v16qu)__b);
}

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_unpacklo_epi8(__m128i __a,
							       __m128i __b)
{
	return (__m128i)__builtin_shufflevector((__v16qi)__a, (__v16qi)__b, 0,
						16 + 0, 1, 16 + 1, 2, 16 + 2, 3,
						16 + 3, 4, 16 + 4, 5, 16 + 5, 6,
						16 + 6, 7, 16 + 7);
}

static __inline__ void __DEFAULT_FN_ATTRS _mm_storeu_si128(__m128i_u *__p,
							   __m128i __b)
{
	struct __storeu_si128 {
		__m128i_u __v;
	} __attribute__((__packed__, __may_alias__));
	((struct __storeu_si128 *)__p)->__v = __b;
}

static __inline__ __m128i __DEFAULT_FN_ATTRS
_mm_loadu_si128(__m128i_u const *__p)
{
	struct __loadu_si128 {
		__m128i_u __v;
	} __attribute__((__packed__, __may_alias__));
	return ((const struct __loadu_si128 *)__p)->__v;
}

static __inline__ __m128d __DEFAULT_FN_ATTRS _mm_castsi128_pd(__m128i __a)
{
	return (__m128d)__a;
}

static __inline__ void __DEFAULT_FN_ATTRS _mm_storel_pd(double *__dp,
							__m128d __a)
{
	struct __mm_storeh_pd_struct {
		double __u;
	} __attribute__((__packed__, __may_alias__));
	((struct __mm_storeh_pd_struct *)__dp)->__u = __a[0];
}

static __inline__ void __DEFAULT_FN_ATTRS _mm_storeh_pd(double *__dp,
							__m128d __a)
{
	struct __mm_storeh_pd_struct {
		double __u;
	} __attribute__((__packed__, __may_alias__));
	((struct __mm_storeh_pd_struct *)__dp)->__u = __a[1];
}

static __inline__ __m128i __DEFAULT_FN_ATTRS
_mm_set_epi8(char __b15, char __b14, char __b13, char __b12, char __b11,
	     char __b10, char __b9, char __b8, char __b7, char __b6, char __b5,
	     char __b4, char __b3, char __b2, char __b1, char __b0)
{
	return __extension__(__m128i)(__v16qi){ __b0,  __b1,  __b2,  __b3,
						__b4,  __b5,  __b6,  __b7,
						__b8,  __b9,  __b10, __b11,
						__b12, __b13, __b14, __b15 };
}

extern __inline__ __m128i __DEFAULT_FN_ATTRS _mm_set_epi32(int __i3, int __i2,
							   int __i1, int __i0)
{
	return __extension__(__m128i)(__v4si){ __i0, __i1, __i2, __i3 };
}

static __inline__ __m128i __DEFAULT_FN_ATTRS _mm_set1_epi32(int __i)
{
	return _mm_set_epi32(__i, __i, __i, __i);
}

#define _mm_insert_epi16(a, b, imm)                                            \
	((__m128i)__builtin_ia32_vec_set_v8hi((__v8hi)(__m128i)(a),            \
					      (short)(b), (int)(imm)))

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_unpacklo_epi64(__m128i __A, __m128i __B)
{
	return (__m128i)__builtin_ia32_punpcklqdq128((__v2di)__A, (__v2di)__B);
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_unpackhi_epi64(__m128i __A, __m128i __B)
{
	return (__m128i)__builtin_ia32_punpckhqdq128((__v2di)__A, (__v2di)__B);
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_bslli_si128(__m128i __A, const int __N)
{
	return (__m128i)__builtin_ia32_pslldqi128(__A, __N * 8);
}

extern __inline int
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_cvtsi128_si32(__m128i __A)
{
	return __builtin_ia32_vec_ext_v4si((__v4si)__A, 0);
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_xor_si128(__m128i __A, __m128i __B)
{
	return (__m128i)((__v2du)__A ^ (__v2du)__B);
}

/* Create a vector of zeros.  */
extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_setzero_si128(void)
{
	return __extension__(__m128i)(__v4si){ 0, 0, 0, 0 };
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_shuffle_epi32(__m128i __A, const int __mask)
{
	return (__m128i)__builtin_ia32_pshufd((__v4si)__A, __mask);
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_cvtsi32_si128(int __A)
{
	return _mm_set_epi32(0, 0, 0, __A);
}
extern __inline void
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_store_si128(__m128i *__P, __m128i __B)
{
	*__P = __B;
}

extern __inline __m128i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm_load_si128(__m128i const *__P)
{
	return *__P;
}

#undef __DEFAULT_FN_ATTRS

#endif /* EXT_X86_EMMINTRIN_H */
