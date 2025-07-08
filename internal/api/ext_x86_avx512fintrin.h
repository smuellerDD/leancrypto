/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#define _MM_CMPINT_EQ 0x0

typedef unsigned long long __v8du __attribute__((__vector_size__(64)));
typedef short __v32hi __attribute__((__vector_size__(64)));
typedef char __v64qi __attribute__((__vector_size__(64)));
typedef unsigned short __v32hu __attribute__((__vector_size__(64)));
typedef int __v16si __attribute__((__vector_size__(64)));
typedef unsigned int __v16su __attribute__((__vector_size__(64)));
typedef unsigned char __mmask8;
typedef unsigned short __mmask16;
typedef long long __v8di __attribute__((__vector_size__(64)));
typedef long long __m512i __attribute__((__vector_size__(64), __may_alias__));
typedef double __m512d __attribute__((__vector_size__(64), __may_alias__));

typedef long long __m512i_u
	__attribute__((__vector_size__(64), __may_alias__, __aligned__(1)));

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
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_undefined_pd(void)
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
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_loadu_si512(void const *__P)
{
	return *(__m512i_u *)__P;
}

extern __inline void
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_storeu_si512(void *__P, __m512i __A)
{
	*(__m512i_u *)__P = __A;
}

extern __inline void
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_mask_storeu_epi64(void *__P, __mmask8 __U, __m512i __A)
{
	__builtin_ia32_storedqudi512_mask((long long *)__P, (__v8di)__A,
					  (__mmask8)__U);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_set1_epi64(long long __A)
{
	return (__m512i)(__v8di){ __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_add_epi64(__m512i __A, __m512i __B)
{
	return (__m512i)((__v8du)__A + (__v8du)__B);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_permutex2var_epi64(__m512i __A, __m512i __I, __m512i __B)
{
	return (__m512i)__builtin_ia32_vpermt2varq512_mask((__v8di)__I
							   /* idx */,
							   (__v8di)__A,
							   (__v8di)__B,
							   (__mmask8)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_srlv_epi64(__m512i __X, __m512i __Y)
{
	return (__m512i)__builtin_ia32_psrlv8di_mask(
		(__v8di)__X, (__v8di)__Y, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_sllv_epi64(__m512i __X, __m512i __Y)
{
	return (__m512i)__builtin_ia32_psllv8di_mask(
		(__v8di)__X, (__v8di)__Y, (__v8di)_mm512_undefined_pd(),
		(__mmask8)-1);
}

extern __inline __m512i __attribute__((__gnu_inline__, __always_inline__,
				       __artificial__))
_mm512_mask_xor_epi64(__m512i __W, __mmask8 __U, __m512i __A, __m512i __B)
{
	return (__m512i)__builtin_ia32_pxorq512_mask(
		(__v8di)__A, (__v8di)__B, (__v8di)__W, (__mmask8)__U);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_alignr_epi64(__m512i __A, __m512i __B, const int __imm)
{
	return (__m512i)__builtin_ia32_alignq512_mask(
		(__v8di)__A, (__v8di)__B, __imm,
		(__v8di)_mm512_undefined_epi32(), (__mmask8)-1);
}

extern __inline __m512i __attribute__((__gnu_inline__, __always_inline__,
				       __artificial__))
_mm512_mask_or_epi64(__m512i __W, __mmask8 __U, __m512i __A, __m512i __B)
{
	return (__m512i)__builtin_ia32_porq512_mask((__v8di)__A, (__v8di)__B,
						    (__v8di)__W, (__mmask8)__U);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_set1_epi16(short __A)
{
	return __extension__(__m512i)(
		__v32hi){ __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
			  __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
			  __A, __A, __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_set1_epi8(char __A)
{
	return __extension__(__m512i)(__v64qi){
		__A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
		__A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
		__A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
		__A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A,
		__A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A, __A
	};
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_set1_epi32(int __A)
{
	return (__m512i)(__v16si){ __A, __A, __A, __A, __A, __A, __A, __A,
				   __A, __A, __A, __A, __A, __A, __A, __A };
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_add_epi32(__m512i __A, __m512i __B)
{
	return (__m512i)((__v16su)__A + (__v16su)__B);
}

extern __inline __mmask16
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_cmp_epu32_mask(__m512i __X, __m512i __Y, const int __P)
{
	return (__mmask16)__builtin_ia32_ucmpd512_mask(
		(__v16si)__X, (__v16si)__Y, __P, (__mmask16)-1);
}

extern __inline __m512i __attribute__((__gnu_inline__, __always_inline__,
				       __artificial__))
_mm512_mask_sub_epi32(__m512i __W, __mmask16 __U, __m512i __A, __m512i __B)
{
	return (__m512i)__builtin_ia32_psubd512_mask(
		(__v16si)__A, (__v16si)__B, (__v16si)__W, (__mmask16)__U);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_xor_si512(__m512i __A, __m512i __B)
{
	return (__m512i)((__v16su)__A ^ (__v16su)__B);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_broadcast_i32x4(__m128i __A)
{
	return (__m512i)__builtin_ia32_broadcasti32x4_512(
		(__v4si)__A, (__v16si)_mm512_undefined_epi32(), (__mmask16)-1);
}

#ifdef __OPTIMIZE__
extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_rol_epi32(__m512i __A, const int __B)
{
	return (__m512i)__builtin_ia32_prold512_mask(
		(__v16si)__A, __B, (__v16si)_mm512_undefined_epi32(),
		(__mmask16)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_slli_epi64(__m512i __A, unsigned int __B)
{
	return (__m512i)__builtin_ia32_psllqi512_mask(
		(__v8di)__A, (int)__B, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_srli_epi64(__m512i __A, unsigned int __B)
{
	return (__m512i)__builtin_ia32_psrlqi512_mask(
		(__v8di)__A, (int)__B, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)-1);
}

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_permutex_epi64(__m512i __X, const int __I)
{
	return (__m512i)__builtin_ia32_permdi512_mask(
		(__v8di)__X, __I, (__v8di)_mm512_undefined_epi32(),
		(__mmask8)(-1));
}

extern __inline __mmask8
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_cmp_epi64_mask(__m512i __X, __m512i __Y, const int __P)
{
	return (__mmask8)__builtin_ia32_cmpq512_mask((__v8di)__X, (__v8di)__Y,
						     __P, (__mmask8)-1);
}

typedef enum {
	_MM_PERM_AAAA = 0x00,
	_MM_PERM_AAAB = 0x01,
	_MM_PERM_AAAC = 0x02,
	_MM_PERM_AAAD = 0x03,
	_MM_PERM_AABA = 0x04,
	_MM_PERM_AABB = 0x05,
	_MM_PERM_AABC = 0x06,
	_MM_PERM_AABD = 0x07,
	_MM_PERM_AACA = 0x08,
	_MM_PERM_AACB = 0x09,
	_MM_PERM_AACC = 0x0A,
	_MM_PERM_AACD = 0x0B,
	_MM_PERM_AADA = 0x0C,
	_MM_PERM_AADB = 0x0D,
	_MM_PERM_AADC = 0x0E,
	_MM_PERM_AADD = 0x0F,
	_MM_PERM_ABAA = 0x10,
	_MM_PERM_ABAB = 0x11,
	_MM_PERM_ABAC = 0x12,
	_MM_PERM_ABAD = 0x13,
	_MM_PERM_ABBA = 0x14,
	_MM_PERM_ABBB = 0x15,
	_MM_PERM_ABBC = 0x16,
	_MM_PERM_ABBD = 0x17,
	_MM_PERM_ABCA = 0x18,
	_MM_PERM_ABCB = 0x19,
	_MM_PERM_ABCC = 0x1A,
	_MM_PERM_ABCD = 0x1B,
	_MM_PERM_ABDA = 0x1C,
	_MM_PERM_ABDB = 0x1D,
	_MM_PERM_ABDC = 0x1E,
	_MM_PERM_ABDD = 0x1F,
	_MM_PERM_ACAA = 0x20,
	_MM_PERM_ACAB = 0x21,
	_MM_PERM_ACAC = 0x22,
	_MM_PERM_ACAD = 0x23,
	_MM_PERM_ACBA = 0x24,
	_MM_PERM_ACBB = 0x25,
	_MM_PERM_ACBC = 0x26,
	_MM_PERM_ACBD = 0x27,
	_MM_PERM_ACCA = 0x28,
	_MM_PERM_ACCB = 0x29,
	_MM_PERM_ACCC = 0x2A,
	_MM_PERM_ACCD = 0x2B,
	_MM_PERM_ACDA = 0x2C,
	_MM_PERM_ACDB = 0x2D,
	_MM_PERM_ACDC = 0x2E,
	_MM_PERM_ACDD = 0x2F,
	_MM_PERM_ADAA = 0x30,
	_MM_PERM_ADAB = 0x31,
	_MM_PERM_ADAC = 0x32,
	_MM_PERM_ADAD = 0x33,
	_MM_PERM_ADBA = 0x34,
	_MM_PERM_ADBB = 0x35,
	_MM_PERM_ADBC = 0x36,
	_MM_PERM_ADBD = 0x37,
	_MM_PERM_ADCA = 0x38,
	_MM_PERM_ADCB = 0x39,
	_MM_PERM_ADCC = 0x3A,
	_MM_PERM_ADCD = 0x3B,
	_MM_PERM_ADDA = 0x3C,
	_MM_PERM_ADDB = 0x3D,
	_MM_PERM_ADDC = 0x3E,
	_MM_PERM_ADDD = 0x3F,
	_MM_PERM_BAAA = 0x40,
	_MM_PERM_BAAB = 0x41,
	_MM_PERM_BAAC = 0x42,
	_MM_PERM_BAAD = 0x43,
	_MM_PERM_BABA = 0x44,
	_MM_PERM_BABB = 0x45,
	_MM_PERM_BABC = 0x46,
	_MM_PERM_BABD = 0x47,
	_MM_PERM_BACA = 0x48,
	_MM_PERM_BACB = 0x49,
	_MM_PERM_BACC = 0x4A,
	_MM_PERM_BACD = 0x4B,
	_MM_PERM_BADA = 0x4C,
	_MM_PERM_BADB = 0x4D,
	_MM_PERM_BADC = 0x4E,
	_MM_PERM_BADD = 0x4F,
	_MM_PERM_BBAA = 0x50,
	_MM_PERM_BBAB = 0x51,
	_MM_PERM_BBAC = 0x52,
	_MM_PERM_BBAD = 0x53,
	_MM_PERM_BBBA = 0x54,
	_MM_PERM_BBBB = 0x55,
	_MM_PERM_BBBC = 0x56,
	_MM_PERM_BBBD = 0x57,
	_MM_PERM_BBCA = 0x58,
	_MM_PERM_BBCB = 0x59,
	_MM_PERM_BBCC = 0x5A,
	_MM_PERM_BBCD = 0x5B,
	_MM_PERM_BBDA = 0x5C,
	_MM_PERM_BBDB = 0x5D,
	_MM_PERM_BBDC = 0x5E,
	_MM_PERM_BBDD = 0x5F,
	_MM_PERM_BCAA = 0x60,
	_MM_PERM_BCAB = 0x61,
	_MM_PERM_BCAC = 0x62,
	_MM_PERM_BCAD = 0x63,
	_MM_PERM_BCBA = 0x64,
	_MM_PERM_BCBB = 0x65,
	_MM_PERM_BCBC = 0x66,
	_MM_PERM_BCBD = 0x67,
	_MM_PERM_BCCA = 0x68,
	_MM_PERM_BCCB = 0x69,
	_MM_PERM_BCCC = 0x6A,
	_MM_PERM_BCCD = 0x6B,
	_MM_PERM_BCDA = 0x6C,
	_MM_PERM_BCDB = 0x6D,
	_MM_PERM_BCDC = 0x6E,
	_MM_PERM_BCDD = 0x6F,
	_MM_PERM_BDAA = 0x70,
	_MM_PERM_BDAB = 0x71,
	_MM_PERM_BDAC = 0x72,
	_MM_PERM_BDAD = 0x73,
	_MM_PERM_BDBA = 0x74,
	_MM_PERM_BDBB = 0x75,
	_MM_PERM_BDBC = 0x76,
	_MM_PERM_BDBD = 0x77,
	_MM_PERM_BDCA = 0x78,
	_MM_PERM_BDCB = 0x79,
	_MM_PERM_BDCC = 0x7A,
	_MM_PERM_BDCD = 0x7B,
	_MM_PERM_BDDA = 0x7C,
	_MM_PERM_BDDB = 0x7D,
	_MM_PERM_BDDC = 0x7E,
	_MM_PERM_BDDD = 0x7F,
	_MM_PERM_CAAA = 0x80,
	_MM_PERM_CAAB = 0x81,
	_MM_PERM_CAAC = 0x82,
	_MM_PERM_CAAD = 0x83,
	_MM_PERM_CABA = 0x84,
	_MM_PERM_CABB = 0x85,
	_MM_PERM_CABC = 0x86,
	_MM_PERM_CABD = 0x87,
	_MM_PERM_CACA = 0x88,
	_MM_PERM_CACB = 0x89,
	_MM_PERM_CACC = 0x8A,
	_MM_PERM_CACD = 0x8B,
	_MM_PERM_CADA = 0x8C,
	_MM_PERM_CADB = 0x8D,
	_MM_PERM_CADC = 0x8E,
	_MM_PERM_CADD = 0x8F,
	_MM_PERM_CBAA = 0x90,
	_MM_PERM_CBAB = 0x91,
	_MM_PERM_CBAC = 0x92,
	_MM_PERM_CBAD = 0x93,
	_MM_PERM_CBBA = 0x94,
	_MM_PERM_CBBB = 0x95,
	_MM_PERM_CBBC = 0x96,
	_MM_PERM_CBBD = 0x97,
	_MM_PERM_CBCA = 0x98,
	_MM_PERM_CBCB = 0x99,
	_MM_PERM_CBCC = 0x9A,
	_MM_PERM_CBCD = 0x9B,
	_MM_PERM_CBDA = 0x9C,
	_MM_PERM_CBDB = 0x9D,
	_MM_PERM_CBDC = 0x9E,
	_MM_PERM_CBDD = 0x9F,
	_MM_PERM_CCAA = 0xA0,
	_MM_PERM_CCAB = 0xA1,
	_MM_PERM_CCAC = 0xA2,
	_MM_PERM_CCAD = 0xA3,
	_MM_PERM_CCBA = 0xA4,
	_MM_PERM_CCBB = 0xA5,
	_MM_PERM_CCBC = 0xA6,
	_MM_PERM_CCBD = 0xA7,
	_MM_PERM_CCCA = 0xA8,
	_MM_PERM_CCCB = 0xA9,
	_MM_PERM_CCCC = 0xAA,
	_MM_PERM_CCCD = 0xAB,
	_MM_PERM_CCDA = 0xAC,
	_MM_PERM_CCDB = 0xAD,
	_MM_PERM_CCDC = 0xAE,
	_MM_PERM_CCDD = 0xAF,
	_MM_PERM_CDAA = 0xB0,
	_MM_PERM_CDAB = 0xB1,
	_MM_PERM_CDAC = 0xB2,
	_MM_PERM_CDAD = 0xB3,
	_MM_PERM_CDBA = 0xB4,
	_MM_PERM_CDBB = 0xB5,
	_MM_PERM_CDBC = 0xB6,
	_MM_PERM_CDBD = 0xB7,
	_MM_PERM_CDCA = 0xB8,
	_MM_PERM_CDCB = 0xB9,
	_MM_PERM_CDCC = 0xBA,
	_MM_PERM_CDCD = 0xBB,
	_MM_PERM_CDDA = 0xBC,
	_MM_PERM_CDDB = 0xBD,
	_MM_PERM_CDDC = 0xBE,
	_MM_PERM_CDDD = 0xBF,
	_MM_PERM_DAAA = 0xC0,
	_MM_PERM_DAAB = 0xC1,
	_MM_PERM_DAAC = 0xC2,
	_MM_PERM_DAAD = 0xC3,
	_MM_PERM_DABA = 0xC4,
	_MM_PERM_DABB = 0xC5,
	_MM_PERM_DABC = 0xC6,
	_MM_PERM_DABD = 0xC7,
	_MM_PERM_DACA = 0xC8,
	_MM_PERM_DACB = 0xC9,
	_MM_PERM_DACC = 0xCA,
	_MM_PERM_DACD = 0xCB,
	_MM_PERM_DADA = 0xCC,
	_MM_PERM_DADB = 0xCD,
	_MM_PERM_DADC = 0xCE,
	_MM_PERM_DADD = 0xCF,
	_MM_PERM_DBAA = 0xD0,
	_MM_PERM_DBAB = 0xD1,
	_MM_PERM_DBAC = 0xD2,
	_MM_PERM_DBAD = 0xD3,
	_MM_PERM_DBBA = 0xD4,
	_MM_PERM_DBBB = 0xD5,
	_MM_PERM_DBBC = 0xD6,
	_MM_PERM_DBBD = 0xD7,
	_MM_PERM_DBCA = 0xD8,
	_MM_PERM_DBCB = 0xD9,
	_MM_PERM_DBCC = 0xDA,
	_MM_PERM_DBCD = 0xDB,
	_MM_PERM_DBDA = 0xDC,
	_MM_PERM_DBDB = 0xDD,
	_MM_PERM_DBDC = 0xDE,
	_MM_PERM_DBDD = 0xDF,
	_MM_PERM_DCAA = 0xE0,
	_MM_PERM_DCAB = 0xE1,
	_MM_PERM_DCAC = 0xE2,
	_MM_PERM_DCAD = 0xE3,
	_MM_PERM_DCBA = 0xE4,
	_MM_PERM_DCBB = 0xE5,
	_MM_PERM_DCBC = 0xE6,
	_MM_PERM_DCBD = 0xE7,
	_MM_PERM_DCCA = 0xE8,
	_MM_PERM_DCCB = 0xE9,
	_MM_PERM_DCCC = 0xEA,
	_MM_PERM_DCCD = 0xEB,
	_MM_PERM_DCDA = 0xEC,
	_MM_PERM_DCDB = 0xED,
	_MM_PERM_DCDC = 0xEE,
	_MM_PERM_DCDD = 0xEF,
	_MM_PERM_DDAA = 0xF0,
	_MM_PERM_DDAB = 0xF1,
	_MM_PERM_DDAC = 0xF2,
	_MM_PERM_DDAD = 0xF3,
	_MM_PERM_DDBA = 0xF4,
	_MM_PERM_DDBB = 0xF5,
	_MM_PERM_DDBC = 0xF6,
	_MM_PERM_DDBD = 0xF7,
	_MM_PERM_DDCA = 0xF8,
	_MM_PERM_DDCB = 0xF9,
	_MM_PERM_DDCC = 0xFA,
	_MM_PERM_DDCD = 0xFB,
	_MM_PERM_DDDA = 0xFC,
	_MM_PERM_DDDB = 0xFD,
	_MM_PERM_DDDC = 0xFE,
	_MM_PERM_DDDD = 0xFF
} _MM_PERM_ENUM;

extern __inline __m512i
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_mm512_shuffle_epi32(__m512i __A, _MM_PERM_ENUM __mask)
{
	return (__m512i)__builtin_ia32_pshufd512_mask(
		(__v16si)__A, __mask, (__v16si)_mm512_undefined_epi32(),
		(__mmask16)-1);
}

#else

#define _mm512_rol_epi32(A, B)                                                 \
	((__m512i)__builtin_ia32_prold512_mask(                                \
		(__v16si)(__m512i)(A), (int)(B),                               \
		(__v16si)_mm512_undefined_epi32(), (__mmask16)(-1)))

#define _mm512_shuffle_epi32(X, C)                                             \
	((__m512i)__builtin_ia32_pshufd512_mask(                               \
		(__v16si)(__m512i)(X), (int)(C),                               \
		(__v16si)(__m512i)_mm512_undefined_epi32(), (__mmask16) - 1))

#define _mm512_slli_epi64(X, C)                                                \
	((__m512i)__builtin_ia32_psllqi512_mask(                               \
		(__v8di)(__m512i)(X), (int)(C),                                \
		(__v8di)(__m512i)_mm512_undefined_epi32(), (__mmask8) - 1))

#define _mm512_srli_epi64(X, C)                                                \
	((__m512i)__builtin_ia32_psrlqi512_mask(                               \
		(__v8di)(__m512i)(X), (int)(C),                                \
		(__v8di)(__m512i)_mm512_undefined_epi32(), (__mmask8) - 1))

#define _mm512_permutex_epi64(X, I)                                            \
	((__m512i)__builtin_ia32_permdi512_mask(                               \
		(__v8di)(__m512i)(X), (int)(I),                                \
		(__v8di)(__m512i)(_mm512_undefined_epi32()), (__mmask8)(-1)))

#define _mm512_cmp_epi64_mask(X, Y, P)                                         \
	((__mmask8)__builtin_ia32_cmpq512_mask((__v8di)(__m512i)(X),           \
					       (__v8di)(__m512i)(Y), (int)(P), \
					       (__mmask8) - 1))

#endif /* OPTIMIZE */

#ifdef __DISABLE_AVX512F__
#undef __DISABLE_AVX512F__
#pragma GCC pop_options
#endif /* __DISABLE_AVX512F__ */

#endif /* EXT_X86_AVX512FINTRIN_H */
