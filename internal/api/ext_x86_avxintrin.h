/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef EXT_X86_AVXINTRIN_H
#define EXT_X86_AVXINTRIN_H

typedef double __v4df __attribute__ ((__vector_size__ (32)));
typedef float __v8sf __attribute__ ((__vector_size__ (32)));
typedef long long __v4di __attribute__ ((__vector_size__ (32)));
typedef int __v8si __attribute__ ((__vector_size__ (32)));
typedef short __v16hi __attribute__ ((__vector_size__ (32)));
typedef char __v32qi __attribute__ ((__vector_size__ (32)));

typedef unsigned long long __v4du __attribute__ ((__vector_size__ (32)));
typedef unsigned short __v16hu __attribute__ ((__vector_size__ (32)));
typedef unsigned char __v32qu __attribute__ ((__vector_size__ (32)));

typedef float __m256 __attribute__ ((__vector_size__ (32), __aligned__(32)));
typedef double __m256d __attribute__((__vector_size__(32), __aligned__(32)));
typedef long long __m256i __attribute__((__vector_size__(32), __aligned__(32)));
typedef long long __m256i_u __attribute__((__vector_size__(32), __aligned__(1)));

#ifdef __clang__
#define __DEFAULT_FN_ATTRS __attribute__((__always_inline__, __nodebug__, __target__("avx"), __min_vector_width__(256)))
#else

#ifndef __AVX__
#pragma GCC push_options
#pragma GCC target("avx")
#define __DISABLE_AVX__
#endif /* __AVX__ */

#define __DEFAULT_FN_ATTRS __attribute__((__gnu_inline__, __always_inline__, __artificial__))
#endif

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_load_si256(__m256i const *__p)
{
  return *__p;
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set_epi8(char __b31, char __b30, char __b29, char __b28,
                char __b27, char __b26, char __b25, char __b24,
                char __b23, char __b22, char __b21, char __b20,
                char __b19, char __b18, char __b17, char __b16,
                char __b15, char __b14, char __b13, char __b12,
                char __b11, char __b10, char __b09, char __b08,
                char __b07, char __b06, char __b05, char __b04,
                char __b03, char __b02, char __b01, char __b00)
{
  return __extension__ (__m256i)(__v32qi){
    __b00, __b01, __b02, __b03, __b04, __b05, __b06, __b07,
    __b08, __b09, __b10, __b11, __b12, __b13, __b14, __b15,
    __b16, __b17, __b18, __b19, __b20, __b21, __b22, __b23,
    __b24, __b25, __b26, __b27, __b28, __b29, __b30, __b31
  };
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set_epi16(short __w15, short __w14, short __w13, short __w12,
                 short __w11, short __w10, short __w09, short __w08,
                 short __w07, short __w06, short __w05, short __w04,
                 short __w03, short __w02, short __w01, short __w00)
{
  return __extension__ (__m256i)(__v16hi){ __w00, __w01, __w02, __w03, __w04, __w05, __w06,
    __w07, __w08, __w09, __w10, __w11, __w12, __w13, __w14, __w15 };
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set1_epi8(char __b)
{
  return _mm256_set_epi8(__b, __b, __b, __b, __b, __b, __b, __b,
                         __b, __b, __b, __b, __b, __b, __b, __b,
                         __b, __b, __b, __b, __b, __b, __b, __b,
                         __b, __b, __b, __b, __b, __b, __b, __b);
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set1_epi16(short __w)
{
  return _mm256_set_epi16(__w, __w, __w, __w, __w, __w, __w, __w,
                          __w, __w, __w, __w, __w, __w, __w, __w);
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_loadu_si256(__m256i_u const *__p)
{
  struct __loadu_si256 {
    __m256i_u __v;
  } __attribute__((__packed__, __may_alias__));
  return ((const struct __loadu_si256*)__p)->__v;
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_castsi128_si256(__m128i __a)
{
  return __builtin_shufflevector((__v2di)__a, (__v2di)__a, 0, 1, -1, -1);
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set_epi32(int __i0, int __i1, int __i2, int __i3,
                 int __i4, int __i5, int __i6, int __i7)
{
  return __extension__ (__m256i)(__v8si){ __i7, __i6, __i5, __i4, __i3, __i2, __i1, __i0 };
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set1_epi32(int __i)
{
  return _mm256_set_epi32(__i, __i, __i, __i, __i, __i, __i, __i);
}

static __inline void __DEFAULT_FN_ATTRS
_mm256_store_si256(__m256i *__p, __m256i __a)
{
  *__p = __a;
}

static __inline __m128i __DEFAULT_FN_ATTRS
_mm256_castsi256_si128(__m256i __a)
{
  return __builtin_shufflevector((__v4di)__a, (__v4di)__a, 0, 1);
}

static __inline int __DEFAULT_FN_ATTRS
_mm256_movemask_ps(__m256 __a)
{
  return __builtin_ia32_movmskps256((__v8sf)__a);
}

static __inline void __DEFAULT_FN_ATTRS
_mm256_storeu_si256(__m256i_u *__p, __m256i __a)
{
  struct __storeu_si256 {
    __m256i_u __v;
  } __attribute__((__packed__, __may_alias__));
  ((struct __storeu_si256*)__p)->__v = __a;
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_setzero_si256(void)
{
  return __extension__ (__m256i)(__v4di){ 0, 0, 0, 0 };
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_castps_si256(__m256 __a)
{
  return (__m256i)__a;
}

static __inline __m256 __DEFAULT_FN_ATTRS
_mm256_blendv_ps(__m256 __a, __m256 __b, __m256 __c)
{
  return (__m256)__builtin_ia32_blendvps256(
    (__v8sf)__a, (__v8sf)__b, (__v8sf)__c);
}

static __inline __m256 __DEFAULT_FN_ATTRS
_mm256_castsi256_ps(__m256i __a)
{
  return (__m256)__a;
}

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set_epi64x(long long __a, long long __b, long long __c, long long __d)
{
  return __extension__ (__m256i)(__v4di){ __d, __c, __b, __a };
}

#ifdef __clang__
static __inline__ __m256i __DEFAULT_FN_ATTRS
_mm256_undefined_si256(void)
{
  return (__m256i)__builtin_ia32_undef256();
}
#else
extern __inline __m256i __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm256_undefined_si256 (void)
{
  __m256i __Y = __Y;
  return __Y;
}
#endif

static __inline __m256i __DEFAULT_FN_ATTRS
_mm256_set1_epi64x(long long __q)
{
  return _mm256_set_epi64x(__q, __q, __q, __q);
}

static __inline int __DEFAULT_FN_ATTRS
_mm256_testz_si256(__m256i __a, __m256i __b)
{
  return __builtin_ia32_ptestz256((__v4di)__a, (__v4di)__b);
}

#define _mm256_permute2f128_ps(V1, V2, M) \
  ((__m256)__builtin_ia32_vperm2f128_ps256((__v8sf)(__m256)(V1), \
                                           (__v8sf)(__m256)(V2), (int)(M)))

  #define _mm256_shuffle_pd(a, b, mask) \
  ((__m256d)__builtin_ia32_shufpd256((__v4df)(__m256d)(a), \
                                     (__v4df)(__m256d)(b), (int)(mask)))

static __inline __m256d __DEFAULT_FN_ATTRS
_mm256_broadcast_sd(double const *__a)
{
  double __d = *__a;
  return __extension__ (__m256d)(__v4df){ __d, __d, __d, __d };
}

#undef __DEFAULT_FN_ATTRS

#endif /* EXT_X86_AVXINTRIN_H */
