/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef BIKE_UTILITIES_H
#define BIKE_UTILITIES_H

#include "bike_internal.h"
#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * "VALUE_BARRIER returns |a|, but prevents GCC and Clang from reasoning about
 * the returned value. This is used to mitigate compilers undoing constant-time
 * code, until we can express our requirements directly in the language.
 * Note the compiler is aware that |VALUE_BARRIER| has no side effects and
 * always has the same output for a given input. This allows it to eliminate
 * dead code, move computations across loops, and vectorize."
 * See:
 * https://github.com/google/boringssl/commit/92b7c89e6e8ba82924b57153bea68241cc45f658
 */
#if (defined(__GNUC__) || defined(__clang__))
#define VALUE_BARRIER(name, type)                                              \
	static inline type name##_barrier(type a)                              \
	{                                                                      \
		__asm__("" : "+r"(a) : /* no inputs */);                       \
		return a;                                                      \
	}
#else
#define VALUE_BARRIER(name, type)                                              \
	static inline type name##_barrier(type a)                              \
	{                                                                      \
		return a;                                                      \
	}
#endif

VALUE_BARRIER(u8, uint8_t)
VALUE_BARRIER(u32, uint32_t)
VALUE_BARRIER(u64, uint64_t)

// Return 0 if v1 < v2, (-1) otherwise
static inline uint32_t secure_l32_mask(const uint32_t v1, const uint32_t v2)
{
#if defined(__aarch64__)
	uint32_t res;
	__asm__ __volatile__("cmp  %w[V2], %w[V1]; \n "
			     "cset %w[RES], HI; \n"
			     : [RES] "=r"(res)
			     : [V1] "r"(v1), [V2] "r"(v2)
			     : "cc" /*The condition code flag*/);
	return (res - 1);
#elif defined(__x86_64__) || defined(__i386__)
	uint32_t res;
	__asm__ __volatile__("xor  %%edx, %%edx; \n"
			     "cmp  %1, %2; \n "
			     "setl %%dl; \n"
			     "dec %%edx; \n"
			     "mov %%edx, %0; \n"

			     : "=r"(res)
			     : "r"(v2), "r"(v1)
			     : "rdx");

	return res;
#else
	/*
	 * If v1 >= v2 then the subtraction result is 0^32||(v1-v2).
	 * else it is 1^32||(v2-v1+1). Subsequently, negating the upper
	 * 32 bits gives 0 if v1 < v2 and otherwise (-1).
	 */
	return ~((uint32_t)(((uint64_t)v1 - (uint64_t)v2) >> 32));
#endif
}

// Return 1 if v1 < v2. Return 0 otherwise.
static inline uint32_t secure_l32(const uint32_t v1, const uint32_t v2)
{
#if defined(__aarch64__)
	uint32_t res;
	__asm__ __volatile__("cmp  %w[V2], %w[V1]; \n "
			     "cset %w[RES], HI; \n"
			     : [RES] "=r"(res)
			     : [V1] "r"(v1), [V2] "r"(v2)
			     : "cc" /*The condition code flag*/);
	return res;
#elif defined(__x86_64__) || defined(__i386__)
	uint32_t res;
	__asm__ __volatile__("xor  %%edx, %%edx; \n"
			     "cmp  %1, %2; \n "
			     "setl %%dl; \n"
			     "mov %%edx, %0; \n"
			     : "=r"(res)
			     : "r"(v2), "r"(v1)
			     : "rdx");
	return res;
#else
	/*
	 * Insecure comparison: The main purpose of secure_l32 is to avoid
	 * branches to prevent potential side channel leaks. To do that,
	 * we normally leverage some special CPU instructions such as "setl"
	 * (for __x86_64__) and "cset" (for __aarch64__). When dealing with
	 * general CPU architectures, the interpretation of the line below is
	 * left for the compiler. It could lead to an "insecure" branch. This
	 * case needs to be checked individually on such platforms (e.g., by
	 * checking the compiler-generated assembly).
	 */
	return (v1 < v2 ? 1 : 0);
#endif
}

// Return (-1) if v1 == v2, 0 otherwise
static inline uint64_t secure_cmpeq64_mask(const uint64_t v1, const uint64_t v2)
{
	return -(1 - ((uint64_t)((v1 - v2) | (v2 - v1)) >> 63));
}

static inline uint64_t r_bits_vector_weight(const r_t *in)
{
	uint64_t acc = 0;
	size_t i;

	for (i = 0; i < (LC_BIKE_R_BYTES - 1); i++) {
		acc += (uint64_t)__builtin_popcount(in->raw[i]);
	}

	acc += (uint64_t)__builtin_popcount(in->raw[LC_BIKE_R_BYTES - 1] &
					    LC_BIKE_LAST_R_BYTE_MASK);
	return acc;
}

// Return 1 if the arguments are equal to each other. Return 0 otherwise.
static inline uint32_t secure_cmp32(const uint32_t v1, const uint32_t v2)
{
#if defined(__aarch64__)
	uint32_t res;
	__asm__ __volatile__("cmp  %w[V1], %w[V2]; \n "
			     "cset %w[RES], EQ; \n"
			     : [RES] "=r"(res)
			     : [V1] "r"(v1), [V2] "r"(v2)
			     : "cc" /*The condition code flag*/);
	return res;
#elif defined(__x86_64__) || defined(__i386__)
	uint32_t res;
	__asm__ __volatile__("xor  %%edx, %%edx; \n"
			     "cmp  %1, %2; \n "
			     "sete %%dl; \n"
			     "mov %%edx, %0; \n"
			     : "=r"(res)
			     : "r"(v1), "r"(v2)
			     : "rdx");
	return res;
#else
	/*
	 * Insecure comparison: The main purpose of secure_l32 is to avoid
	 * branches to prevent potential side channel leaks. To do that,
	 * we normally leverage some special CPU instructions such as "setl"
	 * (for __x86_64__) and "cset" (for __aarch64__). When dealing with
	 * general CPU architectures, the interpretation of the line below is
	 * left for the compiler. It could lead to an "insecure" branch. This
	 * case needs to be checked individually on such platforms (e.g., by
	 * checking the compiler-generated assembly).
	 */
	return (v1 == v2 ? 1 : 0);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* BIKE_UTILITIES_H */
