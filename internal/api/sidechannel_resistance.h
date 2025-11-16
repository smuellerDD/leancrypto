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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef SIDECHANNEL_RESISTANCE_H
#define SIDECHANNEL_RESISTANCE_H

#include "ext_headers_internal.h"
#include "null_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief cmov - Copy len bytes from x to r if b is 1;
 *		 don't modify x if b is 0. Requires b to be in {0,1};
 *		 assumes two's complement representation of negative integers.
 *		 Runs in constant time.
 *
 * @param [out] r pointer to output byte array
 * @param [in] x pointer to input byte array
 * @param [in] len Amount of bytes to be copied
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
	size_t i;
	uint8_t opt_blocker;

	/*
	 * Goal: copy data only depending on a given condition without
	 * the use of a branching operation which alters the timing behavior
	 * depending on the condition. As the condition here depends on
	 * secret data, the code has to ensure that no branching is used to have
	 * time-invariant code. This solution below also shall ensure that the
	 * compiler cannot optimize this code such that it brings back the
	 * branching.
	 *
	 * (condition ^ opt_blocker) can be any value at run-time to the
	 * compiler, making it impossible to skip the computation (except the
	 * compiler would care to create a branch for opt_blocker to be either
	 * 0 or 1, which would be extremely unlikely). Yet the volatile
	 * variable has to be loaded only once at the beginning of the function
	 * call.
	 *
	 * Note, the opt_blocker is not required in most instances, but in the
	 * ARMv8 Neon implementation of SLH-DSA the compiler managed to still
	 * create time-variant code without the optimization blocker.
	 */
	opt_blocker = (uint8_t)optimization_blocker_uint64;

	b = (uint8_t)-b;
	for (i = 0; i < len; i++)
		r[i] ^= (b & (r[i] ^ x[i])) ^ opt_blocker;
}

/**
 * @brief cmov_int16 - Copy input v to *r if b is 1, don't modify *r if b is 0.
 *		       Requires b to be in {0,1}; Runs in constant time.
 *
 * @param [out] r pointer to output int16_t
 * @param [in] v input int16_t
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
	b = (uint16_t)-b;
	*r ^= (int16_t)(b & ((*r) ^ v));
}

/**
 * @brief cmov_uint32 - Copy input v to *r if b is 1, don't modify *r if b is 0.
 *			Requires b to be in {0,1}; Runs in constant time.
 *
 * @param [out] r pointer to output int16_t
 * @param [in] v input int16_t
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov_uint32(uint32_t *r, uint32_t v, uint32_t b)
{
	b = (uint32_t)-b;
	*r ^= (uint32_t)(b & ((*r) ^ v));
}

/**
 * @brief cmov_int - Copy input v to *r if b is 1, don't modify *r if b is 0.
 *		       Requires b to be in {0,1}; Runs in constant time.
 *
 * @param [out] r pointer to output int16_t
 * @param [in] v input int16_t
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov_int(int *r, int v, uint16_t b)
{
	b = (uint16_t)-b;
	*r ^= (int)(b & ((*r) ^ v));
}

static inline uint8_t value_barrier_u8(uint8_t b)
{
	return (b ^ (uint8_t)optimization_blocker_uint64);
}

static inline uint32_t value_barrier_u32(uint32_t b)
{
	return (b ^ (uint32_t)optimization_blocker_uint64);
}

static inline uint64_t value_barrier_u64(uint64_t b)
{
	return (b ^ optimization_blocker_uint64);
}

static inline int64_t value_barrier_i64(int64_t b)
{
	return (b ^ (int64_t)optimization_blocker_uint64);
}

/**
 * @brief ct_sel_int32 - Functionally equivalent to cond ? a : b,
 *			 but implemented with guards against
 *			 compiler-introduced branches.
 *
 * @param [in] a First alternative
 * @param [in] b Second alternative
 * @param [in] cond Condition variable.
 *
 * @return selected value
 */
static inline int32_t ct_sel_int32(int32_t a, int32_t b, uint32_t cond)
{
	uint32_t au = (uint32_t)a;
	uint32_t bu = (uint32_t)b;
	uint32_t res = bu ^ (value_barrier_u32(cond) & (au ^ bu));

	return (int32_t)(res);
}

/**
 * @brief ct_cmask_neg_i32
 *
 * @param [in] x Value to be converted into a mask
 *
 * @return Return 0 if input is non-negative, and -1 otherwise.
 */
static inline uint32_t ct_cmask_neg_i32(int32_t x)
{
	int64_t tmp = value_barrier_i64((int64_t)x);

	tmp >>= 31;
	return (uint32_t)(tmp);
}

/**
 * @brief ct_abs_i32
 *
 * @param [in] x Input value
 *
 * @return -x if x<0, x otherwise
 */
static inline int32_t ct_abs_i32(int32_t x)
{
	return ct_sel_int32(-x, x, ct_cmask_neg_i32(x));
}

#ifdef __cplusplus
}
#endif

#endif /* SIDECHANNEL_RESISTANCE_H */
