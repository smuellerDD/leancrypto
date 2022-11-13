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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_REDUCE_H
#define DILITHIUM_REDUCE_H

#include "ext_headers.h"

#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

/**
 * @brief montgomery_reduce - For finite field element a with
 *			     -2^{31}Q <= a <= Q*2^31,
 *			     compute r \equiv a*2^{-32} (mod Q) such that
 *			     -Q < r < Q.
 *
 * @param a [in] finite field element
 *
 * @return r
 */
static inline int32_t montgomery_reduce(int64_t a)
{
	int32_t t;

	t = (int32_t)a * QINV;
	t = (int32_t)((a - (int64_t)t * LC_DILITHIUM_Q) >> 32);
	return t;
}


/**
 * @brief reduce32 - For finite field element a with a <= 2^{31} - 2^{22} - 1,
 *		     compute r \equiv a (mod Q) such that
 *		     -6283009 <= r <= 6283007.
 *
 * @param a [in] finite field element
 *
 * @return r
 */
static inline int32_t reduce32(int32_t a)
{
	int32_t t;

	t = (a + (1 << 22)) >> 23;
	t = a - t * LC_DILITHIUM_Q;
	return t;
}

/**
 * @brief caddq - Add Q if input coefficient is negative.
 *
 * @param a [in] finite field element
 *
 * @return r
 */
static inline int32_t caddq(int32_t a)
{
	a += (a >> 31) & LC_DILITHIUM_Q;
	return a;
}

/**
 * @brief freeze - For finite field element a, compute standard representative
 *		   r = a mod^+ Q.
 *
 * @param a [in] finite field element a
 *
 * @return r
 */
static inline int32_t freeze(int32_t a)
{
	a = reduce32(a);
	a = caddq(a);
	return a;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_REDUCE_H */
