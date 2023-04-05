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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include "ext_headers.h"
#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

/**
 * @brief montgomery_reduce - Montgomery reduction; given a 32-bit integer a,
 *			     computes 16-bit integer congruent to
 *			     a * R^-1 mod q, where R=2^16
 *
 * @param [in] a input integer to be reduced;
 *		has to be in {-q2^15,...,q2^15-1}
 *
 * @return in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 */
static inline int16_t montgomery_reduce(int32_t a)
{
	int16_t t;

	t = (int16_t)a * QINV;
	t = (int16_t)((a - (int32_t)t * LC_KYBER_Q) >> 16);
	return t;
}

/**
 * @brief barrett_reduce - Barrett reduction; given a 16-bit integer a, computes
 *			   centered representative congruent to
 *			   a mod q in {-(q-1)/2,...,(q-1)/2}
 *
 * @param [in] a input integer to be reduced
 *
 * @return in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
 */
static inline int16_t barrett_reduce(int16_t a)
{
	int16_t t;
	const int16_t v = ((1<<26) + LC_KYBER_Q / 2)/ LC_KYBER_Q;

	t  = (int16_t)(((int32_t)v * a + (1<<25)) >> 26);
	t *= LC_KYBER_Q;
	return a - t;
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_REDUCE_H */
