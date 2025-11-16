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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "dilithium_rounding.h"
#include "sidechannel_resistantce.h"

/**
 * @brief power2round - For finite field element a, compute a0, a1 such that
 *			a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 *			Assumes a to be standard representative.
 *
 * @param [in] a input element
 * @param [out] a0 pointer to output element a0
 *
 * @return a1.
 */
int32_t power2round(int32_t *a0, int32_t a)
{
	int32_t a1;

	a1 = (a + (1 << (LC_DILITHIUM_D - 1)) - 1) >> LC_DILITHIUM_D;
	*a0 = a - (a1 << LC_DILITHIUM_D);
	return a1;
}

/**
 * @brief decompose - For finite field element a, compute high and low bits a0,
 *		      a1 such that a mod^+ Q = a1*ALPHA + a0 with
 *		      -ALPHA/2 < a0 <= ALPHA/2 except if a1 = (Q-1)/ALPHA where
 *		      we set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0.
 *		      Assumes a to be standard representative.
 *
 * @param [in] a input element
 * @param [out] a0 pointer to output element a0
 *
 * @return a1.
 */
int32_t decompose(int32_t *a0, int32_t a)
{
	int32_t a1;

	a1 = (a + 127) >> 7;
#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 32
	a1 = (a1 * 1025 + (1 << 21)) >> 22;
	a1 &= 15;
#elif LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 88
	a1 = (a1 * 11275 + (1 << 23)) >> 24;
	a1 = ct_sel_int32(0, a1, ct_cmask_neg_i32(43 - a1));
#else
#error "Uknown GAMMA2"
#endif

	*a0 = a - a1 * 2 * LC_DILITHIUM_GAMMA2;
	*a0 = ct_sel_int32(*a0 - LC_DILITHIUM_Q, *a0,
			   ct_cmask_neg_i32((LC_DILITHIUM_Q - 1) / 2 - *a0));

	return a1;
}

/**
 * @brief make_hint - Compute hint bit indicating whether the low bits of the
 *		      input element overflow into the high bits.
 *
 * @param  a0 [in] low bits of input element
 * @param  a1 [in] high bits of input element
 *
 * @return 1 if overflow.
 */
int32_t make_hint(int32_t a0, int32_t a1)
{
	if (a0 > LC_DILITHIUM_GAMMA2 || a0 < -LC_DILITHIUM_GAMMA2 ||
	    (a0 == -LC_DILITHIUM_GAMMA2 && a1 != 0))
		return 1;

	return 0;
}

/**
 * @brief use_hint - Correct high bits according to hint.
 *
 * @param [in] a input element
 * @param [in] hint hint bit
 *
 * @return corrected high bits.
 */
int32_t use_hint(int32_t a, int32_t hint)
{
	int32_t a0, a1;

	a1 = decompose(&a0, a);
	if (hint == 0)
		return a1;

#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 32
	if (a0 > 0)
		return (a1 + 1) & 15;
	else
		return (a1 - 1) & 15;
#elif LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 88
	if (a0 > 0)
		return (a1 == 43) ? 0 : a1 + 1;
	else
		return (a1 == 0) ? 43 : a1 - 1;
#else
#error "Uknown GAMMA2"
#endif
}
