/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "dilithium_ntt.h"
#include "dilithium_reduce.h"
#include "dilithium_zetas.h"

/**
 * @brief ntt - Forward NTT, in-place. No modular reduction is performed after
 *		additions or subtractions. Output vector is in bitreversed
 *		order.
 *
 * @param [in,out] p input/output coefficient array
 */
void ntt(int32_t a[LC_DILITHIUM_N])
{
	unsigned int len, start, j, k;
	int32_t zeta, t;

	k = 0;

	for (len = 128; len > 0; len >>= 1) {
		for (start = 0; start < LC_DILITHIUM_N; start = j + len) {
			zeta = zetas[++k];
			for (j = start; j < start + len; ++j) {
				t = montgomery_reduce((int64_t)zeta *
						      a[j + len]);
				a[j + len] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
}

/**
 * @brief invntt_tomont - Inverse NTT and multiplication by Montgomery factor
 *			  2^32. In-place. No modular reductions after additions
 *			  or subtractions; input coefficients need to be smaller
 *			  than Q in absolute value. Output coefficient are
 *			  smaller than Q in absolute value.
 *
 * @param [in,out] p input/output coefficient array
 */
void invntt_tomont(int32_t a[LC_DILITHIUM_N])
{
	unsigned int start, len, j, k;
	int32_t t, zeta;
	const int32_t f = 41978; // mont^2/256

	k = 256;

	for (len = 1; len < LC_DILITHIUM_N; len <<= 1) {
		for (start = 0; start < LC_DILITHIUM_N; start = j + len) {
			zeta = -zetas[--k];
			for (j = start; j < start + len; ++j) {
				t = a[j];
				a[j] = t + a[j + len];
				a[j + len] = t - a[j + len];
				a[j + len] = montgomery_reduce((int64_t)zeta *
							       a[j + len]);
			}
		}
	}

	for (j = 0; j < LC_DILITHIUM_N; ++j)
		a[j] = montgomery_reduce((int64_t)f * a[j]);
}
