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

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_service_helpers.h"
#include "lc_sha3.h"

/**
 * @brief poly_chknorm - Check infinity norm of polynomial against given bound.
 *			 Assumes input coefficients were reduced by reduce32().
 *
 * @param a [in] pointer to polynomial
 * @param B [in] norm bound
 *
 * @return 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 */
int poly_chknorm(const poly *a, int32_t B)
{
	unsigned int i;
	int32_t t;

	if (B > (LC_DILITHIUM_Q - 1) / 8)
		return 1;

	/*
	 * It is ok to leak which coefficient violates the bound since
	 * the probability for each coefficient *is independent of secret
	 * data but we must not leak the sign of the centralized representative.
	 */
	for (i = 0; i < LC_DILITHIUM_N; ++i) {
		/* Absolute value */
		t = a->coeffs[i] >> 31;
		t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

		if (t >= B)
			return 1;
	}

	return 0;
}

/**
 * @brief poly_uniform - Sample polynomial with uniformly random coefficients
 *			 in [0,Q-1] by performing rejection sampling on the
 *			 output stream of SHAKE128(seed|nonce).
 *
 * @param a [out] pointer to output polynomial
 * @param seed [in] byte array with seed of length LC_DILITHIUM_SEEDBYTES
 * @param nonce [in] 2-byte nonce
 */
void poly_uniform(poly *a, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
		  uint16_t nonce, void *ws_buf)
{
	unsigned int i, ctr, off;
	unsigned int buflen = POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK;
	uint8_t *buf = ws_buf;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake128);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(hash_ctx, (uint8_t *)&nonce, sizeof(nonce));
	lc_hash_set_digestsize(hash_ctx, buflen);
	lc_hash_final(hash_ctx, buf);

	lc_hash_set_digestsize(hash_ctx, LC_SHAKE_128_SIZE_BLOCK);

	ctr = rej_uniform(a->coeffs, LC_DILITHIUM_N, buf, buflen);

	while (ctr < LC_DILITHIUM_N) {
		off = buflen % 3;
		for (i = 0; i < off; ++i)
			buf[i] = buf[buflen - off + i];

		lc_hash_final(hash_ctx, buf + off);
		buflen = LC_DILITHIUM_SEEDBYTES + off;
		ctr += rej_uniform(a->coeffs + ctr, LC_DILITHIUM_N - ctr, buf,
				   buflen);
	}

	lc_hash_zero(hash_ctx);
}

/**
 * @brief poly_uniform_eta - Sample polynomial with uniformly random
 *			     coefficients in [-ETA,ETA] by performing rejection
 *			     sampling on the output stream from
 *			     SHAKE256(seed|nonce).
 *
 * @param a [out] pointer to output polynomial
 * @param seed [in] byte array with seed of length LC_DILITHIUM_CRHBYTES
 * @param nonce [in] 2-byte nonce
 */
void poly_uniform_eta(poly *a, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		      uint16_t nonce, void *ws_buf)
{
	unsigned int ctr;
	uint8_t *buf = ws_buf;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, (uint8_t *)&nonce, sizeof(nonce));
	lc_hash_set_digestsize(hash_ctx, POLY_UNIFORM_ETA_BYTES);
	lc_hash_final(hash_ctx, buf);

	ctr = rej_eta(a->coeffs, LC_DILITHIUM_N, buf, POLY_UNIFORM_ETA_BYTES);

	while (ctr < LC_DILITHIUM_N) {
		lc_hash_final(hash_ctx, buf);
		ctr += rej_eta(a->coeffs + ctr, LC_DILITHIUM_N - ctr, buf,
			       LC_SHAKE_256_SIZE_BLOCK);
	}

	lc_hash_zero(hash_ctx);
}

/**
 * @brief poly_uniform_gamma1 - Sample polynomial with uniformly random
 *				coefficients in [-(GAMMA1 - 1), GAMMA1] by
 *				unpacking output stream of
 *				SHAKE256(seed|nonce).
 *
 * @param a [out] pointer to output polynomial
 * @param seed [in]: byte array with seed of length LC_DILITHIUM_CRHBYTES
 * @param nonce 16-bit nonce
 */
void poly_uniform_gamma1(poly *a, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			 uint16_t nonce, void *ws_buf)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, (uint8_t *)&nonce, sizeof(nonce));
	lc_hash_set_digestsize(hash_ctx, POLY_UNIFORM_GAMMA1_BYTES);
	lc_hash_final(hash_ctx, ws_buf);
	lc_hash_zero(hash_ctx);

	polyz_unpack(a, ws_buf);
}

/**
 * @brief poly_challenge - Implementation of H. Samples polynomial with TAU
 *			   nonzero coefficients in {-1,1} using the output
 *			   stream of SHAKE256(seed).
 *
 * @param c [out] pointer to output polynomial
 * @param mu [in] byte array containing seed of length LC_DILITHIUM_SEEDBYTES
 */
void poly_challenge(poly *c, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
		    void *ws_buf)
{
	unsigned int i, b, pos;
	uint64_t signs;
	uint8_t *buf = ws_buf;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_SEEDBYTES);
	lc_hash_set_digestsize(hash_ctx, POLY_CHALLENGE_BYTES);
	lc_hash_final(hash_ctx, buf);

	signs = 0;
	for (i = 0; i < 8; ++i)
		signs |= (uint64_t)buf[i] << 8 * i;
	pos = 8;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		c->coeffs[i] = 0;

	for (i = LC_DILITHIUM_N - LC_DILITHIUM_TAU; i < LC_DILITHIUM_N; ++i) {
		do {
			if (pos >= LC_SHAKE_256_SIZE_BLOCK) {
				lc_hash_final(hash_ctx, buf);
				pos = 0;
			}

			b = buf[pos++];
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - (int32_t)(2 * (signs & 1));
		signs >>= 1;
	}

	lc_hash_zero(hash_ctx);
}

/**
 * @brief polyeta_pack - Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * @param r [out] pointer to output byte array with at least
 *		  LC_DILITHIUM_POLYETA_PACKEDBYTES bytes
 * @param a [in] pointer to input polynomial
 */
void polyeta_pack(uint8_t *r, const poly *a)
{
	unsigned int i;
	uint8_t t[8];

#if LC_DILITHIUM_ETA == 2
	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		t[0] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 0]);
		t[1] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 1]);
		t[2] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 2]);
		t[3] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 3]);
		t[4] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 4]);
		t[5] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 5]);
		t[6] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 6]);
		t[7] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8 * i + 7]);

		r[3 * i + 0] =
			(uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
		r[3 * i + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) |
					 (t[4] << 4) | (t[5] << 7));
		r[3 * i + 2] =
			(uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
	}
#elif LC_DILITHIUM_ETA == 4
	for (i = 0; i < LC_DILITHIUM_N / 2; ++i) {
		t[0] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[2 * i + 0]);
		t[1] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[2 * i + 1]);
		r[i] = (uint8_t)(t[0] | (t[1] << 4));
	}
#else
#error "Undefined LC_DILITHIUM_ETA"
#endif
}

/**
 * @brief polyeta_unpack - Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] byte array with bit-packed polynomial
 */
void polyeta_unpack(poly *r, const uint8_t *a)
{
	unsigned int i;

#if LC_DILITHIUM_ETA == 2
	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
		r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
		r->coeffs[8 * i + 2] =
			((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
		r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
		r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
		r->coeffs[8 * i + 5] =
			((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
		r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
		r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

		r->coeffs[8 * i + 0] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] = LC_DILITHIUM_ETA - r->coeffs[8 * i + 7];
	}
#elif LC_DILITHIUM_ETA == 4
	for (i = 0; i < LC_DILITHIUM_N / 2; ++i) {
		r->coeffs[2 * i + 0] = a[i] & 0x0F;
		r->coeffs[2 * i + 1] = a[i] >> 4;
		r->coeffs[2 * i + 0] = LC_DILITHIUM_ETA - r->coeffs[2 * i + 0];
		r->coeffs[2 * i + 1] = LC_DILITHIUM_ETA - r->coeffs[2 * i + 1];
	}
#else
#error "Undefined LC_DILITHIUM_ETA"
#endif
}

/**
 * @brief polyt1_pack - Bit-pack polynomial t1 with coefficients fitting in 10
 *			bits. Input coefficients are assumed to be standard
 *			representatives.
 *
 * @param r [out] pointer to output byte array with at least
 * 		  LC_DILITHIUM_POLYT1_PACKEDBYTES bytes
 * @param a [in] pointer to input polynomial
 */
void polyt1_pack(uint8_t *r, const poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r[5 * i + 0] = (uint8_t)((a->coeffs[4 * i + 0] >> 0));
		r[5 * i + 1] = (uint8_t)((a->coeffs[4 * i + 0] >> 8) |
					 (a->coeffs[4 * i + 1] << 2));
		r[5 * i + 2] = (uint8_t)((a->coeffs[4 * i + 1] >> 6) |
					 (a->coeffs[4 * i + 2] << 4));
		r[5 * i + 3] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) |
					 (a->coeffs[4 * i + 3] << 6));
		r[5 * i + 4] = (uint8_t)((a->coeffs[4 * i + 3] >> 2));
	}
}

/**
 * @brief polyt0_pack - Bit-pack polynomial t0 with coefficients in
 *			]-2^{D-1}, 2^{D-1}].
 *
 * @param r [out] pointer to output byte array with at least
 *		  LC_DILITHIUM_POLYT0_PACKEDBYTES bytes
 * @param a [in] pointer to input polynomial
 */
void polyt0_pack(uint8_t *r, const poly *a)
{
	unsigned int i;
	uint32_t t[8];

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		t[0] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 0]);
		t[1] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 1]);
		t[2] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 2]);
		t[3] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 3]);
		t[4] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 4]);
		t[5] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 5]);
		t[6] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 6]);
		t[7] = (uint32_t)((1 << (LC_DILITHIUM_D - 1)) -
				  a->coeffs[8 * i + 7]);

		r[13 * i + 0] = (uint8_t)(t[0]);
		r[13 * i + 1] = (uint8_t)(t[0] >> 8);
		r[13 * i + 1] |= (uint8_t)(t[1] << 5);
		r[13 * i + 2] = (uint8_t)(t[1] >> 3);
		r[13 * i + 3] = (uint8_t)(t[1] >> 11);
		r[13 * i + 3] |= (uint8_t)(t[2] << 2);
		r[13 * i + 4] = (uint8_t)(t[2] >> 6);
		r[13 * i + 4] |= (uint8_t)(t[3] << 7);
		r[13 * i + 5] = (uint8_t)(t[3] >> 1);
		r[13 * i + 6] = (uint8_t)(t[3] >> 9);
		r[13 * i + 6] |= (uint8_t)(t[4] << 4);
		r[13 * i + 7] = (uint8_t)(t[4] >> 4);
		r[13 * i + 8] = (uint8_t)(t[4] >> 12);
		r[13 * i + 8] |= (uint8_t)(t[5] << 1);
		r[13 * i + 9] = (uint8_t)(t[5] >> 7);
		r[13 * i + 9] |= (uint8_t)(t[6] << 6);
		r[13 * i + 10] = (uint8_t)(t[6] >> 2);
		r[13 * i + 11] = (uint8_t)(t[6] >> 10);
		r[13 * i + 11] |= (uint8_t)(t[7] << 3);
		r[13 * i + 12] = (uint8_t)(t[7] >> 5);
	}

	lc_memset_secure(t, 0, sizeof(t));
}

/**
 * @brief polyt0_unpack - Unpack polynomial t0 with coefficients in
 *			  ]-2^{D-1}, 2^{D-1}].
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] byte array with bit-packed polynomial
 */
void polyt0_unpack(poly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[13 * i + 0];
		r->coeffs[8 * i + 0] |= (int32_t)a[13 * i + 1] << 8;
		r->coeffs[8 * i + 0] &= 0x1FFF;

		r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
		r->coeffs[8 * i + 1] |= (int32_t)a[13 * i + 2] << 3;
		r->coeffs[8 * i + 1] |= (int32_t)a[13 * i + 3] << 11;
		r->coeffs[8 * i + 1] &= 0x1FFF;

		r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
		r->coeffs[8 * i + 2] |= (int32_t)a[13 * i + 4] << 6;
		r->coeffs[8 * i + 2] &= 0x1FFF;

		r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
		r->coeffs[8 * i + 3] |= (int32_t)a[13 * i + 5] << 1;
		r->coeffs[8 * i + 3] |= (int32_t)a[13 * i + 6] << 9;
		r->coeffs[8 * i + 3] &= 0x1FFF;

		r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
		r->coeffs[8 * i + 4] |= (int32_t)a[13 * i + 7] << 4;
		r->coeffs[8 * i + 4] |= (int32_t)a[13 * i + 8] << 12;
		r->coeffs[8 * i + 4] &= 0x1FFF;

		r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
		r->coeffs[8 * i + 5] |= (int32_t)a[13 * i + 9] << 7;
		r->coeffs[8 * i + 5] &= 0x1FFF;

		r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
		r->coeffs[8 * i + 6] |= (int32_t)a[13 * i + 10] << 2;
		r->coeffs[8 * i + 6] |= (int32_t)a[13 * i + 11] << 10;
		r->coeffs[8 * i + 6] &= 0x1FFF;

		r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
		r->coeffs[8 * i + 7] |= (int32_t)a[13 * i + 12] << 5;
		r->coeffs[8 * i + 7] &= 0x1FFF;

		r->coeffs[8 * i + 0] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] =
			(1 << (LC_DILITHIUM_D - 1)) - r->coeffs[8 * i + 7];
	}
}

/**
 * @param polyz_pack - Bit-pack polynomial with coefficients
 *		       in [-(GAMMA1 - 1), GAMMA1].
 *
 * @param r [out] pointer to output byte array with at least
 *		  LC_DILITHIUM_POLYZ_PACKEDBYTES bytes
 * @param a [in] pointer to input polynomial
 */
void polyz_pack(uint8_t *r, const poly *a)
{
	unsigned int i;
	uint32_t t[4];

#if LC_DILITHIUM_GAMMA1 == (1 << 17)
	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		t[0] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[4 * i + 0]);
		t[1] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[4 * i + 1]);
		t[2] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[4 * i + 2]);
		t[3] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[4 * i + 3]);

		r[9 * i + 0] = (uint8_t)(t[0]);
		r[9 * i + 1] = (uint8_t)(t[0] >> 8);
		r[9 * i + 2] = (uint8_t)(t[0] >> 16);
		r[9 * i + 2] |= (uint8_t)(t[1] << 2);
		r[9 * i + 3] = (uint8_t)(t[1] >> 6);
		r[9 * i + 4] = (uint8_t)(t[1] >> 14);
		r[9 * i + 4] |= (uint8_t)(t[2] << 4);
		r[9 * i + 5] = (uint8_t)(t[2] >> 4);
		r[9 * i + 6] = (uint8_t)(t[2] >> 12);
		r[9 * i + 6] |= (uint8_t)(t[3] << 6);
		r[9 * i + 7] = (uint8_t)(t[3] >> 2);
		r[9 * i + 8] = (uint8_t)(t[3] >> 10);
	}
#elif LC_DILITHIUM_GAMMA1 == (1 << 19)
	for (i = 0; i < LC_DILITHIUM_N / 2; ++i) {
		t[0] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[2 * i + 0]);
		t[1] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[2 * i + 1]);

		r[5 * i + 0] = (uint8_t)(t[0]);
		r[5 * i + 1] = (uint8_t)(t[0] >> 8);
		r[5 * i + 2] = (uint8_t)(t[0] >> 16);
		r[5 * i + 2] |= (uint8_t)(t[1] << 4);
		r[5 * i + 3] = (uint8_t)(t[1] >> 4);
		r[5 * i + 4] = (uint8_t)(t[1] >> 12);
	}
#else
#error "Undefined Gamma"
#endif

	lc_memset_secure(t, 0, sizeof(t));
}

/**
 * @brief polyz_unpack - Unpack polynomial z with coefficients
 *			 in [-(GAMMA1 - 1), GAMMA1].
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] byte array with bit-packed polynomial
 */
void polyz_unpack(poly *r, const uint8_t *a)
{
	unsigned int i;

#if LC_DILITHIUM_GAMMA1 == (1 << 17)
	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r->coeffs[4 * i + 0] = a[9 * i + 0];
		r->coeffs[4 * i + 0] |= (int32_t)a[9 * i + 1] << 8;
		r->coeffs[4 * i + 0] |= (int32_t)a[9 * i + 2] << 16;
		r->coeffs[4 * i + 0] &= 0x3FFFF;

		r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
		r->coeffs[4 * i + 1] |= (int32_t)a[9 * i + 3] << 6;
		r->coeffs[4 * i + 1] |= (int32_t)a[9 * i + 4] << 14;
		r->coeffs[4 * i + 1] &= 0x3FFFF;

		r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
		r->coeffs[4 * i + 2] |= (int32_t)a[9 * i + 5] << 4;
		r->coeffs[4 * i + 2] |= (int32_t)a[9 * i + 6] << 12;
		r->coeffs[4 * i + 2] &= 0x3FFFF;

		r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
		r->coeffs[4 * i + 3] |= (int32_t)a[9 * i + 7] << 2;
		r->coeffs[4 * i + 3] |= (int32_t)a[9 * i + 8] << 10;
		r->coeffs[4 * i + 3] &= 0x3FFFF;

		r->coeffs[4 * i + 0] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[4 * i + 0];
		r->coeffs[4 * i + 1] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[4 * i + 1];
		r->coeffs[4 * i + 2] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[4 * i + 2];
		r->coeffs[4 * i + 3] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[4 * i + 3];
	}
#elif LC_DILITHIUM_GAMMA1 == (1 << 19)
	for (i = 0; i < LC_DILITHIUM_N / 2; ++i) {
		r->coeffs[2 * i + 0] = a[5 * i + 0];
		r->coeffs[2 * i + 0] |= (int32_t)a[5 * i + 1] << 8;
		r->coeffs[2 * i + 0] |= (int32_t)a[5 * i + 2] << 16;
		r->coeffs[2 * i + 0] &= 0xFFFFF;

		r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
		r->coeffs[2 * i + 1] |= (int32_t)a[5 * i + 3] << 4;
		r->coeffs[2 * i + 1] |= (int32_t)a[5 * i + 4] << 12;
		r->coeffs[2 * i + 0] &= 0xFFFFF;

		r->coeffs[2 * i + 0] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[2 * i + 0];
		r->coeffs[2 * i + 1] =
			LC_DILITHIUM_GAMMA1 - r->coeffs[2 * i + 1];
	}
#else
#error "Undefined Gamma"
#endif
}

/**
 * @brief polyw1_pack - Bit-pack polynomial w1 with coefficients in [0,15] or
 *			[0,43]. Input coefficients are assumed to be standard
 *			representatives.
 *
 * @param r [out] pointer to output byte array with at least
 *		  LC_DILITHIUM_POLYW1_PACKEDBYTES bytes
 * @param a [in] pointer to input polynomial
 */
void polyw1_pack(uint8_t *r, const poly *a)
{
	unsigned int i;

#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 88
	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r[3 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0]);
		r[3 * i + 0] |= (uint8_t)(a->coeffs[4 * i + 1] << 6);
		r[3 * i + 1] = (uint8_t)(a->coeffs[4 * i + 1] >> 2);
		r[3 * i + 1] |= (uint8_t)(a->coeffs[4 * i + 2] << 4);
		r[3 * i + 2] = (uint8_t)(a->coeffs[4 * i + 2] >> 4);
		r[3 * i + 2] |= (uint8_t)(a->coeffs[4 * i + 3] << 2);
	}
#elif LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1) / 32
	for (i = 0; i < LC_DILITHIUM_N / 2; ++i)
		r[i] = (uint8_t)(a->coeffs[2 * i + 0] |
				 (a->coeffs[2 * i + 1] << 4));
#else
#error "Undefined Gamma"
#endif
}
