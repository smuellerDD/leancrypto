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

#ifndef DILITHIUM_PACK_AVX2_H
#define DILITHIUM_PACK_AVX2_H

#include "dilithium_type.h"
#include "dilithium_polyvec_avx2.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param [out] rho output byte array for rho
 * @param [in] sk byte array containing bit-packed sk
 */
static inline void unpack_sk_rho_avx2(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				      const struct lc_dilithium_sk *sk)
{
	memcpy(rho, sk->sk, LC_DILITHIUM_SEEDBYTES);
}

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param [out] key output byte array for key
 * @param [in] sk byte array containing bit-packed sk
 */
static inline void unpack_sk_key_avx2(uint8_t key[LC_DILITHIUM_SEEDBYTES],
				      const struct lc_dilithium_sk *sk)
{
	memcpy(key, sk->sk + LC_DILITHIUM_SEEDBYTES, LC_DILITHIUM_SEEDBYTES);
}

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param [out] tr output byte array for tr
 * @param [in] sk byte array containing bit-packed sk
 */
static inline void unpack_sk_tr_avx2(uint8_t tr[LC_DILITHIUM_TRBYTES],
				     const struct lc_dilithium_sk *sk)
{
	memcpy(tr, sk->sk + 2 * LC_DILITHIUM_SEEDBYTES, LC_DILITHIUM_TRBYTES);
}

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param [out] s1 pointer to output vector s1
 * @param [in] sk_in byte array containing bit-packed sk
 */
static inline void unpack_sk_s1_avx2(polyvecl *s1,
				     const struct lc_dilithium_sk *sk_in)
{
	const uint8_t *sk =
		sk_in->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES;
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_unpack_avx(&s1->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
}

/**
 * @brief unpack_sk - Unpack secret key sk parts
 *
 * @param [out] s2 pointer to output vector s2
 * @param [in] sk_in byte array containing bit-packed sk
 */
static inline void unpack_sk_s2_avx2(polyveck *s2,
				     const struct lc_dilithium_sk *sk_in)
{
	const uint8_t *sk = sk_in->sk + 2 * LC_DILITHIUM_SEEDBYTES +
			    LC_DILITHIUM_TRBYTES +
			    LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_unpack_avx(&s2->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
}

/**
 * @brief unpack_sk - Unpack secret key sk parts
 *
 * @param [out] t0 pointer to output vector t0
 * @param [in] sk_in byte array containing bit-packed sk
 */
static inline void unpack_sk_t0_avx2(polyveck *t0,
				     const struct lc_dilithium_sk *sk_in)
{
	const uint8_t *sk = sk_in->sk + 2 * LC_DILITHIUM_SEEDBYTES +
			    LC_DILITHIUM_TRBYTES +
			    LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES +
			    LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_unpack_avx(&t0->vec[i],
				  sk + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_PACK_AVX2_H */
