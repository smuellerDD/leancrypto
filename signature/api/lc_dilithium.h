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

#ifndef LC_DILITHIUM_H
#define LC_DILITHIUM_H

#include <errno.h>
#include <stdint.h>

#include "lc_rng.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Dilithium Security Levels
 * 2 -> 192 bits of security strength
 * 3 -> 225 bits of security strength
 * 5 -> 257 bits of security strength
 */
#ifndef LC_DILITHIUM_MODE
#define LC_DILITHIUM_MODE 5
#endif

#define LC_DILITHIUM_SEEDBYTES 32
#define LC_DILITHIUM_CRHBYTES 64
#define LC_DILITHIUM_N 256
#define LC_DILITHIUM_Q 8380417
#define LC_DILITHIUM_D 13
#define LC_DILITHIUM_ROOT_OF_UNITY 1753

#if LC_DILITHIUM_MODE == 2
#define LC_DILITHIUM_K 4
#define LC_DILITHIUM_L 4
#define LC_DILITHIUM_ETA 2
#define LC_DILITHIUM_TAU 39
#define LC_DILITHIUM_BETA 78
#define LC_DILITHIUM_GAMMA1 (1 << 17)
#define LC_DILITHIUM_GAMMA2 ((LC_DILITHIUM_Q - 1)/88)
#define LC_DILITHIUM_OMEGA 80

#elif LC_DILITHIUM_MODE == 3
#define LC_DILITHIUM_K 6
#define LC_DILITHIUM_L 5
#define LC_DILITHIUM_ETA 4
#define LC_DILITHIUM_TAU 49
#define LC_DILITHIUM_BETA 196
#define LC_DILITHIUM_GAMMA1 (1 << 19)
#define LC_DILITHIUM_GAMMA2 ((LC_DILITHIUM_Q - 1)/32)
#define LC_DILITHIUM_OMEGA 55

#elif LC_DILITHIUM_MODE == 5
#define LC_DILITHIUM_K 8
#define LC_DILITHIUM_L 7
#define LC_DILITHIUM_ETA 2
#define LC_DILITHIUM_TAU 60
#define LC_DILITHIUM_BETA 120
#define LC_DILITHIUM_GAMMA1 (1 << 19)
#define LC_DILITHIUM_GAMMA2 ((LC_DILITHIUM_Q - 1)/32)
#define LC_DILITHIUM_OMEGA 75

#endif

#define LC_DILITHIUM_POLYT1_PACKEDBYTES  320
#define LC_DILITHIUM_POLYT0_PACKEDBYTES  416
#define LC_DILITHIUM_POLYVECH_PACKEDBYTES (LC_DILITHIUM_OMEGA + LC_DILITHIUM_K)

#if LC_DILITHIUM_GAMMA1 == (1 << 17)
#define LC_DILITHIUM_POLYZ_PACKEDBYTES   576
#elif LC_DILITHIUM_GAMMA1 == (1 << 19)
#define LC_DILITHIUM_POLYZ_PACKEDBYTES   640
#endif

#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1)/88
#define LC_DILITHIUM_POLYW1_PACKEDBYTES  192
#elif LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q - 1)/32
#define LC_DILITHIUM_POLYW1_PACKEDBYTES  128
#endif

#if LC_DILITHIUM_ETA == 2
#define LC_DILITHIUM_POLYETA_PACKEDBYTES  96
#elif LC_DILITHIUM_ETA == 4
#define LC_DILITHIUM_POLYETA_PACKEDBYTES 128
#endif

#define LC_DILITHIUM_PUBLICKEYBYTES					       \
	(LC_DILITHIUM_SEEDBYTES +					       \
	 LC_DILITHIUM_K * LC_DILITHIUM_POLYT1_PACKEDBYTES)
#define LC_DILITHIUM_SECRETKEYBYTES					       \
	(3 * LC_DILITHIUM_SEEDBYTES					       \
	 + LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES		       \
	 + LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES		       \
	 + LC_DILITHIUM_K * LC_DILITHIUM_POLYT0_PACKEDBYTES)

#define LC_DILITHIUM_CRYPTO_BYTES 					       \
	(LC_DILITHIUM_SEEDBYTES +					       \
	 LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES +		       \
	 LC_DILITHIUM_POLYVECH_PACKEDBYTES)

/**
 * @brief Dilithium secret key
 */
struct lc_dilithium_sk {
	uint8_t sk[LC_DILITHIUM_SECRETKEYBYTES];
};

/**
 * @brief Dilithium public key
 */
struct lc_dilithium_pk {
	uint8_t pk[LC_DILITHIUM_PUBLICKEYBYTES];
};

/**
 * @brief Dilithium signature
 */
struct lc_dilithium_sig {
	uint8_t sig[LC_DILITHIUM_CRYPTO_BYTES];
};

/**
 * @brief lc_dilithium_keypair - Generates Dilithium public and private key.
 *
 * @param pk [out] pointer to allocated output public key
 * @param sk [out] pointer to allocated output private key
 * @param rng_ctx [in] pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_keypair(struct lc_dilithium_pk *pk,
			 struct lc_dilithium_sk *sk,
			 struct lc_rng_ctx *rng_ctx);


/**
 * @param crypto_sign_signature - Computes signature.
 *
 * @param sig [out] pointer to output signature
 * @param m [in] pointer to message to be signed
 * @param mlen [in] length of message
 * @param sk [in] pointer to bit-packed secret key
 * @param rng_ctx [in] pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_sign(struct lc_dilithium_sig *sig,
		      const uint8_t *m,
		      size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx);

/**
 * @brief crypto_sign_verify - Verifies signature.
 *
 * @param sig [in] pointer to input signature
 * @param m [in] pointer to message
 * @param mlen [in] length of message
 * @param pk [in] pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_verify(const struct lc_dilithium_sig *sig,
			const uint8_t *m,
			size_t mlen,
			const struct lc_dilithium_pk *pk);

#ifdef __cplusplus
}
#endif

#endif /* LC_DILITHIUM_H */
