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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief indcpa_keypair - Generates public and private key for the CPA-secure
 *			   public-key encryption scheme underlying Kyber
 *
 * @param pk [out] pointer to output public key
 * @param sk [out] pointer to output private key
 * @param rng_ctx [in] pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_keypair(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		   uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		   struct lc_rng_ctx *rng_ctx);

/**
 * @brief indcpa_enc - Encryption function of the CPA-secure
 *		       public-key encryption scheme underlying Kyber.
 *
 * @param c [out] pointer to output ciphertext
 * @param m [in] pointer to input message
 * @param pk [in] pointer to input public key
 * @param coins [in] pointer to input random coins used as seed to
 *		     deterministically generate all randomness
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_enc(uint8_t c[LC_KYBER_INDCPA_BYTES],
	       const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
               const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
               const uint8_t coins[LC_KYBER_SYMBYTES]);

/**
 * @brief indcpa_dec - Decryption function of the CPA-secure public-key
 *		       encryption scheme underlying Kyber.
 *
 * @param m [out] pointer to output decrypted message
 * @param c [in] pointer to input ciphertext
 * @param sk [in] pointer to input secret key
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_dec(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
               const uint8_t c[LC_KYBER_INDCPA_BYTES],
               const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_H */
