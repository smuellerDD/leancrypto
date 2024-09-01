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
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#ifndef KYBER_INDCPA_ARMV8_H
#define KYBER_INDCPA_ARMV8_H

#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief indcpa_keypair - Generates public and private key for the CPA-secure
 *			   public-key encryption scheme underlying Kyber
 *
 * @param [out] pk pointer to output public key
 * @param [out] sk pointer to output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_keypair_armv8(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			 uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
			 struct lc_rng_ctx *rng_ctx);

/**
 * @brief indcpa_enc - Encryption function of the CPA-secure
 *		       public-key encryption scheme underlying Kyber.
 *
 * @param [out] c pointer to output ciphertext
 * @param [in] m pointer to input message
 * @param [in] pk pointer to input public key
 * @param [in] coins pointer to input random coins used as seed to
 *		     deterministically generate all randomness
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_enc_armv8(uint8_t c[LC_KYBER_INDCPA_BYTES],
		     const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		     const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		     const uint8_t coins[LC_KYBER_SYMBYTES]);

/**
 * @brief indcpa_dec - Decryption function of the CPA-secure public-key
 *		       encryption scheme underlying Kyber.
 *
 * @param [out] m pointer to output decrypted message
 * @param [in] c pointer to input ciphertext
 * @param [in] sk pointer to input secret key
 *
 * @return 0 (success) or < 0 on error
 */
int indcpa_dec_armv8(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		     const uint8_t c[LC_KYBER_INDCPA_BYTES],
		     const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_ARMV8_H */
