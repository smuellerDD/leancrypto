/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 - 2025 Jipeng Zhang (jp-zhang@outlook.com)
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KYBER_INDCPA_RVV_VLEN256_H
#define KYBER_INDCPA_RVV_VLEN256_H

#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_KYBER_RISCV_RVV_VLEN256
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
int indcpa_keypair_rvv_vlen256(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
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
int indcpa_enc_rvv_vlen256(uint8_t c[LC_KYBER_INDCPA_BYTES],
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
int indcpa_dec_rvv_vlen256(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			   const uint8_t c[LC_KYBER_INDCPA_BYTES],
			   const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]);

#else /* LC_KYBER_RISCV_RVV_VLEN256 */

static inline int
indcpa_keypair_rvv_vlen256(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			   uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
			   struct lc_rng_ctx *rng_ctx)
{
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	return -EOPNOTSUPP;
}

static inline int
indcpa_enc_rvv_vlen256(uint8_t c[LC_KYBER_INDCPA_BYTES],
		       const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		       const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		       const uint8_t coins[LC_KYBER_SYMBYTES])
{
	(void)c;
	(void)m;
	(void)pk;
	(void)coins;
	return -EOPNOTSUPP;
}

static inline int
indcpa_dec_rvv_vlen256(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		       const uint8_t c[LC_KYBER_INDCPA_BYTES],
		       const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	(void)m;
	(void)c;
	(void)sk;
	return -EOPNOTSUPP;
}

#endif /* LC_KYBER_RISCV_RVV_VLEN256 */

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_RVV_VLEN256_H */
