/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_KEM_INPUT_VALIDATION_H
#define KYBER_KEM_INPUT_VALIDATION_H

#include "kyber_type.h"
#include "lc_memcmp_secure.h"
#include "small_stack_support.h"
#include "timecop.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int kyber_kem_iv_type(const struct lc_kyber_pk *pk)
{
	(void)pk;

	/*
	 * FIPS 203 input validation: type check not needed, because
	 * struct lc_kyber_pk ensures that the input is of required length
	 */
	return 0;
}

/**
 * @brief kyber_kem_iv_pk_modulus - Encapsulation input validation of modulus of
 *				    encryption key.
 *
 * FIPS 203: (Modulus check.) Perform the computation
 *	     ek_n = ByteEncode(ByteDecode(ek)). If ek ̸= ek_n , the input is
 *	     invalid.
 *
 * @param  [in] pk Public key (ek)
 * @param [in] pkpv Already decoded public key (ek) to prevent another decoding
 *		    step. Note, as this parameter is implementation dependent,
 *		    the caller must include this header file after the header
 *		    file defining polyvec.
 * @param [in] seed Seed informed during decding of pk
 * @param [in] pack_pk Function to encode key
 *
 * @return 0 on success, < 0 on error
 */
static inline int kyber_kem_iv_pk_modulus(
	const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES], const polyvec *pkpv,
	uint8_t seed[LC_KYBER_SYMBYTES], void *ws,
	void (*pack_pk)(uint8_t r[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			const polyvec *pk,
			const uint8_t seed[LC_KYBER_SYMBYTES]))
{
	int ret = 0;

	pack_pk(ws, pkpv, seed);

	if (lc_memcmp_secure(pk, LC_KYBER_INDCPA_PUBLICKEYBYTES, ws,
			     LC_KYBER_INDCPA_PUBLICKEYBYTES))
		ret = -EINVAL;

	return ret;
}

/**
 * @brief kyber_kem_iv_sk_modulus - Encapsulation input validation of modulus of
 *				    encryption key.
 *
 * FIPS 203: (Modulus check.) Perform the computation
 *	     dk_n = ByteEncode(ByteDecode(dk)). If dk ̸= dk_n , the input is
 *	     invalid.
 *
 * @param  [in] sk Secret key (dk)
 * @param [in] skpv Already decoded secret key (dk) to prevent another decoding
 *		    step. Note, as this parameter is implementation dependent,
 *		    the caller must include this header file after the header
 *		    file defining polyvec.
 * @param [in] pack_sk Function to encode key
 *
 * @return 0 on success, < 0 on error
 */
static inline int kyber_kem_iv_sk_modulus(
	const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES], const polyvec *skpv,
	void (*pack_sk)(uint8_t r[LC_KYBER_INDCPA_SECRETKEYBYTES],
			const polyvec *sk))
{
	struct workspace {
		uint8_t sknew[LC_KYBER_INDCPA_SECRETKEYBYTES];
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	pack_sk(ws->sknew, skpv);

	/* Timecop: timing difference due to memcmp is no side channel leak. */
	unpoison(sk, LC_KYBER_INDCPA_SECRETKEYBYTES);
	unpoison(ws->sknew, LC_KYBER_INDCPA_SECRETKEYBYTES);
	if (lc_memcmp_secure(sk, LC_KYBER_INDCPA_SECRETKEYBYTES, ws->sknew,
			     LC_KYBER_INDCPA_SECRETKEYBYTES))
		ret = -EINVAL;

	LC_RELEASE_MEM(ws);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_KEM_INPUT_VALIDATION_H */
