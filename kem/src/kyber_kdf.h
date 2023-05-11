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

#ifndef KYBER_KDF_H
#define KYBER_KDF_H

#include "lc_kyber.h"
#include "lc_hash.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Kyber KDF
 *
 * @param [in] in input buffer
 * @param [in] inlen length of input buffer
 * @param [in] in2 input buffer 2
 * @param [in] inlen2 length of input buffer 2
 * @param [out] out output buffer of size
 * @param [out] outlen output buffer length
 */
static inline void kyber_kdf2(const uint8_t *in, size_t inlen,
			      const uint8_t *in2, size_t inlen2,
			      uint8_t *out, size_t outlen)
{
	LC_HASH_CTX_ON_STACK(shake256, lc_shake256);

	lc_hash_init(shake256);
	lc_hash_update(shake256, in, inlen);
	lc_hash_update(shake256, in2, inlen2);
	lc_hash_set_digestsize(shake256, outlen);
	lc_hash_final(shake256, out);

	lc_hash_zero(shake256);
}

/**
 * @brief Kyber KDF
 *
 * @param [in] in input buffer
 * @param [in] inlen length of input buffer
 * @param [in] in2 input buffer 2
 * @param [in] inlen2 length of input buffer 2
 * @param [in] in3 input buffer 3
 * @param [in] inlen3 length of input buffer 3
 * @param [out] out output buffer of size
 * @param [out] outlen output buffer length
 */
static inline void kyber_kdf3(const uint8_t *in, size_t inlen,
			      const uint8_t *in2, size_t inlen2,
			      const uint8_t *in3, size_t inlen3,
			      uint8_t *out, size_t outlen)
{
	LC_HASH_CTX_ON_STACK(shake256, lc_shake256);

	lc_hash_init(shake256);
	lc_hash_update(shake256, in, inlen);
	lc_hash_update(shake256, in2, inlen2);
	lc_hash_update(shake256, in3, inlen3);
	lc_hash_set_digestsize(shake256, outlen);
	lc_hash_final(shake256, out);

	lc_hash_zero(shake256);
}
/**
 * @brief Kyber KDF
 *
 * @param [in] in input buffer
 * @param [in] inlen length of input buffer
 * @param [in] in2 input buffer 2
 * @param [in] inlen2 length of input buffer 2
 * @param [in] in3 input buffer 3
 * @param [in] inlen3 length of input buffer 3
 * @param [in] in4 input buffer 4
 * @param [in] inlen4 length of input buffer 4
 * @param [out] out output buffer of size
 * @param [out] outlen output buffer length
 */
static inline void kyber_kdf4(const uint8_t *in, size_t inlen,
			      const uint8_t *in2, size_t inlen2,
			      const uint8_t *in3, size_t inlen3,
			      const uint8_t *in4, size_t inlen4,
			      uint8_t *out, size_t outlen)
{
	LC_HASH_CTX_ON_STACK(shake256, lc_shake256);

	lc_hash_init(shake256);
	lc_hash_update(shake256, in, inlen);
	lc_hash_update(shake256, in2, inlen2);
	lc_hash_update(shake256, in3, inlen3);
	lc_hash_update(shake256, in4, inlen4);
	lc_hash_set_digestsize(shake256, outlen);
	lc_hash_final(shake256, out);

	lc_hash_zero(shake256);
}

/**
 * kyber_shake256_prf - Usage of SHAKE256 as a PRF, concatenates secret and
 *			public input and then generates outlen bytes of SHAKE256
 *			output
 *
 * @param [out] out pointer to output
 * @param [in] outlen number of requested output bytes
 * @param [in] key pointer to the key
 * @param [in] nonce single-byte nonce (public PRF input)
 */
static inline void
kyber_shake256_prf(uint8_t *out, size_t outlen,
		   const uint8_t key[LC_KYBER_SYMBYTES], uint8_t nonce)
{
	kyber_kdf2(key, LC_KYBER_SYMBYTES, &nonce, 1, out, outlen);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_KDF_H */
