/* Kyber Hybrid Integrated Encryption Schema - KyberIES
 *
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

#include "kyber_internal.h"

#include "lc_aead.h"
#include "lc_kyber.h"
#include "lc_rng.h"
#include "lc_memset_secure.h"
#include "ret_checkers.h"
#include "visibility.h"

#define LC_KYBER_IES_SYM_KEYSIZE 32
#define LC_KYBER_IES_SYM_IVSIZE 16

int lc_kyber_x25519_ies_enc_internal(
	const struct lc_kyber_x25519_pk *pk, struct lc_kyber_x25519_ct *ct,
	const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen,
	const uint8_t *aad, size_t aadlen, uint8_t *tag, size_t taglen,
	struct lc_aead_ctx *aead, struct lc_rng_ctx *rng_ctx)
{
	uint8_t ss[LC_KYBER_IES_SYM_KEYSIZE + LC_KYBER_IES_SYM_IVSIZE];
	uint8_t *ies_key = ss;
	uint8_t *ies_iv = ss + LC_KYBER_IES_SYM_KEYSIZE;
	int ret;

	CKINT(lc_kyber_x25519_enc_kdf_internal(ct, ss, sizeof(ss), pk,
					       rng_ctx));
	CKINT(lc_aead_setkey(aead, ies_key, LC_KYBER_IES_SYM_KEYSIZE, ies_iv,
			     LC_KYBER_IES_SYM_IVSIZE));
	lc_aead_encrypt(aead, plaintext, ciphertext, datalen, aad, aadlen, tag,
			taglen);

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc,
		      const struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_ct *ct, const uint8_t *plaintext,
		      uint8_t *ciphertext, size_t datalen, const uint8_t *aad,
		      size_t aadlen, uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	return lc_kyber_x25519_ies_enc_internal(pk, ct, plaintext, ciphertext,
						datalen, aad, aadlen, tag,
						taglen, aead, lc_seeded_rng);
}

int lc_kyber_x25519_ies_enc_init_internal(struct lc_aead_ctx *aead,
					  const struct lc_kyber_x25519_pk *pk,
					  struct lc_kyber_x25519_ct *ct,
					  const uint8_t *aad, size_t aadlen,
					  struct lc_rng_ctx *rng_ctx)
{
	uint8_t ss[LC_KYBER_IES_SYM_KEYSIZE + LC_KYBER_IES_SYM_IVSIZE];
	uint8_t *ies_key = ss;
	uint8_t *ies_iv = ss + LC_KYBER_IES_SYM_KEYSIZE;
	int ret;

	CKINT(lc_kyber_x25519_enc_kdf_internal(ct, ss, sizeof(ss), pk,
					       rng_ctx));
	CKINT(lc_aead_setkey(aead, ies_key, LC_KYBER_IES_SYM_KEYSIZE, ies_iv,
			     LC_KYBER_IES_SYM_IVSIZE));
	CKINT(lc_aead_dec_init(aead, aad, aadlen));

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc_init,
		      struct lc_aead_ctx *aead,
		      const struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_ct *ct, const uint8_t *aad,
		      size_t aadlen)
{
	int ret;

	CKINT(lc_kyber_x25519_ies_enc_init_internal(aead, pk, ct, aad, aadlen,
						    lc_seeded_rng));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec,
		      const struct lc_kyber_x25519_sk *sk,
		      const struct lc_kyber_x25519_ct *ct,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen, const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	uint8_t ss[LC_KYBER_IES_SYM_KEYSIZE + LC_KYBER_IES_SYM_IVSIZE];
	uint8_t *ies_key = ss;
	uint8_t *ies_iv = ss + LC_KYBER_IES_SYM_KEYSIZE;
	int ret;

	CKINT(lc_kyber_x25519_dec_kdf(ss, sizeof(ss), ct, sk));
	CKINT(lc_aead_setkey(aead, ies_key, LC_KYBER_IES_SYM_KEYSIZE, ies_iv,
			     LC_KYBER_IES_SYM_IVSIZE));
	CKINT(lc_aead_decrypt(aead, ciphertext, plaintext, datalen, aad, aadlen,
			      tag, taglen));

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec_init,
		      struct lc_aead_ctx *aead,
		      const struct lc_kyber_x25519_sk *sk,
		      const struct lc_kyber_x25519_ct *ct, const uint8_t *aad,
		      size_t aadlen)
{
	uint8_t ss[LC_KYBER_IES_SYM_KEYSIZE + LC_KYBER_IES_SYM_IVSIZE];
	uint8_t *ies_key = ss;
	uint8_t *ies_iv = ss + LC_KYBER_IES_SYM_KEYSIZE;
	int ret;

	CKINT(lc_kyber_x25519_dec_kdf(ss, sizeof(ss), ct, sk));
	CKINT(lc_aead_setkey(aead, ies_key, LC_KYBER_IES_SYM_KEYSIZE, ies_iv,
			     LC_KYBER_IES_SYM_IVSIZE));
	CKINT(lc_aead_dec_init(aead, aad, aadlen));

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}
