/* AEAD cipher based on arbitrary symmetric algorithm and HMAC
 *
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

/******************************************************************************
 * Abstract
 *
 * This specification defines a symmetric stream cipher algorithm using
 * the authenticated encryption with additional data (AEAD) approach. This
 * algorithm can be used to encrypt and decrypt arbitrary user data.
 * The cipher algorithm uses a symmetric algorithm to encrypt/decrypt data
 * along with a HMAC to perform the data authentication. The keys for both
 * the symmetric algorithm as well as the HMAC are derived from the
 * caller-provided key. The result of the HMAC authentication is the
 * message authentication tag which is used during decryption to verify the
 * integrity of the ciphertext.
 *
 * 1. Introduction
 *
 * This specification defines a symmetric algorithm using the authenticated
 * encryption with additional data (AEAD) approach. This algorithm can be used
 * to encrypt and decrypt arbitrary user data.
 *
 * The base of the algorithm is the encryption / decryption of the data using
 * the symmetric algorithm and the authentication of the ciphertext with a
 * HMAC.
 *
 * The algorithm applies an Encrypt-Then-MAC by calculating a message
 * authentication tag using HMAC over the ciphertext. During decryption, this
 * calculated message authentication tag is compared with the message
 * authentication tag obtained during the encryption operation. If both values
 * show a mismatch, the authentication fails and the decryption operation is
 * terminated. Only when both message authentication tags are identical
 * the decryption operation completes successfully and returns the decrypted
 * message.
 *
 * The caller-provided key is inserted into a HKDF to derive the key for
 * the symmetric algorithm as well as the HMAC. The caller-provided IV is
 * inserted into the symmetric algorithm.
 *
 * The size of the key is defined to be 256 bits when using cSHAKE-256.
 * The size of the IV can be selected by the caller. The algorithm supports
 * any IV size, including having no IV.
 *
 * As part of the authentication, the algorithm allows the addition of
 * additional authenticated data (AAD) of arbitrary size. This AAD is inserted
 * into the authentication HMAC instance during calculating the message
 * authentication tag.
 *
 * 2. Symmetric/HMAC-based AEAD Cipher Algorithm
 *
 * 2.1 Notation
 *
 * The "Sym" algorithm denotes an arbitrary symmetric algorithm function,
 * such as AES-CBC, AES-CTR or similar [SP800-38A]. The "Sym" algorithm
 * has 4 arguments: the symmetric algorithm type such as AES-CBC, the main
 * input bit string, the key and the IV. It produces an output string of equal
 * size of the input. It may be possible that the algorithm operates on a fixed
 * block size where the input bit string must be a multiple of the block size.
 * The caller must ensure that the input bit string is a multiple of the block
 * size.
 *
 * The "HASH" algorithm denotes an arbitrary hash algorithm such as [FIPS180-4].
 * The "HASH" algorithm is used to instantiate the following algorithms. The
 * following algorithms are required to use the same "HASH" algorithm. The
 * type of the hash algorithm must be selected by the caller.
 *
 * The "HMAC" algorithm denotes an arbitrary HMAC algorithm function, such
 * as HMAC-SHA2-512 [FIPS198]. The "HMAC" algorithm has 3 arguments:
 * the used hash type such as SHA2-512, the main input bit string, and the key.
 * The output size is defined by the used underlying hash digest size.
 *
 * The "HKDF" algorithm denotes the HKDF algorithm specified in [RFC5869]. The
 * "HKDF" algorithm uses 5 input arguments: the used hash type such as SHA2-512,
 * the IKM (input key material), the salt, the label and the size of the
 * output string in bits.
 *
 * 2.3. Derivation of Symmetric and HMAC key
 *
 * KDF(key) -> symmetric key, auth key
 *
 * Inputs:
 *   key: The caller-provided key of size 256 bits
 *
 * Outputs:
 *   symmetric key: The key used for the symmetric algorithm
 *
 *   auth key: The key that is used for the HMAC algorithm calculating the
 *             message authentication tag.
 *
 * The common processing of data is performed as follows:
 *
 * input length = size of input data in bits
 * KS = HKDF(HASH,
 *           IKM = key,
 *           salt = "",
 *           label = "",
 *           length = 512)
 * symmetric key = 256 left-most bits of KS
 * auth key = 256 right-most bits of KS
 *
 * 2.3 Calculating of Message Authentication Tag
 *
 * HMAC-Auth(auth key, AAD, ciphertext, taglen) -> tag
 *
 * Inputs:
 *   auth key: The key that is used for the cSHAKE operation calculating the
 *             message authentication tag.
 *
 *   AAD: The caller-provided additional authenticated data. The AAD can have
 *	  any size including an empty bit-string.
 *
 *   ciphertext: The ciphertext obtained from the encryption operation or
 *               provided to the decryption operation.
 *
 *   taglen: The length of the message authentication tag to be generated.
 *
 * The calculation of the message authentication tag is performed as follows:
 *
 * temporary tag = HKDF(HASH,
 *                      key = auth key,
 *                      input = ciphertext || AAD)
 *
 * tag = taglen left-most bits of temporary tag
 *
 * 2.4. Encryption Operation
 *
 * SymHMAC-Encrypt(key, IV, plaintext, AAD, taglen) -> ciphertext, tag
 *
 * Input:
 *   key: The caller-provided key of size 256 bits
 *
 *   IV: The caller-provided initialization vector. The IV can have any size
 *	 including an empty bit-string.
 *
 *   plaintext: The caller-provided plaintext data.
 *
 *   AAD: The caller-provided additional authenticated data.
 *
 *   taglen: The length of the message authentication tag to be generated.
 *
 * Output
 *   ciphertext: The ciphertext that can exchanged with the recipient over
 *               insecure channels.
 *
 *   tag: The message authentication tag that can be exchanged with the
 *        recipient over insecure channels.
 *
 * The encryption operation is performed as follows:
 *
 * symmetric key, auth key = KDF(key)
 *
 * ciphertext = Sym(algorithm type,
 *                  input = plaintext,
 *                  key = symmetric key,
 *                  iv = IV)
 * tag = HMAC-Auth(auth key, AAD, ciphertext, taglen)
 *
 * 2.5 Decryption Operation
 *
 * SymHMAC-Decrypt(key, IV, ciphertext, AAD, tag) -> plaintext, authentication result
 *
 * Input:
 *   key: The caller-provided key of size 256 bits
 *
 *   IV: The caller-provided initialization vector. The IV can have any size
 *	 including an empty bit-string.
 *
 *   ciphertext: The ciphertext that was received from the send over
 *               insecure channels.
 *
 *   AAD: The caller-provided additional authenticated data.
 *
 *   tag: The message authentication tag that was received from the send over
 *        insecure channels.
 *
 * Output
 *   plaintext: The plaintext of the data.
 *
 *   authentication result: A boolean indicator specifying whether the
 *			    authentication was successful. If it was
 *			    unsuccessful the caller shall reject the ciphertext.
 *
 * The decryption operation is performed as follows:
 *
 * symmetric key, auth key = KDF(key)
 *
 * plaintext = Sym(algorithm type,
 *                 input = ciphertext,
 *                 key = symmetric key,
 *                 iv = IV)
 *
 * taglen = size of tag
 *
 * new_tag = HMAC-Auth(auth key, AAD, ciphertext, taglen)
 *
 * if (new_tag == tag)
 *   authentication result = success
 * else
 *   authentication result = failure
 *
 * If the authentication result indicates a failure, the result of the
 * decryption operation SHALL be discarded.
 *
 * 3. Normative References
 *
 * [FIPS180-4] FIPS PUB 180-4, Secure Hash Standard (SHS), March 2012
 *
 * [FIPS198] FIPS PUB 198-1, The Keyed-Hash Message Authentication Code
 *           (HMAC), July 2008
 *
 * [RFC5869] Request for Comments: 5869, HMAC-based Extract-and-Expand Key
 *           Derivation Function (HKDF), May 2010
 *
 * [SP800-38A] NIST Special Publication 800-38A, Recommendation for Block
 *             Cipher Modes of Operation, 2001 Edition
 *
 ******************************************************************************/

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <stdlib.h>

#include "lc_hkdf.h"
#include "lc_symhmac.h"
#include "lc_sha512.h"
#include "memcmp_secure.h"
#include "ret_checkers.h"
#include "visibility.h"

#define min_t(type, a, b)	((type)a < (type)b) ? (type)a : (type)b

/**
 * @brief Set the key for the encryption or decryption operation
 *
 * @param sh [in] symmetric/HMAC crypt cipher handle
 * @param key [in] Buffer with key
 * @param keylen [in] Length of key buffer
 * @param iv [in] initialization vector to be used - only the IV size of the
 *		  underlying symmetric algorithm is supported
 * @param ivlen [in] length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
static int lc_sh_setkey(void *state,
			const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_sym_ctx *sym;
	struct lc_hmac_ctx *auth_ctx;
	uint8_t keystream[(256 / 8) * 2];
	int ret;

	sym = &sh->sym;
	auth_ctx = &sh->auth_ctx;

	CKINT(lc_hkdf(lc_sha512, key, keylen, NULL, 0, NULL, 0,
		      keystream, sizeof(keystream)));

	/* Initialize the symmetric algorithm */
	lc_sym_init(sym);
	CKINT(lc_sym_setkey(sym, keystream, sizeof(keystream) / 2));
	CKINT(lc_sym_setiv(sym, iv, ivlen));

	/* Initialize the authentication algorithm */
	lc_hmac_init(auth_ctx, keystream + sizeof(keystream) / 2,
		     sizeof(keystream) / 2);

out:
	memset_secure(keystream, 0, sizeof(keystream));
	return ret;
}

static void lc_sh_encrypt_tag(void *state,
			      const uint8_t *aad, size_t aadlen,
			      uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	size_t maxtaglen = lc_hmac_macsize(auth_ctx);
	uint8_t tmptag[maxtaglen];

	/* Add the AAD data into the HMAC context */
	lc_hmac_update(auth_ctx, aad, aadlen);

	/* Generate authentication tag */
	lc_hmac_final(auth_ctx, tmptag);

	if (taglen < maxtaglen)
		memcpy(tag, tmptag, taglen);
	else
		memcpy(tag, tmptag, maxtaglen);

	memset_secure(tmptag, 0, sizeof(tmptag));
}

static int lc_sh_decrypt_authenticate(void *state,
				      const uint8_t *aad, size_t aadlen,
				      const uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	size_t maxtaglen = lc_hmac_macsize(auth_ctx);
	uint8_t calctag[maxtaglen] __attribute__((aligned(sizeof(uint64_t))));
	int ret;

	taglen = min_t(size_t, taglen, maxtaglen);

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_sh_encrypt_tag(sh, aad, aadlen, calctag, taglen);

	ret = (memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	memset_secure(calctag, 0, taglen);

	return ret;
}

static void
lc_sh_encrypt(void *state,
	      const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	size_t trailing_bytes = datalen % sym_algo->blocksize;

	lc_sym_encrypt(sym, plaintext, ciphertext, datalen);

	/* Safety-measure to avoid leaking data */
	if (trailing_bytes) {
		memset(ciphertext + datalen - trailing_bytes, 0,
		       trailing_bytes);
	}

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_hmac_update(auth_ctx, ciphertext, datalen);
}

static void
lc_sh_decrypt(void *state,
	      const uint8_t *ciphertext, uint8_t *plaintext, size_t datalen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	size_t trailing_bytes = datalen % sym_algo->blocksize;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_hmac_update(auth_ctx, ciphertext, datalen);
	lc_sym_decrypt(sym, ciphertext, plaintext, datalen);

	/* Safety-measure to avoid leaking data */
	if (trailing_bytes) {
		memset(plaintext + datalen - trailing_bytes, 0,
		       trailing_bytes);
	}

}

static void
lc_sh_encrypt_oneshot(void *state,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;

	/* Confidentiality protection: Encrypt data */
	lc_sh_encrypt(sh, plaintext, ciphertext, datalen);

	/* Integrity protection: HMAC data */
	lc_sh_encrypt_tag(sh, aad, aadlen, tag, taglen);
}

static int
lc_sh_decrypt_oneshot(void *state,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */
	/* Confidentiality protection: decrypt data */
	lc_sh_decrypt(sh, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_sh_decrypt_authenticate(sh, aad, aadlen, tag, taglen);
}

DSO_PUBLIC
int lc_sh_alloc(const struct lc_sym *sym, const struct lc_hash *hash,
		struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp;
	int ret;

	ret = posix_memalign((void *)&tmp, sizeof(uint64_t),
			     LC_SH_CTX_SIZE(sym, hash));
	if (ret)
		return -ret;

	LC_SH_SET_CTX(tmp, sym, hash);

	*ctx = tmp;

	return 0;
}

static void lc_sh_zero(void *state)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_hash_ctx *hash_ctx = &auth_ctx->hash_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	const struct lc_hash *hash_algo = hash_ctx->hash;

	memset_secure((uint8_t *)state + sizeof(struct lc_sh_cryptor),
		      0, LC_SH_STATE_SIZE(sym_algo, hash_algo));
}

struct lc_aead _lc_symhmac_aead = {
	.setkey		= lc_sh_setkey,
	.encrypt	= lc_sh_encrypt_oneshot,
	.enc_update	= lc_sh_encrypt,
	.enc_final	= lc_sh_encrypt_tag,
	.decrypt	= lc_sh_decrypt_oneshot,
	.dec_update	= lc_sh_decrypt,
	.dec_final	= lc_sh_decrypt_authenticate,
	.zero		= lc_sh_zero
};
DSO_PUBLIC
const struct lc_aead *lc_symhmac_aead = &_lc_symhmac_aead;
