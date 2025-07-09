/* Symmetric stream AEAD cipher based on cSHAKE
 *
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

/******************************************************************************
 * Abstract
 *
 * This specification defines a symmetric stream cipher algorithm using
 * the authenticated encryption with additional data (AEAD) approach. This
 * algorithm can be used to encrypt and decrypt arbitrary user data.
 * The cipher algorithm uses the cSHAKE algorithm to generate a key stream
 * which is XORed with either the plaintext (encryption) or ciphertext
 * (decryption) data. The cSHAKE is initialized with the user-provided key
 * and the user-provided IV. In addition, a second cSHAKE instance is
 * initialized which calculates a keyed-message digest of the ciphertext to
 * create a message authentication tag. This message authentication tag is used
 * during decryption to verify the integrity of the ciphertext.
 *
 * 1. Introduction
 *
 * This specification defines a symmetric stream cipher algorithm using
 * the authenticated encryption with additional data (AEAD) approach. This
 * algorithm can be used to encrypt and decrypt arbitrary user data.
 *
 * The base of the algorithm is the generation of a key stream using cSHAKE
 * which is XORed with the plaintext for the encryption operation, or with
 * the ciphertext for the decryption operation.
 *
 * The algorithm also applies an Encrypt-Then-MAC by calculating a message
 * authentication tag using cSHAKE over the ciphertext. During decryption, this
 * calculated message authentication tag is compared with the message
 * authentication tag obtained during the encryption operation. If both values
 * show a mismatch, the authentication fails and the decryption operation is
 * terminated. Only when both message authentication tags are identical
 * the decryption operation completes successfully and returns the decrypted
 * message.
 *
 * The key along with the IV are used to initialize the cSHAKE algorithm
 * for generating the key stream. The first output block from the cSHAKE
 * is used to initialize the authenticating cSHAKE instance used to
 * calculate the message authentication tag.
 *
 * The size of the key is defined to be 256 bits when using cSHAKE-256.
 * The size of the IV can be selected by the caller. The algorithm supports
 * any IV size, including having no IV.
 *
 * As part of the authentication, the algorithm allows the addition of
 * additional authenticated data (AAD) of arbitrary size. This AAD is inserted
 * into the authentication cSHAKE instance during calculating the message
 * authentication tag.
 *
 * 2. cSHAKE-based AEAD Cipher Algorithm
 *
 * 2.1 Notation
 *
 * The cSHAKE-hash denotes the cSHAKE256 function [SP800-185]. The cSHAKE-hash
 * has 4 arguments: the main input bit string X, the requested output length L
 * in bits, a function-name bit string, and an optional customization bit
 * string S.
 *
 * The inputs to the cSHAKE-hash function are specified with references to these
 * parameters.
 *
 * 2.3. Common Processing of Data
 *
 * cSHAKE-Crypt(key, IV, input data) -> output data, auth key
 *
 * Inputs:
 *   key: The caller-provided key of size 256 bits
 *
 *   IV: The caller-provided initialization vector. The IV can have any size
 *	 including an empty bit-string. See chapter 3 for a discussion of the
 *	 IV, however.
 *
 *   input data: The caller-provided input data - in case of encryption, the
 *               caller provides the plaintext data, in case of decryption,
 *               caller provides the ciphertext data.
 *
 * Outputs:
 *   output data: The resulting data - in case of encryption, the ciphertext
 *                is produced, in case of decryption, the plaintext is returned.
 *   auth key: The key that is used for the cSHAKE operation calculating the
 *             message authentication tag.
 *
 * The common processing of data is performed as follows:
 *
 * input length = size of input data in bits
 * KS = cSHAKE(N = "cSHAKE-AEAD crypt",
 *             X = IV,
 *             L = 256 bits + input length,
 *             S = key)
 * auth key = 256 left-most bits of KS
 * KS crypt = all right-most bits of KS starting with the 256th bit
 * output data = input data XOR KS crypt
 *
 * 2.3 Calculating of Message Authentication Tag
 *
 * cSHAKE-Auth(auth key, AAD, ciphertext, taglen) -> tag
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
 * tag = cSHAKE(N = "cSHAKE-AEAD auth",
 *              X = AAD || ciphertext,
 *              L = taglen,
 *              S = auth key)
 *
 * 2.4. Encryption Operation
 *
 * cSHAKE-Encrypt(key, IV, plaintext, AAD, taglen) -> ciphertext, tag
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
 * ciphertext, auth key = cSHAKE-Crypt(key, IV, plaintext)
 * tag = cSHAKE-Auth(auth key, AAD, ciphertext, taglen)
 *
 * 2.5 Decryption Operation
 *
 * cSHAKE-Decrypt(key, IV, ciphertext, AAD, tag) -> plaintext, authentication result
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
 * plaintext, auth key = cSHAKE-Crypt(key, IV, ciphertext)
 * taglen = size of tag
 * new_tag = cSHAKE-Auth(auth key, AAD, ciphertext, taglen)
 * if (new_tag == tag)
 *   authentication result = success
 * else
 *   authentication result = failure
 *
 * If the authentication result indicates a failure, the result of the
 * decryption operation SHALL be discarded.
 *
 * 3. Cryptographic Aspects
 *
 * The cSHAKE AEAD algorithm is a stream cipher which uses the XOR-construction
 * method to perform encryption and decryption. This method is susceptible to
 * attacks when the key stream is identical between different encryption
 * operations. This this case, the key stream can be trivially remove and
 * thus a decryption of the data is possible as follows:
 *
 * ciphertext 1 = plaintext 1 XOR KS
 *
 * ciphertext 2 = plaintext 2 XOR KS
 *
 * ciphertext 1 XOR ciphertext 2 =
 *	(plaintext 1 XOR KS) XOR (plaintext 2 XOR KS) =
 *	plaintext 1 XOR plaintext 2
 *
 * Thus, the security of the cSHAKE algorithm is based on the property that
 * the key stream KS is unique for different encryption operations. The key
 * stream is derived from the key and the IV using cSHAKE. In common use cases,
 * the key may not be able to be modified. Yet, the IV can be modified. Common
 * protocols allow the generation of a new IV during encryption and transmit
 * the IV to the decryptor. Thus, the IV can be used as a diversifier to for
 * the different encryption operations to obtain a different key stream.
 *
 * As the cSHAKE algorithm's IV size is unspecified in size, the cSHAKE
 * algorithm can handle any size that may be pre-defined by the use case or
 * protocol consuming the cSHAKE AEAD algorithm.
 *
 * Considering the avalanche effect of the underlying KECCAK algorithm, even
 * a small IV may result in a completely different key stream rendering the
 * aforementioned attack impossible.
 *
 * The IV is not required to be a confidentially-protected value. It can be
 * communicated in plaintext to the decryptor. This is due to the fact that
 * the IV is used together with the key to generate the key stream using cSHAKE.
 * An attacker is not able to construct either the key or the key stream by
 * only possessing the IV. Furthermore, the key is defined to possess a
 * cryptographic meaningful entropy (see section 2.3) which implies that the
 * IV does not need to deliver additional entropy to ensure the strength of
 * the cSHAKE AEAD algorithm.
 *
 * It is permissible that the IV is generated either by a random number
 * generator or using a deterministic construction method. The only requirement
 * is that the probability in generating a key / IV collision is insignificantly
 * low. This implies that considering the IV is only a diversifier for the
 * key stream, and the fact that the IV is not required to be private, the
 * random number generator is not required to possess a cryptographic meaningful
 * strength.
 *
 * The selection of cSHAKE for generating the keystream is based on the
 * statement in [SP800-185] declaring Keccak is usable as a pseudorandom
 * function.
 *
 * The approach of Encrypt-Then-MAC is selected based on the analysis of
 * [AUTHENC] table 3 considering on the finding that the MAC algorithm of cSHAKE
 * is strongly unforgeable.
 *
 * 4. Comparison with KMAC-based AEAD Cipher Algorithm
 *
 * The cSHAKE cipher is completely identical to the KMAC cipher with the
 * exception that the cSHAKE cipher uses cSHAKE256 and the KMAC cipher uses
 * KMACXOF256 as central functions. The difference of the cSHAKE customization
 * string applied by KMAC compared to cSHAKE is irrelevant to the cryptographic
 * strength of both.
 *
 * The handling of the key is also very similar:
 *
 * * The cSHAKE cipher sets the key as part of the N input - the N and X input
 *   are concatenated and padded by cSHAKE to bring the entire string into
 *   multiples of a cSHAKE block. This data is inserted into the SHAKE algorithm
 *   which implies that the insertion triggers as many KECCAK operations as
 *   cSHAKE blocks are present based on the input. The cSHAKE DRNG data implies
 *   that only one cSHAKE block is present and thus one KECCAK operation is
 *   performed.
 *
 * * The KMAC cipher sets the key compliant to the KMAC definition. KMAC sets
 *   two well-defined strings as part of the cSHAKE initialization. The cSHAKE
 *   initialization concatenates and pads the input strings to bring the entire
 *   string into multiples of a cSHAKE block. This data is inserted into the
 *   SHAKE algorithm which implies that the insertion triggers as many KECCAK
 *   operations as cSHAKE blocks are present on the input. The KMAC cipher key
 *   data implies that only one cSHAKE block is present and thus one KECCAK
 *   operation is performed. In addition, KMAC pads the key data into a string
 *   that is also multiples of a cSHAKE block in size. Again, this data is
 *   inserted into the SHAKE algorithm which again triggers as many KECCAK
 *   operations as cSHAKE blocks are present with the key-based input. The
 *   KMAC-based AEAD cipher algorithm specification implies again, that only one
 *   KECCAK operation is performed.
 *
 * The rationale shows that for both, the cSHAKE cipher and the KMAC cipher,
 * the key, is inserted into the SHAKE state. The additional data inserted with
 * the KMAC operation does not contain any entropy and only mixes the SHAKE
 * state further without affecting the existing entropy provided with the key
 * or diminish the information inserted with the IV. Therefore, with respect to
 * the security strength, the cSHAKE cipher and the KMAC cipher are considered
 * equal.
 *
 * Considering that the cSHAKE cipher requires only one KECCAK operation during
 * initialization whereas the KMAC cipher requires two operations, the cSHAKE
 * cipher requires less KECCAK operations for processing the same amount of
 * data.
 *
 * Thus, the cSHAKE cipher has a higher performance with a equal entropy
 * management comparing to the KMAC cipher.
 *
 * 5. Normative References
 *
 * [AUTHENC] Mihir Bellare and Chanathip Namprempre, Authenticated Encryption:
 *	     Relations among Notions and Analysis of the Generic Composition
 *	     Paradigm
 *
 * [SP800-185] John Kelsey, Shu-jen Chang, Ray Perlne, NIST Special Publication
 *             800-185 SHA-3 Derived Functions: cSHAKE, CSHAKE, TupleHash and
 *             ParallelHash, December 2016
 ******************************************************************************/

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "cpufeatures.h"
#include "lc_cshake_crypt.h"
#include "lc_memcmp_secure.h"
#include "math_helper.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

#define LC_CC_AUTHENTICATION_KEY_SIZE (256 >> 3)
#define LC_CC_CUSTOMIZATION_STRING "cSHAKE-AEAD crypt"
#define LC_CC_AUTH_CUSTOMIZATION_STRING "cSHAKE-AEAD auth"

static void lc_cc_selftest(int *tested, const char *impl)
{
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	static const uint8_t exp_ct[] = {
		0x5d, 0x9f, 0x69, 0xff, 0xbc, 0xaf, 0x76, 0xeb, 0x86, 0xdd,
		0xaf, 0x5f, 0x37, 0x0c, 0xb8, 0xf3, 0x4f, 0xf5, 0xf4, 0xa4,
		0xbc, 0x11, 0x98, 0x11, 0x96, 0x29, 0x14, 0x48, 0xc3, 0xfe,
		0x62, 0x1f, 0x3a, 0x0d, 0x3a, 0x62, 0xae, 0xe4, 0x74, 0x65,
		0x02, 0x31, 0x47, 0xf7, 0x36, 0xf8, 0xfd, 0x26, 0x96, 0xf3,
		0x32, 0x35, 0xb2, 0x44, 0x21, 0x1f, 0x56, 0xb7, 0x01, 0xaa,
		0x01, 0xef, 0x16, 0x09
	};
	static const uint8_t exp_tag[] = {
		0x82, 0x40, 0x81, 0x7f, 0xf9, 0xa0, 0xef, 0x9f, 0x53, 0x29,
		0x82, 0x80, 0x8b, 0xdb, 0xc1, 0x0d, 0x52, 0x10, 0x10, 0x87,
		0x7e, 0x30, 0x9c, 0x6e, 0x49, 0xb0, 0x33, 0x8e, 0xfa, 0x7c,
		0x28, 0x6d, 0x98, 0x94, 0x30, 0xad, 0x39, 0x62, 0xfd, 0x5f,
		0xb0, 0x14, 0x6d, 0xe7, 0x36, 0x17, 0x49, 0x20, 0x79, 0x5a,
		0xc5, 0xbd, 0x6b, 0xd9, 0xbd, 0x72, 0x0a, 0x54, 0x79, 0x67,
		0x0d, 0xe3, 0xc3, 0x83
	};
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	char status[25];

	LC_SELFTEST_RUN(tested);

	LC_CC_CTX_ON_STACK(cc, lc_cshake256);

	lc_aead_setkey(cc, key, sizeof(key), NULL, 0);
	lc_aead_encrypt(cc, in, act_ct, sizeof(in), in, sizeof(in), act_tag,
			sizeof(act_tag));
	snprintf(status, sizeof(status), "%s encrypt", impl);
	lc_compare_selftest(act_ct, exp_ct, sizeof(exp_ct), status);
	lc_aead_zero(cc);

	lc_aead_setkey(cc, key, sizeof(key), NULL, 0);
	lc_aead_decrypt(cc, act_ct, act_ct, sizeof(act_ct), in, sizeof(in),
			act_tag, sizeof(act_tag));
	snprintf(status, sizeof(status), "%s decrypt", impl);
	lc_compare_selftest(act_ct, in, sizeof(in), status);
	lc_aead_zero(cc);
}

/**
 * @brief Set the key for the encyption or decryption operation
 *
 * @param [in] state cSHAKE crypt cipher handle
 * @param [in] key Buffer with key
 * @param [in] keylen Length of key buffer
 * @param [in] iv initialization vector to be used
 * @param [in] ivlen length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
static int lc_cc_setkey(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_hash_ctx *cshake = &cc->cshake;
	struct lc_cshake_ctx *auth_ctx = &cc->auth_ctx;
	static int tested = 0;

	/* Timecop: The key is sentitive. */
	poison(key, keylen);

	lc_cc_selftest(&tested, "cSHAKE AEAD");

	/*
	 * The keystream block size should be a multiple of the cSHAKE256 block
	 * size, as otherwise the filling of it is inefficient.
	 */
	BUILD_BUG_ON(LC_SHA3_256_SIZE_BLOCK % LC_CC_KEYSTREAM_BLOCK);
	BUILD_BUG_ON(LC_CC_AUTHENTICATION_KEY_SIZE > LC_CC_KEYSTREAM_BLOCK);

	lc_cshake_init(cshake, (uint8_t *)LC_CC_CUSTOMIZATION_STRING,
		       sizeof(LC_CC_CUSTOMIZATION_STRING) - 1, key, keylen);
	lc_hash_update(cshake, iv, ivlen);

	/*
	 * Generate key for cSHAKE authentication - we simply use two different
	 * keys for the cSHAKE keystream generator and the cSHAKE authenticator.
	 *
	 * After the lc_cshake_final we have to call lc_hash_final for
	 * getting new cSHAKE data. The digest size is already set with the
	 * lc_cshake_final operation.
	 */
	lc_cshake_final(cshake, cc->keystream, LC_CC_KEYSTREAM_BLOCK);
	lc_cshake_ctx_init(auth_ctx, (uint8_t *)LC_CC_AUTH_CUSTOMIZATION_STRING,
			   sizeof(LC_CC_AUTH_CUSTOMIZATION_STRING) - 1,
			   cc->keystream, LC_CC_AUTHENTICATION_KEY_SIZE);

	/* Set the pointer to the start of the keystream */
	cc->keystream_ptr = LC_CC_AUTHENTICATION_KEY_SIZE;

	return 0;
}

static void lc_cc_crypt(struct lc_cc_cryptor *cc, const uint8_t *in,
			uint8_t *out, size_t len)
{
	struct lc_hash_ctx *cshake;

	cshake = &cc->cshake;

	while (len) {
		size_t todo = min_size(len, LC_CC_KEYSTREAM_BLOCK);

		/* Generate a new keystream block */
		if (cc->keystream_ptr >= LC_CC_KEYSTREAM_BLOCK) {
			lc_hash_final(cshake, cc->keystream);

			cc->keystream_ptr = 0;
		}

		todo = min_size(todo,
				LC_CC_KEYSTREAM_BLOCK - cc->keystream_ptr);

		if (in != out)
			memcpy(out, in, todo);

		/* Perform the encryption operation */
		xor_64(out, cc->keystream + cc->keystream_ptr, todo);

		len -= todo;
		in += todo;
		out += todo;
		cc->keystream_ptr += todo;
	}
}

static void lc_cc_add_aad(void *state, const uint8_t *aad, size_t aadlen)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_cshake_ctx *auth_ctx;

	auth_ctx = &cc->auth_ctx;

	/* Add the AAD data into the CSHAKE context */
	lc_cshake_ctx_update(auth_ctx, aad, aadlen);
}

static void lc_cc_encrypt_tag(void *state, uint8_t *tag, size_t taglen)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_cshake_ctx *auth_ctx;

	auth_ctx = &cc->auth_ctx;

	/* Generate authentication tag */
	lc_cshake_ctx_final(auth_ctx, tag, taglen);

	/* Timecop: Tag is not sensitive. */
	unpoison(tag, taglen);

	/* Re-initialize the authentication context for new message digest */
	lc_cshake_ctx_reinit(auth_ctx);
}

static int lc_cc_decrypt_authenticate(void *state, const uint8_t *tag,
				      size_t taglen)
{
	struct lc_cc_cryptor *cc = state;
	uint8_t calctag[128] __align(sizeof(uint64_t));
	uint8_t *calctag_p = calctag;
	int ret;

	if (taglen > sizeof(calctag)) {
		ret = lc_alloc_aligned((void **)&calctag_p,
				       LC_MEM_COMMON_ALIGNMENT, taglen);
		if (ret)
			return -ret;
	}

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_cc_encrypt_tag(cc, calctag_p, taglen);

	ret = (lc_memcmp_secure(calctag_p, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag_p, 0, taglen);
	if (taglen > sizeof(calctag))
		lc_free(calctag_p);

	return ret;
}

static void lc_cc_encrypt(void *state, const uint8_t *plaintext,
			  uint8_t *ciphertext, size_t datalen)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_cshake_ctx *auth_ctx;

	auth_ctx = &cc->auth_ctx;

	lc_cc_crypt(cc, plaintext, ciphertext, datalen);

	/* Timecop: ciphertext is not sensitive regarding side channels. */
	unpoison(ciphertext, datalen);

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_cshake_ctx_update(auth_ctx, ciphertext, datalen);
}

static void lc_cc_decrypt(void *state, const uint8_t *ciphertext,
			  uint8_t *plaintext, size_t datalen)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_cshake_ctx *auth_ctx;

	auth_ctx = &cc->auth_ctx;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_cshake_ctx_update(auth_ctx, ciphertext, datalen);
	lc_cc_crypt(cc, ciphertext, plaintext, datalen);

	/* Timecop: plaintext is not sensitive regarding side channels. */
	unpoison(plaintext, datalen);
}

static void lc_cc_encrypt_oneshot(void *state, const uint8_t *plaintext,
				  uint8_t *ciphertext, size_t datalen,
				  const uint8_t *aad, size_t aadlen,
				  uint8_t *tag, size_t taglen)
{
	struct lc_cc_cryptor *cc = state;

	/* Insert the AAD */
	lc_cc_add_aad(state, aad, aadlen);

	/* Confidentiality protection: Encrypt data */
	lc_cc_encrypt(cc, plaintext, ciphertext, datalen);

	/* Integrity protection: CSHAKE data */
	lc_cc_encrypt_tag(cc, tag, taglen);
}

static int lc_cc_decrypt_oneshot(void *state, const uint8_t *ciphertext,
				 uint8_t *plaintext, size_t datalen,
				 const uint8_t *aad, size_t aadlen,
				 const uint8_t *tag, size_t taglen)
{
	struct lc_cc_cryptor *cc = state;

	/* Insert the AAD */
	lc_cc_add_aad(state, aad, aadlen);

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */
	/* Confidentiality protection: decrypt data */
	lc_cc_decrypt(cc, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_cc_decrypt_authenticate(cc, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_cc_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_CSHAKE_CRYPT_ALIGNMENT,
			       LC_CC_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_CC_SET_CTX(tmp, hash);

	*ctx = tmp;

	return 0;
}

static void lc_cc_zero(void *state)
{
	struct lc_cc_cryptor *cc = state;
	struct lc_hash_ctx *cshake;
	const struct lc_hash *hash;

	cshake = &cc->cshake;
	hash = cshake->hash;
	lc_memset_secure((uint8_t *)cc + sizeof(struct lc_cc_cryptor), 0,
			 LC_CC_STATE_SIZE(hash));
}

struct lc_aead _lc_cshake_aead = { .setkey = lc_cc_setkey,
				   .encrypt = lc_cc_encrypt_oneshot,
				   .enc_init = lc_cc_add_aad,
				   .enc_update = lc_cc_encrypt,
				   .enc_final = lc_cc_encrypt_tag,
				   .decrypt = lc_cc_decrypt_oneshot,
				   .dec_init = lc_cc_add_aad,
				   .dec_update = lc_cc_decrypt,
				   .dec_final = lc_cc_decrypt_authenticate,
				   .zero = lc_cc_zero };
LC_INTERFACE_SYMBOL(const struct lc_aead *, lc_cshake_aead) = &_lc_cshake_aead;
