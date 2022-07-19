/* Symmetric stream AEAD cipher based on CSHAKE
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

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <stdlib.h>

#include "build_bug_on.h"
#include "lc_cshake_crypt.h"
#include "memcmp_secure.h"
#include "visibility.h"
#include "xor.h"

#define min_t(type, a, b)	((type)a < (type)b) ? (type)a : (type)b

DSO_PUBLIC
void lc_cc_setkey(struct lc_cc_cryptor *cc, const uint8_t *key, size_t keylen)
{
	struct lc_hash_ctx *cshake = &cc->cshake;
	struct lc_hash_ctx *auth_ctx = &cc->auth_ctx;

	/*
	 * The keystream block size must be a multiple of the cSHAKE256 block
	 * size, as otherwise the multiple lc_cshake_final calls will not return
	 * the same data as one lc_cshake_final call, because the Keccack
	 * operation to generate a new internal state is invoked at a different
	 * time.
	 */
	BUILD_BUG_ON(LC_SHA3_256_SIZE_BLOCK % LC_CC_KEYSTREAM_BLOCK);

	lc_cshake_init(cshake, key, keylen, NULL, 0);

	/*
	 * Generate key for cSHAKE authentication - we simply use two different
	 * keys for the cSHAKE keystream generator and the cSHAKE authenticator.
	 *
	 * After the lc_cshake_final we have to call lc_hash_final for
	 * getting new cSHAKE data. The digest size is already set with the
	 * lc_cshake_final= operation.
	 */
	lc_cshake_final(cshake, cc->keystream, LC_CC_KEYSTREAM_BLOCK);
	lc_cshake_init(auth_ctx, cc->keystream, LC_CC_KEYSTREAM_BLOCK, NULL, 0);

	/* Generate first keystream */
	lc_hash_final(cshake, cc->keystream);

	cc->keystream_ptr = 0;
}

DSO_PUBLIC
void lc_cc_crypt(struct lc_cc_cryptor *cc, const uint8_t *in, uint8_t *out,
		 size_t len)
{
	struct lc_hash_ctx *cshake = &cc->cshake;

	while (len) {
		size_t todo = min_t(size_t, len, LC_CC_KEYSTREAM_BLOCK);

		/* Generate a new keystream block */
		if (cc->keystream_ptr >= LC_CC_KEYSTREAM_BLOCK) {
			lc_hash_final(cshake, cc->keystream);

			cc->keystream_ptr = 0;
		}

		todo = min_t(size_t, todo,
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

DSO_PUBLIC
void lc_cc_encrypt_tag(struct lc_cc_cryptor *cc,
		       const uint8_t *aad, size_t aadlen,
		       uint8_t *tag, size_t taglen)
{
	struct lc_hash_ctx *auth_ctx = &cc->auth_ctx;

	/* Add the AAD data into the CSHAKE context */
	lc_hash_update(auth_ctx, aad, aadlen);

	/* Generate authentication tag */
	lc_cshake_final(auth_ctx, tag, taglen);
}

DSO_PUBLIC
int lc_cc_decrypt_authenticate(struct lc_cc_cryptor *cc,
			       const uint8_t *aad, size_t aadlen,
			       const uint8_t *tag, size_t taglen)
{
	uint8_t calctag[128] __attribute__((aligned(sizeof(uint64_t))));
	uint8_t *calctag_p = calctag;
	int ret;

	if (taglen > sizeof(calctag)) {
		ret = posix_memalign((void *)&calctag_p, sizeof(uint64_t),
				     taglen);
		if (ret)
			return -ret;
	}

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_cc_encrypt_tag(cc, aad, aadlen, calctag_p, taglen);

	ret = (memcmp_secure(calctag_p, taglen, tag, taglen) ? -EBADMSG : 0);
	memset_secure(calctag_p, 0, taglen);
	if (taglen > sizeof(calctag))
		free(calctag_p);

	return ret;
}

DSO_PUBLIC
void lc_cc_zero_free(struct lc_cc_cryptor *cc)
{
	if (!cc)
		return;

	lc_cc_zero(cc);

	free(cc);
}

DSO_PUBLIC
int lc_cc_alloc(const struct lc_hash *hash, struct lc_cc_cryptor **cc)
{
	struct lc_cc_cryptor *tmp;
	int ret = posix_memalign((void *)&tmp, sizeof(uint64_t),
				 LC_CC_CTX_SIZE(hash));

	if (ret)
		return -ret;

	LC_CC_SET_CTX(tmp, hash);

	*cc = tmp;

	return 0;
}
