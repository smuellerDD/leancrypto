/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "alignment.h"
#include "ascon_internal.h"
#include "build_bug_on.h"
#include "compare.h"
#include "lc_ascon_hash.h"
#include "lc_ascon_lightweight.h"
#include "visibility.h"

/*
 * Ascon with standard Ascon permutation
 */
#define LC_AEAD_ASCON_128_IV 0x80400c0600000000
#define LC_AEAD_ASCON_128a_IV 0x80800c0800000000

static void ascon_aead_selftest(int *tested)
{
	/*
	 * Vector 1089 from genkat_crypto_aead_ascon128v12_ref generated by code
	 * https://github.com/ascon/ascon-c
	 */
	static const uint8_t pt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	static const uint8_t aad[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	static const uint8_t nonce[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	static const uint8_t exp_ct[] = {
		0xA5, 0x52, 0x36, 0xAC, 0x02, 0x0D, 0xBD, 0xA7,
		0x4C, 0xE6, 0xCC, 0xD1, 0x0C, 0x68, 0xC4, 0xD8,
		0x51, 0x44, 0x50, 0xA3, 0x82, 0xBC, 0x87, 0xC6,
		0x89, 0x46, 0xD8, 0x6A, 0x92, 0x1D, 0xD8, 0x8E
	};
	static const uint8_t exp_tag[] = {
		0x2A, 0xDD, 0xDF, 0xBB, 0xE7, 0x7D, 0x41, 0x12,
		0x83, 0x0E, 0x01, 0x96, 0x0B, 0x9D, 0x38, 0xD5
	};

	uint8_t out_enc[sizeof(exp_ct)];
	uint8_t tag[sizeof(exp_tag)];

	LC_SELFTEST_RUN(tested);

	LC_AL_CTX_ON_STACK(al, lc_ascon_128a);

	/* One shot encryption with pt ptr != ct ptr */
	assert(!lc_aead_setkey(al, key, sizeof(key), nonce, sizeof(nonce)));
	assert(!lc_aead_encrypt(al, pt, out_enc, sizeof(pt), aad, sizeof(aad),
				tag, sizeof(tag)));
	lc_aead_zero(al);

	lc_compare_selftest(out_enc, exp_ct, sizeof(exp_ct),
			    "Ascon lightweight crypt: Encryption, ciphertext");
	lc_compare_selftest(tag, exp_tag, sizeof(exp_tag),
			    "Ascon lightweight crypt: Encryption, tag");

	/* One shot decryption with pt ptr != ct ptr */
	assert(!lc_aead_setkey(al, key, sizeof(key), nonce, sizeof(nonce)));
	assert(!lc_aead_decrypt(al, out_enc, out_enc, sizeof(out_enc), aad,
				sizeof(aad), tag, sizeof(tag)));
	lc_aead_zero(al);
	lc_compare_selftest(out_enc, pt, sizeof(pt),
			    "Ascon lightweight crypt: Decryption, plaintext");
}

int lc_ascon_ascon_setiv(struct lc_ascon_cryptor *ascon, size_t keylen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	static int tested = 0;

	/* Check that the key store is sufficiently large */
	BUILD_BUG_ON(sizeof(ascon->key) < 64);

	ascon_aead_selftest(&tested);

	switch (hash->sponge_rate) {
	case 128 / 8: /* Ascon 128a */
		if (keylen != 16)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_128a_IV;
		ascon->keylen = 16;
		ascon->roundb = 8;

		break;

	case 64 / 8: /* Ascon 128 */
		if (keylen != 16)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_128_IV;
		ascon->keylen = 16;
		ascon->roundb = 6;

		break;
	default:
		return 0;
	}

	return 1;
}

LC_INTERFACE_FUNCTION(int, lc_al_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	struct lc_ascon_cryptor *ascon;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_ASCON_ALIGNMENT,
			       LC_AL_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_ASCON_SET_CTX(tmp, hash);

	ascon = tmp->aead_state;
	ascon->statesize = LC_ASCON_HASH_STATE_SIZE;

	*ctx = tmp;

	return 0;
}
