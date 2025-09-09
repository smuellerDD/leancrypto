/* Ascon-Keccak specific code
 *
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "fips_mode.h"
#include "lc_ascon_keccak.h"
#include "lc_memory_support.h"
#include "lc_sha3.h"
#include "timecop.h"
#include "visibility.h"

/*
 * Ascon with Keccak permutation
 *
 * The algorithm with have the security strength equal to their key size
 * as they are defined with a Keccak sponge capacity of double the size of
 * the key. The associated quantum adversary strength is half of the key
 * size.
 *
 * The selected capacity defines the datablock rate as specified for SHA3-256 /
 * SHA3-512 considering the use of Keccak-p[1600,24]: rate = 1600 - capacity.
 *
 * The Ascon-Keccak algorithm is defined with the reference to <keysize>.
 *
 *                       -------------- Bit size of -------------- Rounds
 *                       Key   Nonce        Tag          DataBlock  pa pb
 *                                                       Rate
 * Ascon-Keccak 512      512   128 to 512   128 to 512    576       24 24
 * Ascon-Keccak 256      256   128 to 256   128 to 256   1088       24 24
 *
 * Note, the tag is allowed also to be larger, up to the size of the key.
 */

/*
 * The IV is defined using the specification provided with the Ascon algorithm.
 * The IV is specified without the tag length which is set in lc_ak_setiv.
 */
#define LC_AEAD_ASCON_KECCAK_512_IV 0x4048181800000000
#define LC_AEAD_ASCON_KECCAK_256_IV 0x2088181800000000

static void lc_ak_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_ct[] = {
		0xbf, 0xdf, 0xeb, 0x80, 0x84, 0x88, 0xbe, 0xd1, 0xda, 0xdb,
		0x85, 0xda, 0xe2, 0x39, 0x18, 0xfc, 0x14, 0x20, 0xf1, 0x0b,
		0xc4, 0xd2, 0xaf, 0xc3, 0x1c, 0xee, 0x97, 0x0f, 0xad, 0x52,
		0xa0, 0xfa, 0xa6, 0x1a, 0x58, 0x0b, 0x56, 0x3f, 0xf6, 0xe8,
		0x03, 0x49, 0x43, 0xf1, 0x12, 0x0d, 0x5e, 0xb0, 0x82, 0x69,
		0xe2, 0xfd, 0xde, 0x02, 0xc2, 0x12, 0xd6, 0x91, 0x3b, 0x31,
		0x3d, 0x20, 0x54, 0x63
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_tag[] = { 0xc5, 0x72, 0x34, 0x77, 0xa0, 0x60,
					   0x46, 0x0d, 0xc1, 0x74, 0x21, 0x17,
					   0x6a, 0x28, 0xbb, 0x70 };
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(LC_ALG_STATUS_ASCON_KECCAK);

	LC_AK_CTX_ON_STACK(ak, lc_sha3_256);

	lc_ascon_setkey_int(ak->aead_state, key, sizeof(key), iv, sizeof(iv),
			    1);
	lc_aead_encrypt(ak, in, act_ct, sizeof(in), in, sizeof(in),
				act_tag, sizeof(act_tag));
	if (lc_compare_selftest(LC_ALG_STATUS_ASCON_KECCAK, act_ct, exp_ct,
				sizeof(exp_ct),
				"Ascon Keccak crypt: Encryption, ciphertext"))
		goto out;
	if (lc_compare_selftest(LC_ALG_STATUS_ASCON_KECCAK, act_tag, exp_tag,
				sizeof(exp_tag),
				"Ascon Keccak crypt: Encryption, tag"))
		goto out;

	lc_aead_zero(ak);

	lc_ascon_setkey_int(ak->aead_state, key, sizeof(key), iv, sizeof(iv),
			    1);
	lc_aead_decrypt(ak, act_ct, act_ct, sizeof(act_ct), in,
			sizeof(in), act_tag, sizeof(act_tag));
	lc_compare_selftest(LC_ALG_STATUS_ASCON_KECCAK, act_ct, in, sizeof(in),
			    "Ascon Keccak crypt: Decryption, plaintext");

out:
	lc_aead_zero(ak);
}

int lc_ak_setiv(struct lc_ascon_cryptor *ascon, size_t keylen, int nocheck)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;

	/* Check that the key store is sufficiently large */
	BUILD_BUG_ON(sizeof(ascon->key) < 64);

	/* This is a FIPS 140 non-approved algorithm */
	if (fips140_mode_enabled())
		return -EOPNOTSUPP;

	/*
	 * Tag size can be at most the key size which in turn is smaller than
	 * the capacity. Thus, all bits of the tag (a) are always affected by
	 * the key, and (b) affected by the capacity.
	 *
	 * Note, this code allows small tag sizes, including zero tag sizes.
	 * It is supported here, but the decryption side requires 16 bytes
	 * tag length as a minimum.
	 */
	if (ascon->taglen < 16 || ascon->taglen > keylen)
		return -EINVAL;

	switch (hash->sponge_rate) {
	case 0x240 / 8: /* Keccak security level 512 bits */

		if (!nocheck) {
			lc_ak_selftest();
			LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ASCON_KECCAK);
		}

		if (keylen != 64)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_KECCAK_512_IV;

		/* Add the taglen to fifth byte in the IV */
		state_mem[0] |= (uint64_t)(ascon->taglen << (8 * 3));

		ascon->keylen = 64;

		break;
	case 0x440 / 8: /* Keccak security level 256 bits */

		if (!nocheck) {
			lc_ak_selftest();
			LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ASCON_KECCAK);
		}

		if (keylen != 32)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_KECCAK_256_IV;

		/* Add the taglen to fifth byte in the IV */
		state_mem[0] |= (uint64_t)(ascon->taglen << (8 * 3));

		ascon->keylen = 32;

		break;

	default:
		return 0;
	}

	return 1;
}

static int lc_ak_alloc_internal(const struct lc_hash *hash, uint8_t taglen,
				struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	struct lc_ascon_cryptor *ascon;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_ASCON_ALIGNMENT,
			       LC_AK_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_ASCON_SET_CTX(tmp, hash);

	ascon = tmp->aead_state;
	ascon->statesize = LC_SHA3_STATE_SIZE;
	ascon->taglen = taglen;

	*ctx = tmp;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_ak_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	return lc_ak_alloc_internal(hash, 16, ctx);
}

LC_INTERFACE_FUNCTION(int, lc_ak_alloc_taglen, const struct lc_hash *hash,
		      uint8_t taglen, struct lc_aead_ctx **ctx)
{
	return lc_ak_alloc_internal(hash, taglen, ctx);
}
