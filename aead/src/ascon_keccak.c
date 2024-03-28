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
#include "compare.h"
#include "lc_ascon_keccak.h"
#include "lc_memory_support.h"
#include "lc_sha3.h"
#include "visibility.h"

/*
 * Ascon with Keccak permutation
 *
 * Algorithms with 256 bit security strength based on the fact that the
 * capacity is 512 bits or larger.
 *
 * The Ascon-Keccak algorithm is defined with the reference to
 * <keysize>/<Keccak security level (half of capacity)>.
 *
 *                       ---- Bit size of ----- Rounds
 *                       Key Nonce Tag DataBlock pa pb
 *                                     Rate
 * Ascon-Keccak 512/512  512 128   128  576      24 24
 * Ascon-Keccak 256/512  256 128   128  576      24 24
 * Ascon-Keccak 256/256  256 128   128 1088      24 24
 *
 * Note, the tag is allowed also to be larger, up to the size of the capacity.
 */
#define LC_AEAD_ASCON_KECCAK_512_512_IV 0x0200024000180018
#define LC_AEAD_ASCON_KECCAK_256_512_IV 0x0100024000180018
#define LC_AEAD_ASCON_KECCAK_256_256_IV 0x0100044000180018

/*
 * Some considerations on the self test: The different lc_sponge* APIs return
 * error indicators which are important to observe, because those APIs refuse
 * to operate when there is no Sponge implementation provided by the selected
 * hash instance. As the entire AEAD code does not check for these errors,
 * it could lead to the case that plaintext is leaked if (a) an encryption
 * in place is performed, and (b) the used hash implementation does not
 * have a Sponge implementation. This issue is alleviated by the self test
 * which would only return success if all Sponge implementations are provided.
 */
static void lc_ak_selftest(int *tested, const char *impl)
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
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	};
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	};
	static const uint8_t exp_ct[] = {
		0x98, 0xe1, 0x5c, 0xd7, 0x81, 0xd9, 0x90, 0x9a, 0x63, 0x87,
		0x6f, 0xf8, 0x2a, 0x74, 0x38, 0xa2, 0xc0, 0xbf, 0x1e, 0xe4,
		0x82, 0x50, 0xc0, 0x1d, 0xea, 0x17, 0x30, 0xec, 0xb7, 0xd2,
		0x36, 0xbc, 0x83, 0xd8, 0x8d, 0xa1, 0xf1, 0x7e, 0xe9, 0x6d,
		0x53, 0xb6, 0x48, 0xef, 0x43, 0x85, 0xea, 0x72, 0x6f, 0x51,
		0x3d, 0xb2, 0x35, 0x5d, 0x48, 0x44, 0x77, 0xb7, 0x60, 0x27,
		0x53, 0x9a, 0x74, 0x8e
	};
	static const uint8_t exp_tag[] = {
		0x79, 0xd0, 0x7e, 0x7a, 0xb6, 0x79, 0x7d, 0x14,
		0x0e, 0x6b, 0xe6, 0xe9, 0x64, 0xdb, 0x59, 0x14,
	};
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	char status[35];

	LC_SELFTEST_RUN(tested);

	LC_AK_CTX_ON_STACK(ak, lc_sha3_256);

	assert(!lc_aead_setkey(ak, key, sizeof(key), iv, sizeof(iv)));
	assert(!lc_aead_encrypt(ak, in, act_ct, sizeof(in), in, sizeof(in),
				act_tag, sizeof(act_tag)));
	snprintf(status, sizeof(status), "%s encrypt", impl);
	lc_compare_selftest(act_ct, exp_ct, sizeof(exp_ct), status);
	lc_compare_selftest(act_tag, exp_tag, sizeof(exp_tag), status);
	lc_aead_zero(ak);

	assert(!lc_aead_setkey(ak, key, sizeof(key), iv, sizeof(iv)));
	assert(!lc_aead_decrypt(ak, act_ct, act_ct, sizeof(act_ct), in,
				sizeof(in), act_tag, sizeof(act_tag)));

	snprintf(status, sizeof(status), "%s decrypt", impl);
	lc_compare_selftest(act_ct, in, sizeof(in), status);
	lc_aead_zero(ak);
}

int lc_ak_setiv(struct lc_ascon_cryptor *ascon, size_t keylen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	static int tested = 0;

	lc_ak_selftest(&tested, "Asacon Keccak AEAD");

	switch (hash->rate) {
	case 0x240 / 8: /* Keccak security level 512 bits */
		switch (keylen) {
		case 32:
			state_mem[0] = LC_AEAD_ASCON_KECCAK_256_512_IV;
			ascon->keylen = 32;
			break;
		case 64:
			state_mem[0] = LC_AEAD_ASCON_KECCAK_512_512_IV;
			ascon->keylen = 64;
			break;
		default:
			return -EINVAL;
		}

		break;
	case 0x440 / 8: /* Keccak security level 256 bits */
		if (keylen != 32)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_KECCAK_256_256_IV;
		ascon->keylen = 32;

		break;

	default:
		return 0;
	}

	return 1;
}

LC_INTERFACE_FUNCTION(int, lc_ak_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	struct lc_ascon_cryptor *ascon;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_ASCON_KECCAK_ALIGNMENT,
			       LC_AK_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_ASCON_SET_CTX(tmp, hash);

	ascon = tmp->aead_state;
	ascon->statesize = LC_SHA3_STATE_SIZE;

	*ctx = tmp;

	return 0;
}
