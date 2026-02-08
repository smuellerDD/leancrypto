/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "asm/riscv64/keccak_riscv64.h"

#include "compare.h"
#include "keccak_asm_glue.h"
#include "status_algorithms.h"
#include "sha3_riscv_asm.h"
#include "sha3_common.h"
#include "sha3_selftest.h"
#include "visibility.h"

static int sha3_224_riscv_asm_zbb_init_nocheck(void *_state)
{
	sha3_224_init_common(_state);

	return 0;
}

static int sha3_224_riscv_asm_zbb_init(void *_state)
{
	sha3_224_selftest_common(lc_sha3_224_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_224_riscv_asm_zbb_init_nocheck(_state);
}

static int sha3_256_riscv_asm_zbb_init_nocheck(void *_state)
{
	sha3_256_init_common(_state);

	return 0;
}

static int sha3_256_riscv_asm_zbb_init(void *_state)
{
	sha3_256_selftest_common(lc_sha3_256_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_256_riscv_asm_zbb_init_nocheck(_state);
}

static int sha3_384_riscv_asm_zbb_init_nocheck(void *_state)
{
	sha3_384_init_common(_state);

	return 0;
}

static int sha3_384_riscv_asm_zbb_init(void *_state)
{
	sha3_384_selftest_common(lc_sha3_384_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_384_riscv_asm_zbb_init_nocheck(_state);
}

static int sha3_512_riscv_asm_zbb_init_nocheck(void *_state)
{
	sha3_512_init_common(_state);

	return 0;
}

static int sha3_512_riscv_asm_zbb_init(void *_state)
{
	sha3_512_selftest_common(lc_sha3_512_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_512_riscv_asm_zbb_init_nocheck(_state);
}

static int shake_128_riscv_asm_zbb_init_nocheck(void *_state)
{
	shake_128_init_common(_state);

	return 0;
}

static int shake_128_riscv_asm_zbb_init(void *_state)
{
	shake128_selftest_common(lc_shake128_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_128_riscv_asm_zbb_init_nocheck(_state);
}

static int shake_256_riscv_asm_zbb_init_nocheck(void *_state)
{
	shake_256_init_common(_state);

	return 0;
}

static int shake_256_riscv_asm_zbb_init(void *_state)
{
	shake256_selftest_common(lc_shake256_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_256_riscv_asm_zbb_init_nocheck(_state);
}

static int shake_512_riscv_asm_zbb_init_nocheck(void *_state)
{
	shake_512_init_common(_state);

	return 0;
}

static int shake_512_riscv_asm_zbb_init(void *_state)
{
	shake512_selftest_common(lc_shake512_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE512);

	return shake_512_riscv_asm_zbb_init_nocheck(_state);
}

static int cshake_128_riscv_asm_zbb_init_nocheck(void *_state)
{
	cshake_128_init_common(_state);

	return 0;
}

static int cshake_128_riscv_asm_zbb_init(void *_state)
{
	cshake128_selftest_common(lc_cshake128_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_128_riscv_asm_zbb_init_nocheck(_state);
}

static int cshake_256_riscv_asm_zbb_init_nocheck(void *_state)
{
	cshake_256_init_common(_state);

	return 0;
}

static int cshake_256_riscv_asm_zbb_init(void *_state)
{
	cshake256_selftest_common(lc_cshake256_riscv_asm_zbb);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_256_riscv_asm_zbb_init_nocheck(_state);
}

static inline void keccakf1600_add_byte(void *state, const unsigned char byte,
					unsigned int offset)
{
	((unsigned char *)state)[offset] ^= (byte);
}

static inline void keccakf1600_add_bytes(void *state, const unsigned char *data,
					 size_t offset, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		keccakf1600_add_byte(state, data[i],
				     (unsigned int)(offset + i));
}

static inline void keccakf1600_permute(void *state, unsigned int rounds)
{
	uint32_t *lanes = state;

	(void)rounds;
	KeccakF1600_StatePermute_RV64ZBB(lanes);
}

static inline void keccakf1600_extract_bytes(const void *state,
					     unsigned char *digest,
					     size_t offset, size_t length)
{
	size_t i, word, byte;
	const uint32_t *lanes = state;

	for (i = offset; i < length + offset; i++, digest++) {
		word = i / sizeof(lanes[0]);
		byte = (i % sizeof(lanes[0])) << 3;

		*digest = (unsigned char)(lanes[word] >> byte);
	}
}

static void keccak_riscv_asm_zbb_absorb(void *_state, const uint8_t *in,
					size_t inlen)
{
	keccak_asm_absorb(_state, in, inlen, keccakf1600_add_bytes,
			  KeccakF1600_StatePermute_RV64ZBB, NULL);
}

static void keccak_riscv_asm_zbb_squeeze(void *_state, uint8_t *digest)
{
	keccak_asm_squeeze(_state, digest, keccakf1600_add_byte,
			   KeccakF1600_StatePermute_RV64ZBB,
			   keccakf1600_extract_bytes);
}

static void keccak_riscv_add_bytes(void *state, const unsigned char *data,
				   size_t offset, size_t length)
{
	keccakf1600_add_bytes(state, data, offset, length);
}

static void keccak_riscv_extract_bytes(const void *state, unsigned char *data,
				       size_t offset, size_t length)
{
	keccakf1600_extract_bytes(state, data, offset, length);
}

static void keccak_riscv_newstate(void *state, const uint8_t *data,
				  size_t offset, size_t length)
{
	memcpy((uint8_t *)state + offset, data, length);
}

static const struct lc_hash _sha3_224_riscv_asm_zbb = {
	.init = sha3_224_riscv_asm_zbb_init,
	.init_nocheck = sha3_224_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_224_riscv_asm_zbb) = &_sha3_224_riscv_asm_zbb;

static const struct lc_hash _sha3_256_riscv_asm_zbb = {
	.init = sha3_256_riscv_asm_zbb_init,
	.init_nocheck = sha3_256_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_256_riscv_asm_zbb) = &_sha3_256_riscv_asm_zbb;

static const struct lc_hash _sha3_384_riscv_asm_zbb = {
	.init = sha3_384_riscv_asm_zbb_init,
	.init_nocheck = sha3_384_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_384_riscv_asm_zbb) = &_sha3_384_riscv_asm_zbb;

static const struct lc_hash _sha3_512_riscv_asm_zbb = {
	.init = sha3_512_riscv_asm_zbb_init,
	.init_nocheck = sha3_512_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_512_riscv_asm_zbb) = &_sha3_512_riscv_asm_zbb;

static const struct lc_hash _shake128_riscv_asm_zbb = {
	.init = shake_128_riscv_asm_zbb_init,
	.init_nocheck = shake_128_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake128_riscv_asm_zbb) = &_shake128_riscv_asm_zbb;

static const struct lc_hash _shake256_riscv_asm_zbb = {
	.init = shake_256_riscv_asm_zbb_init,
	.init_nocheck = shake_256_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake256_riscv_asm_zbb) = &_shake256_riscv_asm_zbb;

static const struct lc_hash _shake512_riscv_asm_zbb = {
	.init = shake_512_riscv_asm_zbb_init,
	.init_nocheck = shake_512_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE512
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake512_riscv_asm_zbb) = &_shake512_riscv_asm_zbb;

static const struct lc_hash _cshake128_riscv_asm_zbb = {
	.init = cshake_128_riscv_asm_zbb_init,
	.init_nocheck = cshake_128_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
	.algorithm_type = LC_ALG_STATUS_CSHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_riscv_asm_zbb) = &_cshake128_riscv_asm_zbb;

static const struct lc_hash _cshake256_riscv_asm_zbb = {
	.init = cshake_256_riscv_asm_zbb_init,
	.init_nocheck = cshake_256_riscv_asm_zbb_init_nocheck,
	.update = keccak_riscv_asm_zbb_absorb,
	.final = keccak_riscv_asm_zbb_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccakf1600_permute,
	.sponge_add_bytes = keccak_riscv_add_bytes,
	.sponge_extract_bytes = keccak_riscv_extract_bytes,
	.sponge_newstate = keccak_riscv_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_CSHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_riscv_asm_zbb) = &_cshake256_riscv_asm_zbb;
