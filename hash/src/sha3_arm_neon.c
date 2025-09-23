/*
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

#include "KeccakP-1600-SnP.h"

#include "compare.h"
#include "ext_headers_arm.h"
#include "keccak_asm_glue.h"
#include "lc_status.h"
#include "sha3_arm_neon.h"
#include "sha3_selftest.h"
#include "visibility.h"

static int sha3_224_arm_neon_init_nocheck(void *_state)
{
	sha3_224_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int sha3_224_arm_neon_init(void *_state)
{
	sha3_224_selftest_common(lc_sha3_224_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_224_arm_neon_init_nocheck(_state);
}

static int sha3_256_arm_neon_init_nocheck(void *_state)
{
	sha3_256_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int sha3_256_arm_neon_init(void *_state)
{
	sha3_256_selftest_common(lc_sha3_256_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_256_arm_neon_init_nocheck(_state);
}

static int sha3_384_arm_neon_init_nocheck(void *_state)
{
	sha3_384_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int sha3_384_arm_neon_init(void *_state)
{
	sha3_384_selftest_common(lc_sha3_384_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_384_arm_neon_init_nocheck(_state);
}

static int sha3_512_arm_neon_init_nocheck(void *_state)
{
	sha3_512_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int sha3_512_arm_neon_init(void *_state)
{
	sha3_512_selftest_common(lc_sha3_512_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_512_arm_neon_init_nocheck(_state);
}

static int shake_128_arm_neon_init_nocheck(void *_state)
{
	shake_128_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int shake_128_arm_neon_init(void *_state)
{
	shake128_selftest_common(lc_shake128_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_128_arm_neon_init_nocheck(_state);
}

static int shake_256_arm_neon_init_nocheck(void *_state)
{
	shake_256_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int shake_256_arm_neon_init(void *_state)
{
	shake256_selftest_common(lc_shake256_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_256_arm_neon_init_nocheck(_state);
}

static int shake_512_arm_neon_init_nocheck(void *_state)
{
	shake_512_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int shake_512_arm_neon_init(void *_state)
{
	shake512_selftest_common(lc_shake512_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE512);

	return shake_512_arm_neon_init_nocheck(_state);
}

static int cshake_128_arm_neon_init_nocheck(void *_state)
{
	cshake_128_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int cshake_128_arm_neon_init(void *_state)
{
	cshake128_selftest_common(lc_cshake128_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_128_arm_neon_init_nocheck(_state);
}

static int cshake_256_arm_neon_init_nocheck(void *_state)
{
	cshake_256_asm_init(_state, NULL, KeccakP1600_Initialize);

	return 0;
}

static int cshake_256_arm_neon_init(void *_state)
{
	cshake256_selftest_common(lc_cshake256_arm_neon);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_256_arm_neon_init_nocheck(_state);
}

static void keccak_arm_neon_absorb(void *_state, const uint8_t *in,
				   size_t inlen)
{
	LC_NEON_ENABLE;
	keccak_asm_absorb(_state, in, inlen, KeccakP1600_AddBytes,
			  KeccakP1600_Permute_24rounds, NULL);
	LC_NEON_DISABLE;
}

static void keccak_arm_neon_squeeze(void *_state, uint8_t *digest)
{
	LC_NEON_ENABLE;
	keccak_asm_squeeze(_state, digest, KeccakP1600_AddByte,
			   KeccakP1600_Permute_24rounds,
			   KeccakP1600_ExtractBytes);
	LC_NEON_DISABLE;
}

static void keccak_arm_neon_permutation(void *state, unsigned int rounds)
{
	(void)rounds;

	LC_NEON_ENABLE;
	KeccakP1600_Permute_24rounds((uint64_t *)state);
	LC_NEON_DISABLE;
}

static void keccak_arm_neon_add_bytes(void *state, const uint8_t *data,
				      size_t offset, size_t length)
{
	LC_NEON_ENABLE;
	KeccakP1600_AddBytes(state, data, offset, length);
	LC_NEON_DISABLE;
}

static void keccak_arm_neon_extract_bytes(const void *state, uint8_t *data,
					  size_t offset, size_t length)
{
	LC_NEON_ENABLE;
	KeccakP1600_ExtractBytes(state, data, offset, length);
	LC_NEON_DISABLE;
}

static void keccak_arm_neon_newstate(void *state, const uint8_t *data,
				     size_t offset, size_t length)
{
	memcpy((uint8_t *)state + offset, data, length);
}

static const struct lc_hash _sha3_224_arm_neon = {
	.init = sha3_224_arm_neon_init,
	.init_nocheck = sha3_224_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_224_arm_neon) = &_sha3_224_arm_neon;

static const struct lc_hash _sha3_256_arm_neon = {
	.init = sha3_256_arm_neon_init,
	.init_nocheck = sha3_256_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_256_arm_neon) = &_sha3_256_arm_neon;

static const struct lc_hash _sha3_384_arm_neon = {
	.init = sha3_384_arm_neon_init,
	.init_nocheck = sha3_384_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_384_arm_neon) = &_sha3_384_arm_neon;

static const struct lc_hash _sha3_512_arm_neon = {
	.init = sha3_512_arm_neon_init,
	.init_nocheck = sha3_512_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
	.algorithm_type = LC_ALG_STATUS_SHA3
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_512_arm_neon) = &_sha3_512_arm_neon;

static const struct lc_hash _shake128_arm_neon = {
	.init = shake_128_arm_neon_init,
	.init_nocheck = shake_128_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake128_arm_neon) = &_shake128_arm_neon;

static const struct lc_hash _shake256_arm_neon = {
	.init = shake_256_arm_neon_init,
	.init_nocheck = shake_256_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake256_arm_neon) = &_shake256_arm_neon;

static const struct lc_hash _shake512_arm_neon = {
	.init = shake_512_arm_neon_init,
	.init_nocheck = shake_512_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
	.algorithm_type = LC_ALG_STATUS_SHAKE512
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake512_arm_neon) = &_shake512_arm_neon;

static const struct lc_hash _cshake128_arm_neon = {
	.init = cshake_128_arm_neon_init,
	.init_nocheck = cshake_128_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
	.algorithm_type = LC_ALG_STATUS_CSHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_arm_neon) = &_cshake128_arm_neon;

static const struct lc_hash _cshake256_arm_neon = {
	.init = cshake_256_arm_neon_init,
	.init_nocheck = cshake_256_arm_neon_init_nocheck,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_neon_permutation,
	.sponge_add_bytes = keccak_arm_neon_add_bytes,
	.sponge_extract_bytes = keccak_arm_neon_extract_bytes,
	.sponge_newstate = keccak_arm_neon_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
	.algorithm_type = LC_ALG_STATUS_CSHAKE
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_arm_neon) = &_cshake256_arm_neon;
