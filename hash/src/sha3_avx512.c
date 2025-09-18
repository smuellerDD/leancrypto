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

#include "asm/AVX512/KeccakP-1600-SnP.h"

#include "compare.h"
#include "ext_headers_x86.h"
#include "keccak_asm_glue.h"
#include "sha3_avx512.h"
#include "sha3_selftest.h"
#include "visibility.h"

static int sha3_224_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	sha3_224_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int sha3_224_avx512_init(void *_state)
{
	sha3_224_selftest_common(lc_sha3_224_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_224_avx512_init_nocheck(_state);
}

static int sha3_256_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	sha3_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int sha3_256_avx512_init(void *_state)
{
	sha3_256_selftest_common(lc_sha3_256_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_256_avx512_init_nocheck(_state);
}

static int sha3_384_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	sha3_384_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int sha3_384_avx512_init(void *_state)
{
	sha3_384_selftest_common(lc_sha3_384_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_384_avx512_init_nocheck(_state);
}

static int sha3_512_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	sha3_512_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int sha3_512_avx512_init(void *_state)
{
	sha3_512_selftest_common(lc_sha3_512_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHA3);

	return sha3_512_avx512_init_nocheck(_state);
}

static int shake_128_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	shake_128_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int shake_128_avx512_init(void *_state)
{
	shake128_selftest_common(lc_shake128_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_128_avx512_init_nocheck(_state);
}

static int shake_256_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	shake_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int shake_256_avx512_init(void *_state)
{
	shake256_selftest_common(lc_shake256_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_256_avx512_init_nocheck(_state);
}

static int shake_512_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	shake_512_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int shake_512_avx512_init(void *_state)
{
	shake512_selftest_common(lc_shake512_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SHAKE);

	return shake_512_avx512_init_nocheck(_state);
}

static int cshake_128_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	cshake_128_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int cshake_128_avx512_init(void *_state)
{
	cshake128_selftest_common(lc_cshake128_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_128_avx512_init_nocheck(_state);
}

static int cshake_256_avx512_init_nocheck(void *_state)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	cshake_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
#pragma GCC diagnostic pop

	return 0;
}

static int cshake_256_avx512_init(void *_state)
{
	cshake256_selftest_common(lc_cshake256_avx512);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_CSHAKE);

	return cshake_256_avx512_init_nocheck(_state);
}

static void keccak_avx512_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	LC_FPU_ENABLE;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	keccak_asm_absorb(_state, in, inlen, KeccakP1600_AVX512_AddBytes,
			  KeccakP1600_AVX512_Permute_24rounds,
			  KeccakF1600_AVX512_FastLoop_Absorb);
#pragma GCC diagnostic pop
	LC_FPU_DISABLE;
}

static void keccak_avx512_squeeze(void *_state, uint8_t *digest)
{
	LC_FPU_ENABLE;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	/* Handle SYSV_ABI */
	keccak_asm_squeeze(_state, digest, KeccakP1600_AVX512_AddByte,
			   KeccakP1600_AVX512_Permute_24rounds,
			   KeccakP1600_AVX512_ExtractBytes);
#pragma GCC diagnostic pop
	LC_FPU_DISABLE;
}

static void keccak_avx512_permutation(void *state, unsigned int rounds)
{
	(void)rounds;

	LC_FPU_ENABLE;
	KeccakP1600_AVX512_Permute_24rounds(state);
	LC_FPU_DISABLE;
}

static void keccak_avx512_add_bytes(void *state, const uint8_t *data,
				    size_t offset, size_t length)
{
	LC_FPU_ENABLE;
	KeccakP1600_AVX512_AddBytes(state, data, offset, length);
	LC_FPU_DISABLE;
}

static void keccak_avx512_extract_bytes(const void *state, uint8_t *data,
					size_t offset, size_t length)
{
	LC_FPU_ENABLE;
	KeccakP1600_AVX512_ExtractBytes(state, data, offset, length);
	LC_FPU_DISABLE;
}

static void keccak_avx512_newstate(void *state, const uint8_t *data,
				   size_t offset, size_t length)
{
	/*
	 * Due to the use of registers where the rate does not fit in, we need
	 * to do the following schema.
	 */
	uint8_t tmp[200];

	keccak_avx512_extract_bytes(state, tmp, offset, length);
	keccak_avx512_add_bytes(state, data, offset, length);

	/* The following XOR masks out the existing data. */
	keccak_avx512_add_bytes(state, tmp, offset, length);

	lc_memset_secure(tmp, 0, length);
}

static const struct lc_hash _sha3_224_avx512 = {
	.init = sha3_224_avx512_init,
	.init_nocheck = sha3_224_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_224_avx512) = &_sha3_224_avx512;

static const struct lc_hash _sha3_256_avx512 = {
	.init = sha3_256_avx512_init,
	.init_nocheck = sha3_256_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_256_avx512) = &_sha3_256_avx512;

static const struct lc_hash _sha3_384_avx512 = {
	.init = sha3_384_avx512_init,
	.init_nocheck = sha3_384_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_384_avx512) = &_sha3_384_avx512;

static const struct lc_hash _sha3_512_avx512 = {
	.init = sha3_512_avx512_init,
	.init_nocheck = sha3_512_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_512_avx512) = &_sha3_512_avx512;

static const struct lc_hash _shake128_avx512 = {
	.init = shake_128_avx512_init,
	.init_nocheck = shake_128_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake128_avx512) = &_shake128_avx512;

static const struct lc_hash _shake256_avx512 = {
	.init = shake_256_avx512_init,
	.init_nocheck = shake_256_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake256_avx512) = &_shake256_avx512;

static const struct lc_hash _shake512_avx512 = {
	.init = shake_512_avx512_init,
	.init_nocheck = shake_512_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake512_avx512) = &_shake512_avx512;

static const struct lc_hash _cshake128_avx512 = {
	.init = cshake_128_avx512_init,
	.init_nocheck = cshake_128_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_avx512) = &_cshake128_avx512;

static const struct lc_hash _cshake256_avx512 = {
	.init = cshake_256_avx512_init,
	.init_nocheck = cshake_256_avx512_init_nocheck,
	.update = keccak_avx512_absorb,
	.final = keccak_avx512_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx512_permutation,
	.sponge_add_bytes = keccak_avx512_add_bytes,
	.sponge_extract_bytes = keccak_avx512_extract_bytes,
	.sponge_newstate = keccak_avx512_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_avx512) = &_cshake256_avx512;
