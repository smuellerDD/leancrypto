/*
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

#include "asm/AVX2/KeccakP-1600-SnP.h"

#include "ext_headers_x86.h"
#include "keccak_asm_glue.h"
#include "sha3_avx2.h"
#include "sha3_selftest.h"
#include "visibility.h"

static void sha3_224_avx2_init(void *_state)
{
	static int tested = 0;

	sha3_224_selftest_common(lc_sha3_224_avx2, &tested, "SHA3-224 AVX2");
	sha3_224_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void sha3_256_avx2_init(void *_state)
{
	static int tested = 0;

	sha3_256_selftest_common(lc_sha3_256_avx2, &tested, "SHA3-256 AVX2");
	sha3_256_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void sha3_384_avx2_init(void *_state)
{
	static int tested = 0;

	sha3_384_selftest_common(lc_sha3_384_avx2, &tested, "SHA3-384 AVX2");
	sha3_384_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void sha3_512_avx2_init(void *_state)
{
	static int tested = 0;

	sha3_512_selftest_common(lc_sha3_512_avx2, &tested, "SHA3-512 AVX2");
	sha3_512_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void shake_128_avx2_init(void *_state)
{
	static int tested = 0;

	shake128_selftest_common(lc_shake128_avx2, &tested, "SHAKE128 AVX2");
	shake_128_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void shake_256_avx2_init(void *_state)
{
	static int tested = 0;

	shake256_selftest_common(lc_shake256_avx2, &tested, "SHAKE256 AVX2");
	shake_256_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void cshake_128_avx2_init(void *_state)
{
	static int tested = 0;

	cshake128_selftest_common(lc_cshake128_avx2, &tested, "cSHAKE128 AVX2");
	cshake_128_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void cshake_256_avx2_init(void *_state)
{
	static int tested = 0;

	cshake256_selftest_common(lc_cshake256_avx2, &tested, "cSHAKE256 AVX2");
	cshake_256_asm_init(_state, NULL, KeccakP1600_AVX2_Initialize);
}

static void keccak_avx2_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	LC_FPU_ENABLE;
	keccak_asm_absorb(_state, in, inlen, KeccakP1600_AVX2_AddBytes,
			  KeccakP1600_AVX2_Permute_24rounds,
			  KeccakF1600_AVX2_FastLoop_Absorb);
	LC_FPU_DISABLE;
}

static void keccak_avx2_squeeze(void *_state, uint8_t *digest)
{
	LC_FPU_ENABLE;
	keccak_asm_squeeze(_state, digest, KeccakP1600_AVX2_AddByte,
			   KeccakP1600_AVX2_Permute_24rounds,
			   KeccakP1600_AVX2_ExtractBytes);
	LC_FPU_DISABLE;
}

static void keccak_avx2_permutation(void *state, unsigned int rounds)
{
	(void)rounds;

	LC_FPU_ENABLE;
	KeccakP1600_AVX2_Permute_24rounds(state);
	LC_FPU_DISABLE;
}

static void keccak_avx2_add_bytes(void *state, const uint8_t *data,
				  size_t offset, size_t length)
{
	LC_FPU_ENABLE;
	KeccakP1600_AVX2_AddBytes(state, data, offset, length);
	LC_FPU_DISABLE;
}

static void keccak_avx2_extract_bytes(const void *state, uint8_t *data,
				      size_t offset, size_t length)
{
	LC_FPU_ENABLE;
	KeccakP1600_AVX2_ExtractBytes(state, data, offset, length);
	LC_FPU_DISABLE;
}

static void keccak_avx2_newstate(void *state, const uint8_t *data,
				 size_t offset, size_t length)
{
	/*
	 * Due to the use of registers where the rate does not fit in, we need
	 * to do the following schema.
	 */
	uint8_t tmp[200];

	keccak_avx2_extract_bytes(state, tmp, offset, length);
	keccak_avx2_add_bytes(state, data, (unsigned int)offset,
			      (unsigned int)length);

	/* The following XOR masks out the existing data. */
	keccak_avx2_add_bytes(state, tmp, (unsigned int)offset,
			      (unsigned int)length);

	lc_memset_secure(tmp, 0, length);
}

static const struct lc_hash _sha3_224_avx2 = {
	.init = sha3_224_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_224_avx2) = &_sha3_224_avx2;

static const struct lc_hash _sha3_256_avx2 = {
	.init = sha3_256_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_256_avx2) = &_sha3_256_avx2;

static const struct lc_hash _sha3_384_avx2 = {
	.init = sha3_384_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_384_avx2) = &_sha3_384_avx2;

static const struct lc_hash _sha3_512_avx2 = {
	.init = sha3_512_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_512_avx2) = &_sha3_512_avx2;

static const struct lc_hash _shake128_avx2 = {
	.init = shake_128_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake128_avx2) = &_shake128_avx2;

static const struct lc_hash _shake256_avx2 = {
	.init = shake_256_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake256_avx2) = &_shake256_avx2;

static const struct lc_hash _cshake128_avx2 = {
	.init = cshake_128_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_avx2) = &_cshake128_avx2;

static const struct lc_hash _cshake256_avx2 = {
	.init = cshake_256_avx2_init,
	.update = keccak_avx2_absorb,
	.final = keccak_avx2_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_avx2_permutation,
	.sponge_add_bytes = keccak_avx2_add_bytes,
	.sponge_extract_bytes = keccak_avx2_extract_bytes,
	.sponge_newstate = keccak_avx2_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_avx2) = &_cshake256_avx2;
