/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_x86.h"
#include "keccack_asm_glue.h"
#include "sha3_avx512.h"
#include "sha3_selftest.h"
#include "visibility.h"

static void sha3_224_avx512_init(void *_state)
{
	static int tested = 0;

	sha3_224_selftest_common(lc_sha3_224_avx512, &tested,
				 "SHA3-224 AVX512");
	sha3_224_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void sha3_256_avx512_init(void *_state)
{
	static int tested = 0;

	sha3_256_selftest_common(lc_sha3_256_avx512, &tested,
				 "SHA3-256 AVX512");
	sha3_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void sha3_384_avx512_init(void *_state)
{
	static int tested = 0;

	sha3_384_selftest_common(lc_sha3_384_avx512, &tested,
				 "SHA3-384 AVX512");
	sha3_384_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void sha3_512_avx512_init(void *_state)
{
	static int tested = 0;

	sha3_512_selftest_common(lc_sha3_512_avx512, &tested,
				 "SHA3-512 AVX512");
	sha3_512_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void shake_128_avx512_init(void *_state)
{
	static int tested = 0;

	shake128_selftest_common(lc_shake128_avx512, &tested,
				 "SHAKE128 AVX512");
	shake_128_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void shake_256_avx512_init(void *_state)
{
	static int tested = 0;

	shake256_selftest_common(lc_shake256_avx512, &tested,
				 "SHAKE256 AVX512");
	shake_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void cshake_128_avx512_init(void *_state)
{
	static int tested = 0;

	cshake128_selftest_common(lc_cshake128_avx512, &tested,
				  "cSHAKE128 AVX512");
	cshake_128_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void cshake_256_avx512_init(void *_state)
{
	static int tested = 0;

	cshake256_selftest_common(lc_cshake256_avx512, &tested,
				  "cSHAKE256 AVX512");
	cshake_256_asm_init(_state, NULL, KeccakP1600_AVX512_Initialize);
}

static void keccak_avx512_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	LC_FPU_ENABLE;
	keccak_asm_absorb(_state, in, inlen,
			  KeccakP1600_AVX512_AddBytes,
			  KeccakP1600_AVX512_Permute_24rounds,
			  KeccakF1600_AVX512_FastLoop_Absorb);
	LC_FPU_DISABLE;
}

static void keccak_avx512_squeeze(void *_state, uint8_t *digest)
{
	LC_FPU_ENABLE;
	keccak_asm_squeeze(_state, digest,
			   KeccakP1600_AVX512_AddByte,
			   KeccakP1600_AVX512_Permute_24rounds,
			   KeccakP1600_AVX512_ExtractBytes);
	LC_FPU_DISABLE;
}

static const struct lc_hash _sha3_224_avx512 = {
	.init		= sha3_224_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_224_digestsize,
	.blocksize	= LC_SHA3_224_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_sha3_224_avx512) = &_sha3_224_avx512;

static const struct lc_hash _sha3_256_avx512 = {
	.init		= sha3_256_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_256_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_sha3_256_avx512) = &_sha3_256_avx512;

static const struct lc_hash _sha3_384_avx512 = {
	.init		= sha3_384_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_384_digestsize,
	.blocksize	= LC_SHA3_384_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_sha3_384_avx512) = &_sha3_384_avx512;

static const struct lc_hash _sha3_512_avx512 = {
	.init		= sha3_512_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_512_digestsize,
	.blocksize	= LC_SHA3_512_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_sha3_512_avx512) = &_sha3_512_avx512;

static const struct lc_hash _shake128_avx512 = {
	.init		= shake_128_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHAKE_128_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_shake128_avx512) = &_shake128_avx512;

static const struct lc_hash _shake256_avx512 = {
	.init		= shake_256_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_shake256_avx512) = &_shake256_avx512;

static const struct lc_hash _cshake128_avx512 = {
	.init		= cshake_128_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHAKE_128_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_cshake128_avx512) = &_cshake128_avx512;

static const struct lc_hash _cshake256_avx512 = {
	.init		= cshake_256_avx512_init,
	.update		= keccak_avx512_absorb,
	.final		= keccak_avx512_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(
const struct lc_hash *, lc_cshake256_avx512) = &_cshake256_avx512;
