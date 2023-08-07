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

#include "KeccakP-1600-SnP.h"

#include "ext_headers_arm.h"
#include "keccak_asm_glue.h"
#include "sha3_arm_neon.h"
#include "sha3_selftest.h"
#include "visibility.h"

static void sha3_224_arm_neon_init(void *_state)
{
	static int tested = 0;

	sha3_224_selftest_common(lc_sha3_224_arm_neon, &tested,
				 "SHA3-224 ARM Neon");
	sha3_224_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void sha3_256_arm_neon_init(void *_state)
{
	static int tested = 0;

	sha3_256_selftest_common(lc_sha3_256_arm_neon, &tested,
				 "SHA3-256 ARM Neon");
	sha3_256_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void sha3_384_arm_neon_init(void *_state)
{
	static int tested = 0;

	sha3_384_selftest_common(lc_sha3_384_arm_neon, &tested,
				 "SHA3-384 ARM Neon");
	sha3_384_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void sha3_512_arm_neon_init(void *_state)
{
	static int tested = 0;

	sha3_512_selftest_common(lc_sha3_512_arm_neon, &tested,
				 "SHA3-512 ARM Neon");
	sha3_512_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void shake_128_arm_neon_init(void *_state)
{
	static int tested = 0;

	shake128_selftest_common(lc_shake128_arm_neon, &tested,
				 "SHAKE128 ARM Neon");
	shake_128_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void shake_256_arm_neon_init(void *_state)
{
	static int tested = 0;

	shake256_selftest_common(lc_shake256_arm_neon, &tested,
				 "SHAKE256 ARM Neon");
	shake_256_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void cshake_128_arm_neon_init(void *_state)
{
	static int tested = 0;

	cshake128_selftest_common(lc_cshake128_arm_neon, &tested,
				  "cSHAKE128 ARM Neon");
	cshake_128_asm_init(_state, NULL, KeccakP1600_Initialize);
}

static void cshake_256_arm_neon_init(void *_state)
{
	static int tested = 0;

	cshake256_selftest_common(lc_cshake256_arm_neon, &tested,
				  "cSHAKE256 ARM Neon");
	cshake_256_asm_init(_state, NULL, KeccakP1600_Initialize);
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

static const struct lc_hash _sha3_224_arm_neon = {
	.init = sha3_224_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.blocksize = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_224_arm_neon) = &_sha3_224_arm_neon;

static const struct lc_hash _sha3_256_arm_neon = {
	.init = sha3_256_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.blocksize = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_256_arm_neon) = &_sha3_256_arm_neon;

static const struct lc_hash _sha3_384_arm_neon = {
	.init = sha3_384_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.blocksize = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_384_arm_neon) = &_sha3_384_arm_neon;

static const struct lc_hash _sha3_512_arm_neon = {
	.init = sha3_512_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.blocksize = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_512_arm_neon) = &_sha3_512_arm_neon;

static const struct lc_hash _shake128_arm_neon = {
	.init = shake_128_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.blocksize = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake128_arm_neon) = &_shake128_arm_neon;

static const struct lc_hash _shake256_arm_neon = {
	.init = shake_256_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.blocksize = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake256_arm_neon) = &_shake256_arm_neon;

static const struct lc_hash _cshake128_arm_neon = {
	.init = cshake_128_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.blocksize = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_arm_neon) = &_cshake128_arm_neon;

static const struct lc_hash _cshake256_arm_neon = {
	.init = cshake_256_arm_neon_init,
	.update = keccak_arm_neon_absorb,
	.final = keccak_arm_neon_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.blocksize = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_arm_neon) = &_cshake256_arm_neon;
