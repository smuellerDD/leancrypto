/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "asm/ARMv8A/KeccakP-1600-armv8a-ce.h"

#include "bitshift.h"
#include "conv_be_le.h"
#include "ext_headers.h"
#include "ext_headers_arm.h"
#include "lc_sha3.h"
#include "sha3_arm_asm.h"
#include "sha3_common.h"
#include "sha3_selftest.h"
#include "sponge_common.h"
#include "visibility.h"
#include "xor.h"

/* ARMv6 and ARMv7 are not detectable by meson, thus apply ifdef here */
#ifndef __ARM_ARCH_6__

static void sha3_224_arm_asm_init(void *_state)
{
	struct lc_sha3_224_state *ctx = _state;
	static int tested = 0;

	sha3_224_selftest_common(lc_sha3_224_arm_asm, &tested,
				 "SHA3-224 ARM ASM");
	sha3_224_init_common(_state);
	sha3_state_init(ctx->state);
}

static void sha3_256_arm_asm_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	sha3_256_selftest_common(lc_sha3_256_arm_asm, &tested,
				 "SHA3-256 ARM ASM");
	sha3_256_init_common(_state);
	sha3_state_init(ctx->state);
}

static void sha3_384_arm_asm_init(void *_state)
{
	struct lc_sha3_384_state *ctx = _state;
	static int tested = 0;

	sha3_384_selftest_common(lc_sha3_384_arm_asm, &tested,
				 "SHA3-384 ARM ASM");
	sha3_384_init_common(_state);
	sha3_state_init(ctx->state);
}

static void sha3_512_arm_asm_init(void *_state)
{
	struct lc_sha3_512_state *ctx = _state;
	static int tested = 0;

	sha3_512_selftest_common(lc_sha3_512_arm_asm, &tested,
				 "SHA3-512 ARM ASM");
	sha3_512_init_common(_state);
	sha3_state_init(ctx->state);
}

static void shake_128_arm_asm_init(void *_state)
{
	struct lc_shake_128_state *ctx = _state;
	static int tested = 0;

	shake128_selftest_common(lc_shake128_arm_asm, &tested,
				 "SHAKE128 ARM ASM");
	shake_128_init_common(_state);
	sha3_state_init(ctx->state);
}

static void shake_256_arm_asm_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	shake256_selftest_common(lc_shake256_arm_asm, &tested,
				 "SHAKE256 ARM ASM");
	shake_256_init_common(_state);
	sha3_state_init(ctx->state);
}

static void cshake_128_arm_asm_init(void *_state)
{
	struct lc_shake_128_state *ctx = _state;
	static int tested = 0;

	cshake128_selftest_common(lc_cshake128_arm_asm, &tested,
				  "cSHAKE128 ARM ASM");
	cshake_128_init_common(_state);
	sha3_state_init(ctx->state);
}

static void cshake_256_arm_asm_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	cshake256_selftest_common(lc_cshake256_arm_asm, &tested,
				  "cSHAKE256 ARM ASM");
	cshake_256_init_common(_state);
	sha3_state_init(ctx->state);
}

static void keccak_arm_asm_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	keccak_arm_asm_absorb_internal(_state, in, inlen,
				       lc_keccak_absorb_arm_asm,
				       lc_keccakf1600_arm_asm);
}
static void keccak_arm_asm_squeeze(void *_state, uint8_t *digest)
{
	keccak_arm_asm_squeeze_internal(_state, digest,
					lc_keccak_squeeze_arm_asm,
					lc_keccakf1600_arm_asm);
}

static void keccak_arm_asm_permutation(void *state, unsigned int rounds)
{
	(void)rounds;

	LC_NEON_ENABLE;
	lc_keccakf1600_arm_asm((uint64_t *)state);
	LC_NEON_DISABLE;
}

static void keccak_arm_asm_add_bytes(void *state, const unsigned char *data,
				     unsigned int offset, unsigned int length)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + offset, data, length);
}

static void keccak_arm_asm_extract_bytes(const void *state, unsigned char *data,
					 size_t offset, size_t length)
{
	sponge_extract_bytes(state, data, offset, length,
			     LC_SHA3_STATE_WORDS, le_bswap64, le_bswap32,
			     le64_to_ptr, le32_to_ptr);
}

static void keccak_arm_asm_newstate(void *state, const uint8_t *data,
				    size_t offset, size_t length)
{
	memcpy((uint8_t *)state + offset, data, length);
}

static const struct lc_hash _sha3_224_arm_asm = {
	.init = sha3_224_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_224_arm_asm) = &_sha3_224_arm_asm;

static const struct lc_hash _sha3_256_arm_asm = {
	.init = sha3_256_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_256_arm_asm) = &_sha3_256_arm_asm;

static const struct lc_hash _sha3_384_arm_asm = {
	.init = sha3_384_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_384_arm_asm) = &_sha3_384_arm_asm;

static const struct lc_hash _sha3_512_arm_asm = {
	.init = sha3_512_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha3_512_arm_asm) = &_sha3_512_arm_asm;

static const struct lc_hash _shake128_arm_asm = {
	.init = shake_128_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake128_arm_asm) = &_shake128_arm_asm;

static const struct lc_hash _shake256_arm_asm = {
	.init = shake_256_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_shake256_arm_asm) = &_shake256_arm_asm;

static const struct lc_hash _cshake128_arm_asm = {
	.init = cshake_128_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake128_arm_asm) = &_cshake128_arm_asm;

static const struct lc_hash _cshake256_arm_asm = {
	.init = cshake_256_arm_asm_init,
	.update = keccak_arm_asm_absorb,
	.final = keccak_arm_asm_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.sponge_permutation = keccak_arm_asm_permutation,
	.sponge_add_bytes = keccak_arm_asm_add_bytes,
	.sponge_extract_bytes = keccak_arm_asm_extract_bytes,
	.sponge_newstate = keccak_arm_asm_newstate,
	.sponge_rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_cshake256_arm_asm) = &_cshake256_arm_asm;

#else /* __ARM_ARCH_6__ */

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_224_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_256_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_384_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_512_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake128_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake256_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake128_arm_asm) = NULL;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake256_arm_asm) = NULL;

#endif /* __ARM_ARCH_6__ */
