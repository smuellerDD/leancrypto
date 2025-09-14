/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * This file is derived from https://github.com/mko-x/SharedAES-GCM/ with the
 * following license
 */
/******************************************************************************
*
* THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
*
* This is a simple and straightforward implementation of AES-GCM authenticated
* encryption. The focus of this work was correctness & accuracy. It is written
* in straight 'C' without any particular focus upon optimization or speed. It
* should be endian (memory byte order) neutral since the few places that care
* are handled explicitly.
*
* This implementation of AES-GCM was created by Steven M. Gibson of GRC.com.
*
* It is intended for general purpose use, but was written in support of GRC's
* reference implementation of the SQRL (Secure Quick Reliable Login) client.
*
* See:    http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
*         http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/
*         gcm/gcm-revised-spec.pdf
*
* NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
* REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
*
*******************************************************************************/

#include "aes_c.h"
#include "alignment.h"
#include "bitshift_be.h"
#include "compare.h"
#include "cpufeatures.h"
#include "fips_mode.h"
#include "lc_aes_gcm.h"
#include "lc_memcmp_secure.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

#include "asm/ARMv8/gfmul_neon.h"
#include "asm/X86_64/gfmul_x86_64.h"

#define AES_BLOCKSIZE 16

static int gcm_set_key_iv_nocheck(void *state, const uint8_t *key,
				  const size_t keylen, const uint8_t *iv,
				  size_t iv_len);
static void lc_aes_gcm_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t aad[] = { FIPS140_MOD(0xff), 0x76, 0x28, 0xf6, 0x42, 0x7f,
				       0xbc, 0xef, 0x1f, 0x3b, 0x82, 0xb3,
				       0x74, 0x04, 0xe1, 0x16 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = { 0xb7, 0x06, 0x19, 0x4b, 0xb0, 0xb1,
				      0x0c, 0x47, 0x4e, 0x1b, 0x2d, 0x7b,
				      0x22, 0x78, 0x22, 0x4c };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key[] = { 0x7f, 0x71, 0x68, 0xa4, 0x06, 0xe7, 0xc1,
				       0xef, 0x0f, 0xd4, 0x7a, 0xc9, 0x22, 0xc5,
				       0xec, 0x5f, 0x65, 0x97, 0x65, 0xfb, 0x6a,
				       0xaa, 0x04, 0x8f, 0x70, 0x56, 0xf6, 0xc6,
				       0xb5, 0xd8, 0x51, 0x3d };
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = { 0xb8, 0xb5, 0xe4, 0x07, 0xad, 0xc0,
				      0xe2, 0x93, 0xe3, 0xe7, 0xe9, 0x91 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_ct[] = { 0x8f, 0xad, 0xa0, 0xb8, 0xe7, 0x77,
					  0xa8, 0x29, 0xca, 0x96, 0x80, 0xd3,
					  0xbf, 0x4f, 0x35, 0x74 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_tag[] = { 0xda, 0xca, 0x35, 0x42, 0x77,
					   0xf6, 0x33, 0x5f, 0xc8, 0xbe,
					   0xc9, 0x08, 0x86, 0xda, 0x70 };
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	static const uint8_t f[] = { 0xde, 0xad, }, p[] = { 0xaf, 0xfe };
	int ret;

	LC_SELFTEST_RUN(LC_ALG_STATUS_AES_GCM);

	LC_AES_GCM_CTX_ON_STACK(aes_gcm);

	gcm_set_key_iv_nocheck(aes_gcm->aead_state, key, sizeof(key), iv,
			       sizeof(iv));
	lc_aead_encrypt(aes_gcm, in, act_ct, sizeof(in), aad, sizeof(aad),
			act_tag, sizeof(act_tag));
	if (lc_compare_selftest(LC_ALG_STATUS_AES_GCM, act_ct, exp_ct,
				sizeof(exp_ct),
				"AES GCM AEAD encrypt ciphertext"))
		goto out;

	if (lc_compare_selftest(LC_ALG_STATUS_AES_GCM, act_tag, exp_tag, sizeof(exp_tag),
				"AES GCM AEAD encrypt tag"))
		goto out;

	lc_aead_zero(aes_gcm);

	gcm_set_key_iv_nocheck(aes_gcm->aead_state, key, sizeof(key), iv,
			       sizeof(iv));
	ret = lc_aead_decrypt(aes_gcm, act_ct, act_ct, sizeof(act_ct), aad,
			      sizeof(aad), act_tag, sizeof(act_tag));
	if (ret) {
		if (lc_compare_selftest(LC_ALG_STATUS_AES_GCM, f, p, sizeof(f),
					"AES GCM AEAD decrypt authentication"))
			goto out;
	}

out:
	lc_compare_selftest(LC_ALG_STATUS_AES_GCM, act_ct, in, sizeof(in),
			    "AES GCM AEAD decrypt");
	lc_aead_zero(aes_gcm);
}

/* Calculating the "GHASH"
 *
 * There are many ways of calculating the so-called GHASH in software, each with
 * a traditional size vs performance tradeoff.  The GHASH (Galois field hash) is
 * an intriguing construction which takes two 128-bit strings (also the cipher's
 * block size and the fundamental operation size for the system) and hashes them
 * into a third 128-bit result.
 *
 * Many implementation solutions have been worked out that use large precomputed
 * table lookups in place of more time consuming bit fiddling, and this approach
 * can be scaled easily upward or downward as needed to change the time/space
 * tradeoff. It's been studied extensively and there's a solid body of theory
 * and practice.  For example, without using any lookup tables an implementation
 * might obtain 119 cycles per byte throughput, whereas using a simple, though
 * large, key-specific 64 kbyte 8-bit lookup table the performance jumps to 13
 * cycles per byte.
 *
 * And Intel's processors have, since 2010, included an instruction which does
 * the entire 128x128->128 bit job in just several 64x64->128 bit pieces.
 *
 * Since SQRL is interactive, and only processing a few 128-bit blocks, I've
 * settled upon a relatively slower but appealing small-table compromise which
 * folds a bunch of not only time consuming but also bit twiddling into a simple
 * 16-entry table which is attributed to Victor Shoup's 1996 work while at
 * Bellcore: "On Fast and Provably Secure MessageAuthentication Based on
 * Universal Hashing."  See: http://www.shoup.net/papers/macs.pdf
 * See, also section 4.1 of the "gcm-revised-spec" cited above.
 */

/*
 *  This 16-entry table of pre-computed constants is used by the
 *  GHASH multiplier to improve over a strictly table-free but
 *  significantly slower 128x128 bit multiple within GF(2^128).
 */
LC_FIPS_RODATA_SECTION
static const uint64_t last4[16] = { 0x0000, 0x1c20, 0x3840, 0x2460,
				    0x7080, 0x6ca0, 0x48c0, 0x54e0,
				    0xe100, 0xfd20, 0xd940, 0xc560,
				    0x9180, 0x8da0, 0xa9c0, 0xb5e0 };

/**
 * GHASH
 *
 * Performs a GHASH operation on the 128-bit input vector 'x', setting
 * the 128-bit output vector to 'x' times H using our precomputed tables.
 * 'x' and 'output' are seen as elements of GCM's GF(2^128) Galois field.
 *
 * @param [in] ctx pointer to established context
 * @param [in] x pointer to 128-bit input vector
 * @param [out] output pointer to 128-bit output vector
 */
static void gcm_mult(struct lc_aes_gcm_cryptor *ctx,
		     const uint8_t x[AES_BLOCKSIZE],
		     uint8_t output[AES_BLOCKSIZE])
{
	uint64_t zh, zl;
	int i;
	uint8_t lo, hi, rem;

	/* Accelerated GCM init */
	if (ctx->gcm_ctx.gcm_gmult_accel) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		/*
		 * Aligment to 64 bit is guaranteed with struct lc_gcm_ctx
		 * where .y and .buf are properly aligned. As only .y and .buf
		 * are used with the gcm_mult function, we can ignore the
		 * cast.
		 */
		ctx->gcm_ctx.gcm_gmult_accel((uint64_t *)output,
					     ctx->gcm_ctx.HL);
#pragma GCC diagnostic pop
		return;
	}

	lo = (uint8_t)(x[15] & 0x0f);
	//hi = (uint8_t)(x[15] >> 4);

	/* Timecop: see rationale below */
	unpoison(&lo, sizeof(lo));
	zh = ctx->gcm_ctx.HH[lo];
	zl = ctx->gcm_ctx.HL[lo];

	for (i = 15; i >= 0; i--) {
		lo = (x[i] & 0x0f);
		hi = (x[i] >> 4);

		if (i != 15) {
			rem = (uint8_t)(zl & 0x0f);
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);

			/* Timecop: see rationale below */
			unpoison(&rem, sizeof(rem));
			zh ^= last4[rem] << 48;
			unpoison(&lo, sizeof(lo));
			zh ^= ctx->gcm_ctx.HH[lo];
			zl ^= ctx->gcm_ctx.HL[lo];
		}
		rem = (uint8_t)(zl & 0x0f);
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);

		/*
		 * Timecop: this table lookup implies a side channel that
		 * depends on the key. Implementing GCM without side channel
		 * is not fully achieved here. Even the OpenSSL code that
		 * implements the same concept as this one here writes in
		 * crypto/modes/gcm128.c:
		 *
		 * """
		 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
		 * never be set to 8. 8 is effectively reserved for testing purposes.
		 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
		 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
		 * whole spectrum of possible table driven implementations. Why? In
		 * non-"Shoup's" case memory access pattern is segmented in such manner,
		 * that it's trivial to see that cache timing information can reveal
		 * fair portion of intermediate hash value. Given that ciphertext is
		 * always available to attacker, it's possible for him to attempt to
		 * deduce secret parameter H and if successful, tamper with messages
		 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
		 * not as trivial, but there is no reason to believe that it's resistant
		 * to cache-timing attack. And the thing about "8-bit" implementation is
		 * that it consumes 16 (sixteen) times more memory, 4KB per individual
		 * key + 1KB shared. Well, on pros side it should be twice as fast as
		 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
		 * was observed to run ~75% faster, closer to 100% for commercial
		 * compilers... Yet "4-bit" procedure is preferred, because it's
		 * believed to provide better security-performance balance and adequate
		 * all-round performance. "All-round" refers to things like:
		 *
		 * - shorter setup time effectively improves overall timing for
		 *   handling short messages;
		 * - larger table allocation can become unbearable because of VM
		 *   subsystem penalties (for example on Windows large enough free
		 *   results in VM working set trimming, meaning that consequent
		 *   malloc would immediately incur working set expansion);
		 * - larger table has larger cache footprint, which can affect
		 *   performance of other code paths (not necessarily even from same
		 *   thread in Hyper-Threading world);
		 * """"
		 *
		 * Due to this statement, the lookup is exempted from the
		 * Timecop.
		 */
		unpoison(&rem, sizeof(rem));
		zh ^= (uint64_t)last4[rem] << 48;
		unpoison(&hi, sizeof(hi));
		zh ^= ctx->gcm_ctx.HH[hi];
		zl ^= ctx->gcm_ctx.HL[hi];
	}
	be64_to_ptr(output, zh);
	be64_to_ptr(output + 8, zl);
}

/*
 * GCM setiv
 *
 * This is called to set the AES-GCM key. It initializes the AES key
 * and populates the gcm context's pre-calculated HTables.
 *
 */
static int gcm_setkey(struct lc_aes_gcm_cryptor *ctx, const uint8_t *key,
		      const size_t keylen)
{
	uint64_t H[2];
	enum lc_cpu_features feat = lc_cpu_feature_available();
	int ret, i, j;
	uint8_t h[AES_BLOCKSIZE];

	/*
	 * If no key is provided, do not attempt to set it. This check now
	 * allows the setting of the key and IV with independent calls to
	 * gcm_set_key_iv. This is needed for the Linxu kernel support.
	 */
	CKNULL(key, 0);

	/*
	 * Timecop: the key is the sensitive information
	 *
	 * Yet, the AES C implementation is prone to side channels which is
	 * documented in aes_block.c:aes_setkey
	 */
#ifdef LC_USE_TIMECOP
	if (ctx->sym_ctx.sym != lc_aes_c)
		poison(key, keylen);
#endif

	memset(h, 0, AES_BLOCKSIZE); /* initialize the block to encrypt */

	/*
	 * encrypt the null 128-bit block to generate a key-based value
	 * which is then used to initialize our GHASH lookup tables
	 */
	CKINT(lc_sym_init(&ctx->sym_ctx));
	CKINT(lc_sym_setkey(&ctx->sym_ctx, key, keylen));
	lc_sym_encrypt(&ctx->sym_ctx, h, h, sizeof(h));

	H[0] = ptr_to_be64(h);
	H[1] = ptr_to_be64(h + 8);

	/* Accelerated GCM init */
	if (feat & LC_CPU_FEATURE_ARM_PMULL) {
		gfmul_init_armv8((uint64_t *)ctx->gcm_ctx.HL, H);
		ctx->gcm_ctx.gcm_gmult_accel = gfmul_armv8;
		goto out;
	} else if (feat & LC_CPU_FEATURE_INTEL_PCLMUL) {
		gfmu_x8664_init((uint64_t *)ctx->gcm_ctx.HL, H);
		ctx->gcm_ctx.gcm_gmult_accel = gfmu_x8664;
		goto out;
	} else {
		ctx->gcm_ctx.gcm_gmult_accel = NULL;
	}

	ctx->gcm_ctx.HL[8] = H[1]; /* 8 = 1000 corresponds to 1 in GF(2^128) */
	ctx->gcm_ctx.HH[8] = H[0];
	ctx->gcm_ctx.HH[0] = 0; /* 0 corresponds to 0 in GF(2^128) */
	ctx->gcm_ctx.HL[0] = 0;

	for (i = 4; i > 0; i >>= 1) {
		uint32_t T = (uint32_t)(H[1] & 1) * 0xe1000000U;

		H[1] = (H[0] << 63) | (H[1] >> 1);
		H[0] = (H[0] >> 1) ^ ((uint64_t)T << 32);
		ctx->gcm_ctx.HL[i] = H[1];
		ctx->gcm_ctx.HH[i] = H[0];
	}
	for (i = 2; i < AES_BLOCKSIZE; i <<= 1) {
		uint64_t *HiL = ctx->gcm_ctx.HL + i, *HiH = ctx->gcm_ctx.HH + i;

		H[0] = *HiH;
		H[1] = *HiL;

		for (j = 1; j < i; j++) {
			HiH[j] = H[0] ^ ctx->gcm_ctx.HH[j];
			HiL[j] = H[1] ^ ctx->gcm_ctx.HL[j];
		}
	}

out:
	unpoison(key, keylen);
	return ret;
}

static int gcm_setiv(struct lc_aes_gcm_cryptor *ctx, const uint8_t *iv,
		     size_t iv_len)
{
	const uint8_t *p; /* general purpose array pointer */
	/* XOR source built from provided IV if len != AES_BLOCKSIZE */
	uint8_t work_buf[AES_BLOCKSIZE];
	uint8_t use_len =
		0; /* byte count to process, up to AES_BLOCKSIZE bytes */

	/*
	 * The IV may be NULL, which is appropriate if the gcm_generate_iv API
	 * was used.
	 */
	if (!iv)
		return 0;

	/*
	 * When a new IV is set, we start with a new encryption, thus set the
	 * AAD to zero
	 */
	ctx->gcm_ctx.aad_len = 0;
	ctx->gcm_ctx.rem_aad_inserted = 0;
	memset(ctx->gcm_ctx.buf, 0, sizeof(ctx->gcm_ctx.buf));

	/*
	 * since the context might be reused under the same key we zero the
	 * working buffers for this next new process
	 */
	memset(ctx->gcm_ctx.y, 0, sizeof(ctx->gcm_ctx.y));
	ctx->gcm_ctx.len = 0;

	if (iv_len == 12) { /* GCM natively uses a 12-byte, 96-bit IV */
		/* copy the IV to the top of the 'y' buff */
		memcpy(ctx->gcm_ctx.y, iv, iv_len);
		/* start "counting" from 1 (not 0) */
		ctx->gcm_ctx.y[15] = 1;
	} else {
		/*
		 * if we don't have a 12-byte IV, we GHASH whatever we've been
		 * given
		 */

		/* clear the working buffer */
		memset(work_buf, 0, AES_BLOCKSIZE);

		be32_to_ptr(work_buf + 12, (uint32_t)(iv_len * 8));

		p = iv;
		while (iv_len > 0) {
			use_len = (iv_len < AES_BLOCKSIZE) ? (uint8_t)iv_len :
							     AES_BLOCKSIZE;

			xor_64(ctx->gcm_ctx.y, p, use_len);

			gcm_mult(ctx, ctx->gcm_ctx.y, ctx->gcm_ctx.y);
			iv_len -= use_len;
			p += use_len;
		}

		xor_64(ctx->gcm_ctx.y, work_buf, use_len);

		gcm_mult(ctx, ctx->gcm_ctx.y, ctx->gcm_ctx.y);
	}

	lc_sym_encrypt(&ctx->sym_ctx, ctx->gcm_ctx.y, ctx->gcm_ctx.base_ectr,
		       sizeof(ctx->gcm_ctx.y));

	return 0;
}

static int gcm_set_key_iv_nocheck(void *state, const uint8_t *key,
				  const size_t keylen, const uint8_t *iv,
				  size_t iv_len)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	int ret;

	CKINT(gcm_setkey(ctx, key, keylen));
	CKINT(gcm_setiv(ctx, iv, iv_len))

out:
	return ret;
}

static int gcm_set_key_iv(void *state, const uint8_t *key, const size_t keylen,
			  const uint8_t *iv, size_t iv_len)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	int ret;

	/*
	 * In FIPS mode, only the internal IV generation is allowed where the
	 * IV is generated and set by lc_aes_gcm_generate_iv.
	 */
	if (fips140_mode_enabled() && iv)
		return -EOPNOTSUPP;

	lc_aes_gcm_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_GCM);

	CKINT(gcm_set_key_iv_nocheck(ctx, key, keylen, iv, iv_len));

out:
	return ret;
}

/*
 * GCM start
 *
 * Given a user-provided GCM context, this initializes it, sets the encryption
 * mode, and preprocesses the initialization vector and additional AEAD data.
 *
 * This function allows to be invoked multiple times to insert the AAD. The
 * individual AAD chunks do not need to be multiples of AES blocks.
 */
static void gcm_aad(void *state, const uint8_t *aad, size_t aad_len)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	const uint8_t *p; /* general purpose array pointer */
	uint8_t use_len; /* byte count to process, up to AES_BLOCKSIZE bytes */
	uint8_t rem_aad = ctx->gcm_ctx.aad_len & (AES_BLOCKSIZE - 1);

	/*
	 * Do not re-initialize gcm_ctx.aad_len and gcm_ctx.buf as this call
	 * may be invoked multiple times if we have split AAD.
	 */

	/* Add the AAD to existing AAD */
	ctx->gcm_ctx.aad_len += aad_len;
	p = aad;

	while (aad_len > 0) {
		use_len = (aad_len < (size_t)(AES_BLOCKSIZE - rem_aad) ?
				      (uint8_t)aad_len :
				      (AES_BLOCKSIZE - rem_aad));

		xor_64(ctx->gcm_ctx.buf + rem_aad, p, use_len);

		/*
		 * Only handle full blocks consisting of the previous remaining
		 * and the current part at this time - the enc/dec must
		 * handle the final non-aligned block.
		 */
		if (!((rem_aad + use_len) & (AES_BLOCKSIZE - 1)))
			gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);

		aad_len -= use_len;
		p += use_len;
		rem_aad = 0;
	}
}

/*
 * GCM update
 *
 * This is called once or more to process bulk plaintext or ciphertext data.
 * We give this some number of bytes of input and it returns the same number
 * of output bytes. If called multiple times (which is fine) all but the final
 * invocation MUST be called with length mod AES_BLOCKSIZE == 0. (Only the final
 * call can have a partial block length of < 128 bits.)
 */
static void gcm_enc_update(void *state, const uint8_t *plaintext,
			   uint8_t *ciphertext, size_t datalen)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	uint8_t use_len; /* byte count to process, up to AES_BLOCKSIZE bytes */
	uint8_t i; /* local loop iterator */
	uint8_t non_align;
	uint8_t rem_aad = ctx->gcm_ctx.aad_len & (AES_BLOCKSIZE - 1);

	/* Finalize the AAD processing */
	if (rem_aad && !ctx->gcm_ctx.rem_aad_inserted) {
		gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);
		ctx->gcm_ctx.rem_aad_inserted = 1;
	}

	non_align = ctx->gcm_ctx.len & (AES_BLOCKSIZE - 1);

	/* bump the GCM context's running length count */
	ctx->gcm_ctx.len += datalen;

	/*
	 * SP800-38D requires that the maximum encryption is 2^32 - 1 AES blocks
	 */
	if (ctx->gcm_ctx.len > ((1UL << 32) - 1) * AES_BLOCKSIZE) {
		/* clear out the destination buffer */
		memset(ciphertext, 0, datalen);
		return;
	}

	while (datalen > 0) {
		use_len = (datalen < AES_BLOCKSIZE) ? (uint8_t)datalen :
						      AES_BLOCKSIZE;

		/* clamp the datalen to process at AES_BLOCKSIZE bytes */
		if (non_align) {
			if (use_len + non_align > AES_BLOCKSIZE)
				use_len = AES_BLOCKSIZE - non_align;

			xor_64_3(ciphertext, ctx->gcm_ctx.ectr + non_align,
				 plaintext, use_len);
			xor_64(ctx->gcm_ctx.buf + non_align, ciphertext,
			       use_len);

			if (use_len + non_align == AES_BLOCKSIZE) {
				gcm_mult(ctx, ctx->gcm_ctx.buf,
					 ctx->gcm_ctx.buf);
			}

			/* Ciphertext is not sensitive any more */
			unpoison(ciphertext, use_len);

			datalen -= use_len;
			plaintext += use_len;
			ciphertext += use_len;
			non_align = 0;

			continue;
		}

		/* increment the context's 128-bit IV||Counter 'y' vector */
		for (i = AES_BLOCKSIZE; i > 12; i--)
			if (++ctx->gcm_ctx.y[i - 1] != 0)
				break;

		/* encrypt the context's 'y' vector under the established key */
		lc_sym_encrypt(&ctx->sym_ctx, ctx->gcm_ctx.y, ctx->gcm_ctx.ectr,
			       sizeof(ctx->gcm_ctx.y));

		/*
		 * XOR the cipher's ouptut vector (ectr) with our plaintext
		 */
		xor_64_3(ciphertext, ctx->gcm_ctx.ectr, plaintext, use_len);

		/*
		 * now we mix in our data into the authentication hash.
		 * if we're ENcrypting we XOR in the post-XOR (output)
		 * results, but if we're DEcrypting we XOR in the plaintext data
		 */
		xor_64(ctx->gcm_ctx.buf, ciphertext, use_len);

		/* perform a GHASH operation */
		if (use_len == AES_BLOCKSIZE)
			gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);

		/* Ciphertext is not sensitive any more */
		unpoison(ciphertext, use_len);

		datalen -= use_len; // drop the remaining byte count to process
		plaintext += use_len; // bump our input pointer forward
		ciphertext += use_len; // bump our output pointer forward
	}
}

static void gcm_dec_update(void *state, const uint8_t *ciphertext,
			   uint8_t *plaintext, size_t datalen)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	uint8_t use_len; /* byte count to process, up to AES_BLOCKSIZE bytes */
	uint8_t i; /* local loop iterator */
	uint8_t non_align;
	uint8_t rem_aad = ctx->gcm_ctx.aad_len & (AES_BLOCKSIZE - 1);

	/* Finalize the AAD processing */
	if (rem_aad && !ctx->gcm_ctx.rem_aad_inserted) {
		gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);
		ctx->gcm_ctx.rem_aad_inserted = 1;
	}

	non_align = ctx->gcm_ctx.len & (AES_BLOCKSIZE - 1);

	/* bump the GCM context's running length count */
	ctx->gcm_ctx.len += datalen;

	while (datalen > 0) {
		// clamp the datalen to process at AES_BLOCKSIZE bytes
		use_len = (datalen < AES_BLOCKSIZE) ? (uint8_t)datalen :
						      AES_BLOCKSIZE;

		/* clamp the datalen to process at AES_BLOCKSIZE bytes */
		if (non_align) {
			if (use_len + non_align > AES_BLOCKSIZE)
				use_len = AES_BLOCKSIZE - non_align;

			xor_64(ctx->gcm_ctx.buf + non_align, ciphertext,
			       use_len);
			xor_64_3(plaintext, ctx->gcm_ctx.ectr + non_align,
				 ciphertext, use_len);

			if (use_len + non_align == AES_BLOCKSIZE) {
				gcm_mult(ctx, ctx->gcm_ctx.buf,
					 ctx->gcm_ctx.buf);
			}

			/* Plaintext is not sensitive any more */
			unpoison(plaintext, use_len);

			datalen -= use_len;
			plaintext += use_len;
			ciphertext += use_len;
			non_align = 0;

			continue;
		}

		/* increment the context's 128-bit IV||Counter 'y' vector */
		for (i = 16; i > 12; i--)
			if (++ctx->gcm_ctx.y[i - 1] != 0)
				break;

		/* encrypt the context's 'y' vector under the established key */
		lc_sym_encrypt(&ctx->sym_ctx, ctx->gcm_ctx.y, ctx->gcm_ctx.ectr,
			       sizeof(ctx->gcm_ctx.y));

		/*
		 * but if we're DEcrypting we XOR in the ciphertext
		 * data first, i.e. before saving to ouput data,
		 * otherwise if the ciphertext and plaintext buffer are
		 * the same (inplace decryption) we would not get the
		 * correct auth tag
		 */
		xor_64(ctx->gcm_ctx.buf, ciphertext, use_len);

		/*
		 * XOR the cipher's ouptut vector (ectr) with our ciphertext
		 */
		xor_64_3(plaintext, ctx->gcm_ctx.ectr, ciphertext, use_len);

		/* perform a GHASH operation */
		if (use_len == AES_BLOCKSIZE)
			gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);

		/* Plaintext is not sensitive any more */
		unpoison(plaintext, use_len);

		datalen -= use_len; // drop the remaining byte count to process
		ciphertext += use_len; // bump our input pointer forward
		plaintext += use_len; // bump our plaintext pointer forward
	}
	return;
}

/*
 * GCM finish
 *
 * This is called once after all calls to GCM_UPDATE to finalize the GCM.
 * It performs the final GHASH to produce the resulting authentication TAG.
 *
 */
static void gcm_enc_final(void *state, uint8_t *tag, size_t tag_len)
{
	struct lc_aes_gcm_cryptor *ctx = state;
	uint64_t orig_len = ctx->gcm_ctx.len * 8;
	uint64_t orig_aad_len = ctx->gcm_ctx.aad_len * 8;

	/* Enforce minimum tag size of 64 bits */
	if (tag_len < 64 / 8 || tag_len > AES_BLOCKSIZE)
		return;

	if (ctx->gcm_ctx.len & (AES_BLOCKSIZE - 1))
		gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);

	memcpy(tag, ctx->gcm_ctx.base_ectr, tag_len);

	if (orig_len || orig_aad_len) {
		uint8_t work_buf[AES_BLOCKSIZE];

		memset(work_buf, 0, AES_BLOCKSIZE);

		be64_to_ptr(work_buf, orig_aad_len);
		be64_to_ptr(work_buf + 8, orig_len);

		xor_64(ctx->gcm_ctx.buf, work_buf, AES_BLOCKSIZE);

		gcm_mult(ctx, ctx->gcm_ctx.buf, ctx->gcm_ctx.buf);

		xor_64(tag, ctx->gcm_ctx.buf, tag_len);
	}

	/* Tag is not sensitive any more */
	unpoison(tag, tag_len);

	return;
}

/*
 * GCM_AUTH_DECRYPT
 *
 * This DECRYPTS a user-provided data buffer with optional associated data.
 * It then verifies a user-supplied authentication tag against the tag just
 * re-created during decryption to verify that the data has not been altered.
 *
 * This function calls GCM_CRYPT_AND_TAG (above) to perform the decryption
 * and authentication tag generation.
 */
static int gcm_dec_final(void *state, const uint8_t *tag, size_t taglen)
{
	/* the tag generated and returned by decryption */
	uint8_t check_tag[AES_BLOCKSIZE] __align(8);
	int ret;

	gcm_enc_final(state, check_tag, taglen);

	/* now we verify the authentication tag in 'constant time' */
	ret = lc_memcmp_secure(tag, taglen, check_tag, taglen) ? -EBADMSG : 0;

	lc_memset_secure(check_tag, 0, sizeof(check_tag));
	return ret;
}

static void gcm_encrypt(void *state, const uint8_t *plaintext,
			uint8_t *ciphertext, size_t datalen, const uint8_t *aad,
			size_t aadlen, uint8_t *tag, size_t taglen)
{
	gcm_aad(state, aad, aadlen);
	gcm_enc_update(state, plaintext, ciphertext, datalen);
	gcm_enc_final(state, tag, taglen);
}

static int gcm_decrypt(void *state, const uint8_t *ciphertext,
		       uint8_t *plaintext, size_t datalen, const uint8_t *aad,
		       size_t aadlen, const uint8_t *tag, size_t taglen)
{
	gcm_aad(state, aad, aadlen);
	gcm_dec_update(state, ciphertext, plaintext, datalen);
	return gcm_dec_final(state, tag, taglen);
}

/*
 * GCM_ZERO_CTX
 *
 * The GCM context contains both the GCM context and the AES context.
 * This includes keying and key-related material which is security-
 * sensitive, so it MUST be zeroed after use. This function does that.
 */
static void gcm_zero_ctx(void *state)
{
	struct lc_aes_gcm_cryptor *ctx = state;

	/* zero the context originally provided to us */
	memset(&ctx->gcm_ctx, 0, sizeof(struct lc_gcm_ctx));
	lc_sym_zero(&ctx->sym_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_aes_gcm_alloc, struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_MEM_COMMON_ALIGNMENT,
			       LC_AES_GCM_CTX_SIZE);
	if (ret)
		return -ret;

	LC_AES_GCM_SET_CTX(tmp);

	*ctx = tmp;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aes_gcm_generate_iv, struct lc_aead_ctx *ctx,
		      const uint8_t *fixed_field, size_t fixed_field_len,
		      uint8_t *iv, size_t ivlen, enum lc_aes_gcm_iv_type type)
{
	struct lc_aes_gcm_cryptor *gcm_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(iv, -EINVAL);
	if (fixed_field_len >= ivlen)
		return -EINVAL;

	if (fixed_field && fixed_field != iv)
		memcpy(iv, fixed_field, fixed_field_len);

	switch (type) {
	case lc_aes_gcm_iv_generate_new:
		CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0,
				      iv + fixed_field_len,
				      ivlen - fixed_field_len));
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	gcm_ctx = ctx->aead_state;
	CKINT(gcm_setiv(gcm_ctx, iv, ivlen));

out:
	return ret;
}

static const struct lc_aead _lc_aes_gcm_aead = {
	.setkey = gcm_set_key_iv,
	.encrypt = gcm_encrypt,
	.enc_init = gcm_aad,
	.enc_update = gcm_enc_update,
	.enc_final = gcm_enc_final,
	.decrypt = gcm_decrypt,
	.dec_init = gcm_aad,
	.dec_update = gcm_dec_update,
	.dec_final = gcm_dec_final,
	.zero = gcm_zero_ctx };
LC_INTERFACE_SYMBOL(const struct lc_aead *,
		    lc_aes_gcm_aead) = &_lc_aes_gcm_aead;
