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

#include "bitshift.h"
#include "build_bug_on.h"
#include "compare.h"
#include "conv_be_le.h"
#include "fips_mode.h"
#include "lc_aes.h"
#include "lc_ctr_drbg.h"
#include "lc_memcpy_secure.h"
#include "lc_status.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor.h"

/* Required for context size */
#include "aes_c.h"
#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_riscv64.h"

#include "../../sym/src/mode_ctr.h"

static int lc_drbg_ctr_seed_nocheck(void *_state, const uint8_t *seedbuf,
				    size_t seedlen, const uint8_t *persbuf,
				    size_t perslen);

static void drbg_ctr_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t ent_nonce[] = { FIPS140_MOD(0xDF),
					     0xCA,
					     0x2B,
					     0xD1,
					     0x9D,
					     0x55,
					     0xCB,
					     0xE4,
					     0xEF,
					     0xA5,
					     0x22,
					     0x92,
					     0x0F,
					     0x5F,
					     0x17,
					     0x7E,
					     0xA8,
					     0x80,
					     0x2A,
					     0xCD,
					     0x32,
					     0xF9,
					     0xC4,
					     0x0B,
					     0x85,
					     0xE4,
					     0x1E,
					     0xF5,
					     0x68,
					     0x94,
					     0x64,
					     0x94,
					     0xDB,
					     0x0E,
					     0x17,
					     0x77,
					     0x98,
					     0x12,
					     0x47,
					     0x0F,
					     0x36,
					     0x7B,
					     0x1C,
					     0xC5,
					     0x89,
					     0xEE,
					     0xC7,
					     0xEA };
	LC_FIPS_RODATA_SECTION
	static const uint8_t addtl1[] = { 0xCA, 0x82, 0xF8, 0xC7, 0xA0, 0xCF,
					  0x40, 0x5D, 0xE5, 0x61, 0x6C, 0xCB,
					  0x8D, 0xA0, 0xF4, 0x4E, 0x51, 0x0D,
					  0xCB, 0x59, 0x58, 0x92, 0x6D, 0xD5,
					  0x7B, 0x72, 0xA8, 0xFB, 0xA8, 0x89,
					  0x58, 0xAE };
	LC_FIPS_RODATA_SECTION
	static const uint8_t addtl2[] = { 0xDD, 0xB4, 0xD2, 0xD8, 0xBB, 0x4A,
					  0xA4, 0xF7, 0x41, 0xC4, 0xE4, 0xE5,
					  0x64, 0x02, 0x5F, 0x0C, 0x6A, 0xAB,
					  0x81, 0xD7, 0x4A, 0xF4, 0x32, 0x7A,
					  0x59, 0xE5, 0x18, 0xD6, 0xF0, 0x06,
					  0xCF, 0x69 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t reseed_ent_nonce[] = {
		0x19, 0x37, 0x7A, 0x7B, 0xA2, 0xD6, 0x0F, 0xB0, 0x56, 0x80,
		0xB7, 0x32, 0xE3, 0x49, 0x1F, 0xF4, 0x2C, 0xAE, 0x40, 0xDF,
		0xD8, 0x72, 0xE5, 0x09, 0xEC, 0x28, 0x2F, 0x60, 0x61, 0x6F,
		0xB6, 0xBC, 0x0C, 0x4D, 0x01, 0xEA, 0xA3, 0x1A, 0xAF, 0x21,
		0x9F, 0x38, 0xBB, 0x99, 0x68, 0xC7, 0x79, 0x0A
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t reseed_addtl[] = {
		0x8F, 0x71, 0x86, 0x58, 0x51, 0xB0, 0x19, 0x36,
		0x04, 0xD9, 0x69, 0xB7, 0xCA, 0xAE, 0xED, 0x01,
		0xE1, 0xC0, 0x5F, 0x49, 0xB4, 0x5E, 0xDA, 0x51,
		0xDB, 0x49, 0x78, 0xB9, 0x06, 0x44, 0x36, 0x4F
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp[] = { 0x8d, 0xba, 0x3a, 0xb3, 0x17, 0xad, 0xfe,
				       0x54, 0x37, 0x63, 0x78, 0x19, 0xae, 0x07,
				       0x76, 0xb2, 0x00, 0x66, 0xc3, 0x80, 0x8d,
				       0x83, 0x14, 0x9f, 0xd1, 0x51, 0x0a, 0x8d,
				       0x4c, 0xb7, 0x66, 0x3d };
	uint8_t act[sizeof(exp)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(lc_ctr_drbg->algorithm_type);

	LC_DRBG_CTR_USE_DF_CTX_ON_STACK(drbg_ctx);

	if (lc_drbg_ctr_seed_nocheck(drbg_ctx->rng_state, ent_nonce,
				     sizeof(ent_nonce), NULL, 0))
		goto out;
	if (lc_drbg_ctr_seed_nocheck(drbg_ctx->rng_state, reseed_ent_nonce,
				     sizeof(reseed_ent_nonce), reseed_addtl,
				     sizeof(reseed_addtl)))
		goto out;

	lc_rng_generate(drbg_ctx, addtl1, sizeof(addtl1), act, sizeof(act));
	lc_rng_generate(drbg_ctx, addtl2, sizeof(addtl2), act, sizeof(act));

out:
	lc_compare_selftest(lc_ctr_drbg->algorithm_type, act, exp, sizeof(exp),
			    "CTR DRBG");
	lc_rng_zero(drbg_ctx);
}

/* BCC function for CTR DRBG as defined in 10.4.3 */
static int drbg_ctr_bcc(uint8_t *out, const uint8_t *key,
			struct lc_drbg_string *in)
{
	int ret = 0;
	unsigned short cnt = 0;
	LC_SYM_CTX_ON_STACK(algo, lc_aes);

	CKINT(lc_sym_init(algo));

	/* 10.4.3 step 2 / 4 */
	CKINT(lc_sym_setkey(algo, key, LC_DRBG_KEYLEN));
	for (; in != NULL; in = in->next) {
		const uint8_t *pos = in->buf;
		size_t len = in->len;

		/* 10.4.3 step 4.1 */
		while (len) {
			/* 10.4.3 step 4.2 */
			if (LC_DRBG_CTR_BLOCKLEN == cnt) {
				cnt = 0;
				lc_sym_encrypt(algo, out, out,
					       LC_DRBG_CTR_BLOCKLEN);
			}
			out[cnt] ^= *pos;
			pos++;
			cnt++;
			len--;
		}
	}

	/* 10.4.3 step 4.2 for last block */
	if (cnt)
		lc_sym_encrypt(algo, out, out, LC_DRBG_CTR_BLOCKLEN);

out:
	lc_sym_zero(algo);
	return ret;
}

/*
 * scratchpad usage: drbg_ctr_update is interlinked with drbg_ctr_df
 * (and drbg_ctr_bcc, but this function does not need any temporary buffers),
 * the scratchpad is used as follows:
 * drbg_ctr_update:
 *	temp
 *		start: drbg->scratchpad
 *		length: lc_drbg_ctr_statelen(drbg) + drbg_blocklen(drbg)
 *			note: the cipher writing into this variable works
 *			blocklen-wise. Now, when the statelen is not a multiple
 *			of blocklen, the generateion loop below "spills over"
 *			by at most blocklen. Thus, we need to give sufficient
 *			memory.
 *	df_data
 *		start: drbg->scratchpad +
 *				lc_drbg_ctr_statelen(drbg) + drbg_blocklen(drbg)
 *		length: lc_drbg_ctr_statelen(drbg)
 *
 * drbg_ctr_df:
 *	pad
 *		start: df_data + lc_drbg_ctr_statelen(drbg)
 *		length: drbg_blocklen(drbg)
 *	iv
 *		start: pad + drbg_blocklen(drbg)
 *		length: drbg_blocklen(drbg)
 *	temp
 *		start: iv + drbg_blocklen(drbg)
 *		length: drbg_satelen(drbg) + drbg_blocklen(drbg)
 *			note: temp is the buffer that the BCC function operates
 *			on. BCC operates blockwise. lc_drbg_ctr_statelen(drbg)
 *			is sufficient when the DRBG state length is a multiple
 *			of the block size. For AES192 (and maybe other ciphers)
 *			this is not correct and the length for temp is
 *			insufficient (yes, that also means for such ciphers,
 *			the final output of all BCC rounds are truncated).
 *			Therefore, add drbg_blocklen(drbg) to cover all
 *			possibilities.
 */

/* Derivation Function for CTR DRBG as defined in 10.4.2 */
static int drbg_ctr_df(uint8_t *df_data, size_t bytes_to_return,
		       struct lc_drbg_string *seedlist)
{
	/* S3 is input */
	struct lc_drbg_string S1, S2, S4;
	struct lc_drbg_string *seed = NULL;
	uint8_t *pad = df_data + LC_DRBG_CTR_STATELEN;
	uint8_t *iv = pad + LC_DRBG_CTR_BLOCKLEN;
	uint8_t *temp = iv + LC_DRBG_CTR_BLOCKLEN;
	size_t padlen = 0;
	unsigned int templen = 0;
	/* 10.4.2 step 7 */
	unsigned int i = 0;
	/* 10.4.2 step 8 */
	static const uint8_t K[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				     0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				     0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				     0x1c, 0x1d, 0x1e, 0x1f };
	uint8_t *X;
	size_t generated_len = 0;
	size_t inputlen = 0;
	int ret;
	uint8_t L_N[8];
	LC_SYM_CTX_ON_STACK(algo, lc_aes);

	CKINT(lc_sym_init(algo));

	memset(pad, 0, LC_DRBG_CTR_BLOCKLEN);
	memset(iv, 0, LC_DRBG_CTR_BLOCKLEN);

	/* 10.4.2 step 1 is implicit as we work byte-wise */

	/* 10.4.2 step 2 */
	if ((512 / 8) < bytes_to_return)
		return -EINVAL;

	/* 10.4.2 step 2 -- calculate the entire length of all input data */
	for (seed = seedlist; seed != NULL; seed = seed->next) {
		inputlen += seed->len;
		if (seed->next == NULL) {
			seed->next = &S4;
			break;
		}
	}

	/* Cast is appropriate as outlen is never larger than 2^16. */
	be32_to_ptr(&L_N[0], (uint32_t)(inputlen));

	/* 10.4.2 step 3 */
	be32_to_ptr(&L_N[4], (uint32_t)(bytes_to_return));

	/* 10.4.2 step 5: length is L_N, input_string, one byte, padding */
	padlen = (inputlen + sizeof(L_N) + 1) % LC_DRBG_CTR_BLOCKLEN;
	/* wrap the padlen appropriately */
	if (padlen)
		padlen = LC_DRBG_CTR_BLOCKLEN - padlen;
	/*
	 * pad / padlen contains the 0x80 byte and the following zero bytes.
	 * As the calculated padlen value only covers the number of zero
	 * bytes, this value has to be incremented by one for the 0x80 byte.
	 */
	padlen++;
	pad[0] = 0x80;

	/* 10.4.2 step 4 -- first fill the linked list and then order it */
	lc_drbg_string_fill(&S1, iv, LC_DRBG_CTR_BLOCKLEN);
	S1.next = &S2;
	lc_drbg_string_fill(&S2, L_N, sizeof(L_N));
	S2.next = seedlist;
	lc_drbg_string_fill(&S4, pad, padlen);
	/* S4 was hooked at the end of seedlist above */

	/* 10.4.2 step 9 */
	while (templen < (LC_DRBG_KEYLEN + LC_DRBG_CTR_BLOCKLEN)) {
		/*
		 * 10.4.2 step 9.1 - the padding is implicit as the buffer
		 * holds zeros after allocation -- even the increment of i
		 * is irrelevant as the increment remains within length of i
		 */
		be32_to_ptr(iv, i);
		/* 10.4.2 step 9.2 -- BCC and concatenation with temp */
		ret = drbg_ctr_bcc(temp + templen, K, &S1);
		if (ret)
			goto out;
		/* 10.4.2 step 9.3 */
		i++;
		templen += LC_DRBG_CTR_BLOCKLEN;
	}

	/* 10.4.2 step 11 */
	X = temp + LC_DRBG_KEYLEN;

	/* 10.4.2 step 12: overwriting of outval is implemented in next step */

	/* 10.4.2 step 13 */
	CKINT(lc_sym_setkey(algo, temp, LC_DRBG_KEYLEN));
	while (generated_len < bytes_to_return) {
		size_t blocklen = 0;

		/*
		 * 10.4.2 step 13.1: the truncation of the key length is
		 * implicit as the key is only drbg_blocklen in size based on
		 * the implementation of the cipher function callback
		 */
		lc_sym_encrypt(algo, X, X, LC_DRBG_CTR_BLOCKLEN);
		blocklen = (LC_DRBG_CTR_BLOCKLEN <
			    (bytes_to_return - generated_len)) ?
				   LC_DRBG_CTR_BLOCKLEN :
				   (bytes_to_return - generated_len);
		/* 10.4.2 step 13.2 and 14 */
		memcpy(df_data + generated_len, X, blocklen);
		generated_len += blocklen;
	}

	ret = 0;

out:
	/* Remove pointer to stack variable - this is to shut up the compiler */
	if (seed)
		seed->next = NULL;
	lc_sym_zero(algo);
	lc_memset_secure(iv, 0, LC_DRBG_CTR_BLOCKLEN);
	lc_memset_secure(temp, 0, LC_DRBG_CTR_STATELEN + LC_DRBG_CTR_BLOCKLEN);
	lc_memset_secure(pad, 0, LC_DRBG_CTR_BLOCKLEN);
	return ret;
}

/*
 * Processing of no derivation function behavior
 *
 * seedlist contains 2 entries: first is seed, second is optional
 * personalization/additional information string.
 */
static int drbg_ctr_nodf(uint8_t *df_data, struct lc_drbg_string *seedlist)
{
	struct lc_drbg_string *perso = seedlist->next;

	/*
	 * Seed buffer must not be larger than seedlen bits in size.
	 */
	if (seedlist->len > LC_DRBG_CTR_STATELEN)
		return -EINVAL;

	lc_memcpy_secure(df_data, LC_DRBG_CTR_STATELEN, seedlist->buf,
			 seedlist->len);

	/* Personalization string present */
	if (perso) {
		/* We only process up to seedlen bits */
		if (perso->len > LC_DRBG_CTR_STATELEN)
			return -EINVAL;
		xor_64(df_data, perso->buf, perso->len);
	}

	return 0;
}

/*
 * When enabling the flag LC_DRBG_CTR_SMALL_CTR, the CTR DRBG operates with a
 * small counter size. Usually this operation is not really requested or even
 * relevant. Therefore its code is only provided for analysis. The
 * implementation limits the counter value to 8 bits at max. which is to be set
 * with the macro LC_DRBG_CTR_SMALL_CTR.
 */
#undef LC_DRBG_CTR_SMALL_CTR
#ifndef LC_DRBG_CTR_SMALL_CTR

static inline void drbg_ctr_inc(struct lc_drbg_ctr_state *drbg)
{
	/*
	 * The DRBG uses the CTR mode of the underlying AES cipher. The
	 * CTR mode increments the counter value after the AES operation
	 * but SP800-90A requires that the counter is incremented before
	 * the AES operation. Hence, we increment it at the time we set
	 * it by one.
	 *
	 * To prevent dependencies on the actual CTR Mode
	 * implementation, the V management is kept in the CTR DRBG
	 * code and loaded into the CTR mode using setiv. Yes, that
	 * entails another memcpy, but we take that penalty for code
	 * sanity.
	 */
	drbg->ctr.V_64[0] = be_bswap64(drbg->ctr.V_64[0]);
	drbg->ctr.V_64[1] = be_bswap64(drbg->ctr.V_64[1]);
	ctr128_inc(drbg->ctr.V_64);
	drbg->ctr.V_64[0] = be_bswap64(drbg->ctr.V_64[0]);
	drbg->ctr.V_64[1] = be_bswap64(drbg->ctr.V_64[1]);
}

static inline size_t drbg_ctr_avail_bytes(struct lc_drbg_ctr_state *drbg,
					  size_t requested)
{
	(void)drbg;
	return requested;
}

static inline void drbg_ctr_fixup(struct lc_drbg_ctr_state *drbg)
{
	(void)drbg;
}

#else

#define LC_DRBG_CTR_SMALL_CTR_BITS 6
#define LC_DRBG_CTR_SMALL_CTR_VAL (1 << LC_DRBG_CTR_SMALL_CTR_BITS)
#define LC_DRBG_CTR_SMALL_CTR_MASK (LC_DRBG_CTR_SMALL_CTR_VAL - 1)

static inline void drbg_ctr_inc(struct lc_drbg_ctr_state *drbg)
{
	/*
	 * This implementation only operates on the last byte, so the
	 * counter size cannot be larger than one byte
	 */
	BUILD_BUG_ON(LC_DRBG_CTR_SMALL_CTR_BITS > (sizeof(uint8_t) << 3));

	/*
	 * If the last LC_DRBG_CTR_SMALL_CTR_BITS are all set, then an inc
	 * is simply to unset all bits (i.e. the wrap).
	 */
	if ((drbg->ctr.V[LC_DRBG_CTR_BLOCKLEN - 1] &
	     LC_DRBG_CTR_SMALL_CTR_MASK) == LC_DRBG_CTR_SMALL_CTR_MASK) {
		drbg->ctr.V[LC_DRBG_CTR_BLOCKLEN - 1] &=
			~LC_DRBG_CTR_SMALL_CTR_MASK;
	} else {
		drbg->ctr.V[LC_DRBG_CTR_BLOCKLEN - 1]++;
	}
}

/* Return number of bytes before counter wraps */
static inline size_t drbg_ctr_avail_bytes(struct lc_drbg_ctr_state *drbg,
					  size_t requested)
{
	size_t blocks = LC_DRBG_CTR_SMALL_CTR_VAL -
			(drbg->ctr.V[LC_DRBG_CTR_BLOCKLEN - 1] &
			 LC_DRBG_CTR_SMALL_CTR_MASK);

	if (!blocks)
		blocks = LC_DRBG_CTR_SMALL_CTR_VAL;

	return min_size(requested, (blocks << 4));
}

/*
 * Considering that we use the AES-CTR mode, the counter increment happens
 * after the actual encryption. This implies that a counter may have wrapped
 * with the last increment that the AES-CTR did not apply. Thus, fix up the
 * counter by always undoing the last increment and doing a "manual inc".
 */
static inline void drbg_ctr_fixup(struct lc_drbg_ctr_state *drbg)
{
	drbg->ctr.V_64[0] = be_bswap64(drbg->ctr.V_64[0]);
	drbg->ctr.V_64[1] = be_bswap64(drbg->ctr.V_64[1]);
	if (likely(drbg->ctr.V_64[1] != 0)) {
		drbg->ctr.V_64[1]--;
	} else {
		drbg->ctr.V_64[1] = 0xffffffffffffffff;

		if (likely(drbg->ctr.V_64[0] != 0))
			drbg->ctr.V_64[0]--;
		else
			drbg->ctr.V_64[0] = 0xffffffffffffffff;
	}
	drbg->ctr.V_64[0] = be_bswap64(drbg->ctr.V_64[0]);
	drbg->ctr.V_64[1] = be_bswap64(drbg->ctr.V_64[1]);

	drbg_ctr_inc(drbg);
}

#endif

/*
 * update function of CTR DRBG as defined in 10.2.1.2
 *
 * The reseed variable has an enhanced meaning compared to the update
 * functions of the other DRBGs as follows:
 * 0 => initial seed from initialization
 * 1 => reseed via drbg_seed
 * 2 => first invocation from drbg_ctr_update when addtl is present. In
 *      this case, the df_data scratchpad is not deleted so that it is
 *      available for another calls to prevent calling the DF function
 *      again.
 * 3 => second invocation from drbg_ctr_update. When the update function
 *      was called with addtl, the df_data memory already contains the
 *      DFed addtl information and we do not need to call DF again.
 */
static int drbg_ctr_update(struct lc_drbg_ctr_state *drbg,
			   struct lc_drbg_string *seed, int reseed)
{
	struct lc_sym_ctx *ctr_ctx = &drbg->ctr_ctx;
	/* 10.2.1.2 step 1 */
	uint8_t *temp = drbg->scratchpad;
	uint8_t *df_data = temp + LC_DRBG_CTR_STATELEN + LC_DRBG_CTR_BLOCKLEN;
	int ret = -EFAULT;

	if (3 > reseed)
		memset(df_data, 0, LC_DRBG_CTR_STATELEN);

	if (!reseed) {
		drbg_ctr_inc(drbg);
		CKINT(lc_sym_setkey(ctr_ctx, drbg->C, LC_DRBG_KEYLEN));
	}

	/* 10.2.1.3.2 step 2 and 10.2.1.4.2 step 2 */
	if (seed) {
		if (drbg->use_df) {
			CKINT(drbg_ctr_df(df_data, LC_DRBG_CTR_STATELEN, seed));
		} else {
			CKINT(drbg_ctr_nodf(df_data, seed));
		}
	}

	CKINT(lc_sym_setiv(ctr_ctx, drbg->ctr.V, LC_DRBG_CTR_BLOCKLEN));
	lc_sym_encrypt(ctr_ctx, df_data, temp, LC_DRBG_CTR_STATELEN);

	/* 10.2.1.2 step 5 */
	CKINT(lc_sym_setkey(ctr_ctx, temp, LC_DRBG_KEYLEN));

	/* 10.2.1.2 step 6 */
	memcpy(drbg->ctr.V, temp + LC_DRBG_KEYLEN, LC_DRBG_CTR_BLOCKLEN);

	drbg_ctr_inc(drbg);

	ret = 0;

out:
	lc_memset_secure(temp, 0, LC_DRBG_CTR_STATELEN + LC_DRBG_CTR_BLOCKLEN);
	if (2 != reseed)
		lc_memset_secure(df_data, 0, LC_DRBG_CTR_STATELEN);
	return ret;
}

/*
 * scratchpad use: drbg_ctr_update is called independently from
 * drbg_ctr_extract_bytes. Therefore, the scratchpad is reused
 */
/* Generate function of CTR DRBG as defined in 10.2.1.5.2 */
static int drbg_ctr_generate_internal(struct lc_drbg_ctr_state *drbg,
				      uint8_t *buf, size_t buflen,
				      struct lc_drbg_string *addtl)
{
	struct lc_sym_ctx *ctr_ctx = &drbg->ctr_ctx;
	int ret;

	/* 10.2.1.5.2 step 2 */
	if (addtl)
		CKINT(drbg_ctr_update(drbg, addtl, 2));

	/* 10.2.1.5.2 step 4.1 */
	memset(buf, 0, buflen);

	while (buflen) {
		size_t todo = min_size(LC_DRBG_MAX_REQUEST_BYTES, buflen);

		todo = drbg_ctr_avail_bytes(drbg, todo);

		CKINT(lc_sym_setiv(ctr_ctx, drbg->ctr.V, LC_DRBG_CTR_BLOCKLEN));
		lc_sym_encrypt(ctr_ctx, buf, buf, todo);
		CKINT(lc_sym_getiv(ctr_ctx, drbg->ctr.V, LC_DRBG_CTR_BLOCKLEN));

		drbg_ctr_fixup(drbg);

		/* 10.2.1.5.2 step 6 */
		CKINT(drbg_ctr_update(drbg, NULL, 3));

		buf += todo;
		buflen -= todo;
	}

out:
	return ret;
}

static int lc_drbg_ctr_generate(void *_state, const uint8_t *addtl_input,
				size_t addtl_input_len, uint8_t *out,
				size_t outlen)
{
	struct lc_drbg_ctr_state *drbg_ctr = _state;
	struct lc_drbg_string addtl_data;
	struct lc_drbg_string *addtl = NULL;

	if (!drbg_ctr)
		return -EINVAL;

	if (outlen > lc_drbg_max_request_bytes())
		return -EINVAL;

	if (addtl_input_len > lc_drbg_max_addtl())
		return -EINVAL;

	if (addtl_input_len && addtl_input) {
		lc_drbg_string_fill(&addtl_data, addtl_input, addtl_input_len);
		addtl = &addtl_data;
	}
	return drbg_ctr_generate_internal(drbg_ctr, out, outlen, addtl);
}

static int lc_drbg_ctr_seed_nocheck(void *_state, const uint8_t *seedbuf,
				    size_t seedlen, const uint8_t *persbuf,
				    size_t perslen)
{
	struct lc_drbg_ctr_state *drbg_ctr = _state;
	struct lc_sym_ctx *ctr_ctx;
	struct lc_drbg_string seed;
	struct lc_drbg_string pers;
	int ret;

	/* Sanity check for state size */
	BUILD_BUG_ON(LC_DRBG_CTR_SYM_STATE < LC_AES_RISCV64_CTR_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_DRBG_CTR_SYM_STATE < LC_AES_ARMCE_CTR_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_DRBG_CTR_SYM_STATE < LC_AES_AESNI_CTR_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_DRBG_CTR_SYM_STATE < LC_AES_C_CTR_MAX_BLOCK_SIZE);

	if (!drbg_ctr)
		return -EINVAL;

	/* 9.1 / 9.2 / 9.3.1 step 3 */
	if (persbuf && perslen > (lc_drbg_max_addtl()))
		return -EINVAL;

	if (!seedbuf || !seedlen)
		return -EINVAL;

	/*
	 * CTR DRBG without derivation function always requires exactly
	 * seedlen bits of seed data.
	 */
	if (!drbg_ctr->use_df && (seedlen != LC_DRBG_CTR_STATELEN))
		return -EINVAL;

	ctr_ctx = &drbg_ctr->ctr_ctx;
	CKINT(lc_sym_init(ctr_ctx));

	lc_drbg_string_fill(&seed, seedbuf, seedlen);

	/*
	 * concatenation of entropy with personalization str / addtl input)
	 * the variable pers is directly handed in by the caller, so check its
	 * contents whether it is appropriate
	 */
	if (persbuf && perslen) {
		lc_drbg_string_fill(&pers, persbuf, perslen);
		seed.next = &pers;
	}

	CKINT(drbg_ctr_update(drbg_ctr, &seed, drbg_ctr->seeded));
	drbg_ctr->seeded = 1;

out:
	return ret;
}

static int lc_drbg_ctr_seed(void *_state, const uint8_t *seedbuf,
			    size_t seedlen, const uint8_t *persbuf,
			    size_t perslen)
{
	drbg_ctr_selftest();
	LC_SELFTEST_COMPLETED(lc_ctr_drbg->algorithm_type);

	return lc_drbg_ctr_seed_nocheck(_state, seedbuf, seedlen, persbuf,
					perslen);
}

static void lc_drbg_ctr_zero(void *_state)
{
	struct lc_drbg_ctr_state *drbg_ctr = _state;
	struct lc_sym_ctx *ctr_ctx;

	if (!drbg_ctr)
		return;

	ctr_ctx = &drbg_ctr->ctr_ctx;
	lc_sym_zero(ctr_ctx);

	drbg_ctr->seeded = 0;
	/* leave drbg_ctr->use_df unchanged */
	/* leave drbg_ctr->scratchpad_size unchanged */
	lc_memset_secure(drbg_ctr->ctr.V, 0, sizeof(drbg_ctr->ctr.V));
	lc_memset_secure(drbg_ctr->C, 0, sizeof(drbg_ctr->C));
	lc_memset_secure(drbg_ctr->scratchpad, 0, drbg_ctr->scratchpad_size);
}

LC_INTERFACE_FUNCTION(int, lc_drbg_ctr_use_df_alloc, struct lc_rng_ctx **drbg)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!drbg)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_SYM_COMMON_ALIGNMENT,
				      LC_DRBG_CTR_CTX_SIZE_USE_DF);
	if (ret)
		return -ret;

	LC_DRBG_CTR_RNG_CTX(out_state, 1, LC_DRBG_CTR_SCRATCHPAD_USE_DF);

	lc_drbg_ctr_zero(out_state->rng_state);

	*drbg = out_state;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_drbg_ctr_no_df_alloc, struct lc_rng_ctx **drbg)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!drbg)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_SYM_COMMON_ALIGNMENT,
				      LC_DRBG_CTR_CTX_SIZE_NO_DF);
	if (ret)
		return -ret;

	LC_DRBG_CTR_RNG_CTX(out_state, 0, LC_DRBG_CTR_SCRATCHPAD_NO_DF);

	lc_drbg_ctr_zero(out_state->rng_state);

	*drbg = out_state;

	return 0;
}

static const struct lc_rng _lc_ctr_drbg = {
	.generate = lc_drbg_ctr_generate,
	.seed = lc_drbg_ctr_seed,
	.zero = lc_drbg_ctr_zero,
	.algorithm_type = LC_ALG_STATUS_CTR_DRBG,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_ctr_drbg) = &_lc_ctr_drbg;
