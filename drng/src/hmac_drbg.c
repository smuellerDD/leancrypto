/* SP800-90A HMAC DRBG generic code
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2022 - 2025
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
#include "compare.h"
#include "fips_mode.h"
#include "lc_hmac_drbg_sha512.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "visibility.h"

static int lc_drbg_hmac_seed_nocheck(void *_state, const uint8_t *seedbuf,
				     size_t seedlen, const uint8_t *persbuf,
				     size_t perslen);

static void drbg_hmac_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t ent_nonce[] = { FIPS140_MOD(0xC5),
					     0xD9,
					     0xD7,
					     0x7B,
					     0x3E,
					     0x5C,
					     0x0E,
					     0xC8,
					     0x57,
					     0x13,
					     0xEB,
					     0x25,
					     0x12,
					     0xE8,
					     0x15,
					     0x40,
					     0xBF,
					     0x65,
					     0x89,
					     0x15,
					     0xB3,
					     0xF9,
					     0xC8,
					     0x95,
					     0x22,
					     0x05,
					     0xB5,
					     0xF0,
					     0x16,
					     0x0F,
					     0xD0,
					     0xE8,
					     0xBD,
					     0xA7,
					     0xC6,
					     0x58,
					     0xE2,
					     0x4D,
					     0xB8,
					     0xBD,
					     0xFC,
					     0xC5,
					     0x4E,
					     0x3A,
					     0xFE,
					     0xAA,
					     0xB5,
					     0x79,
					     0x71,
					     0xD4,
					     0x95,
					     0x4D,
					     0xD9,
					     0x98,
					     0x38,
					     0x34,
					     0x28,
					     0xF2,
					     0x1A,
					     0x34,
					     0x2D,
					     0xE8,
					     0xC9,
					     0x74 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t pers[] = { 0x6E, 0xCF, 0x0F, 0xCC, 0x7C, 0x6F,
					0xEC, 0x03, 0x25, 0x8B, 0xDB, 0x2D,
					0xC5, 0xC5, 0xEB, 0x39, 0x33, 0x09,
					0x39, 0x53, 0xED, 0xDD, 0xC0, 0x23,
					0x26, 0x8A, 0x38, 0xA0, 0x4C, 0x3F,
					0x33, 0xEE };
	LC_FIPS_RODATA_SECTION
	static const uint8_t addtl1[] = { 0xB5, 0x18, 0x81, 0x4D, 0xC6, 0xF8,
					  0x71, 0x03, 0x63, 0x5A, 0xCA, 0x88,
					  0xE2, 0xB6, 0x57, 0x13, 0x22, 0x0D,
					  0xE9, 0x28, 0xAD, 0x86, 0x01, 0x6C,
					  0xAE, 0xE9, 0x0C, 0x5C, 0x79, 0x41,
					  0x55, 0xB5 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t addtl2[] = { 0xEB, 0x61, 0x23, 0x14, 0xEA, 0x75,
					  0xDE, 0xFB, 0xEA, 0x48, 0x46, 0xA2,
					  0x2D, 0x5B, 0x3A, 0xDD, 0xE2, 0x30,
					  0x44, 0xFD, 0xD0, 0xB4, 0xD5, 0xE9,
					  0xEE, 0xC2, 0xF1, 0x1D, 0x58, 0xF9,
					  0x11, 0x9E };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp[] = {
		0xb6, 0xb5, 0x4e, 0x7d, 0x8c, 0x62, 0xfe, 0x73, 0x64, 0x0d,
		0x57, 0xb4, 0xb5, 0x87, 0x05, 0x12, 0xe7, 0x62, 0xa8, 0x2d,
		0x86, 0xb8, 0x2b, 0xf3, 0x22, 0x66, 0x7e, 0x93, 0x93, 0x45,
		0x88, 0x30, 0xea, 0x2f, 0xbf, 0xba, 0x8f, 0xe7, 0xed, 0x2a,
		0xb2, 0x08, 0x55, 0x37, 0x63, 0x6e, 0xec, 0x1e, 0xe1, 0xdf,
		0x03, 0x60, 0xf0, 0xc0, 0x92, 0x30, 0x21, 0xdd, 0xff, 0x42,
		0xca, 0x5d, 0x7d, 0x67, 0xce, 0x74, 0xc8, 0x6b, 0xad, 0x20,
		0x75, 0xa8, 0xc3, 0xc0, 0x01, 0x98, 0xa1, 0x38, 0x31, 0x2d,
		0xd0, 0x83, 0x75, 0x17, 0x4c, 0x52, 0x5f, 0xed, 0x8a, 0xbc,
		0xa4, 0x0e, 0xd4, 0x4d, 0x0a, 0x32, 0x44, 0x00, 0xbe, 0x5d,
		0x57, 0xb3, 0x11, 0xa0, 0x32, 0x30, 0x49, 0xd8, 0xd3, 0xe9,
		0x35, 0xb6, 0x3b, 0x27, 0x81, 0xb0, 0x82, 0xf8, 0x19, 0x13,
		0xc5, 0xbc, 0x2f, 0xdc, 0x87, 0xcd, 0x92, 0xd2, 0xa7, 0xb2,
		0xe0, 0x8f, 0xcf, 0x79, 0x20, 0x15, 0x5f, 0x40, 0x47, 0xb6,
		0x7c, 0xe5, 0x6c, 0x7a, 0x6c, 0xe6, 0xb9, 0xba, 0x1b, 0x86,
		0x55, 0x1a, 0xc2, 0xc2, 0xf8, 0x3a, 0xd8, 0xd7, 0xa7, 0xe3,
		0x3c, 0x86, 0xa3, 0xe1, 0x88, 0x0f, 0x5c, 0x1e, 0x79, 0xa6,
		0x14, 0x58, 0x9e, 0x22, 0x22, 0xc2, 0x40, 0xf1, 0x93, 0x4b,
		0xb3, 0x3a, 0x25, 0x4e, 0xc2, 0xeb, 0x0d, 0x04, 0xde, 0xc1,
		0xe2, 0x46, 0x85, 0x6e, 0x65, 0x92, 0xa9, 0x24, 0x44, 0x87,
		0xd1, 0x42, 0x4c, 0x54, 0x71, 0xfb, 0xd7, 0x72, 0x84, 0xa5,
		0x64, 0x41, 0x57, 0x74, 0xb6, 0x01, 0xd7, 0x76, 0x4e, 0x66,
		0x86, 0x60, 0x3a, 0xa5, 0x14, 0x55, 0x5d, 0x5a, 0x56, 0xc4,
		0xb2, 0x82, 0xf9, 0xcd, 0x73, 0x7b, 0xb6, 0xe4, 0xac, 0xe5,
		0x46, 0x74, 0x10, 0xeb, 0x9f, 0x0d, 0x22, 0xf0, 0x94, 0xeb,
		0x09, 0x0f, 0x8e, 0x8d, 0x7f, 0x09
	};
	uint8_t act[sizeof(exp)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(lc_hmac_drbg->algorithm_type);

	LC_DRBG_HMAC_CTX_ON_STACK(drbg_ctx);

	if (lc_drbg_hmac_seed_nocheck(drbg_ctx->rng_state, ent_nonce,
				      sizeof(ent_nonce), pers, sizeof(pers)))
		goto out;
	lc_rng_generate(drbg_ctx, addtl1, sizeof(addtl1), act, sizeof(act));
	lc_rng_generate(drbg_ctx, addtl2, sizeof(addtl2), act, sizeof(act));

out:
	lc_compare_selftest(lc_hmac_drbg->algorithm_type, act, exp, sizeof(exp),
			    "HMAC DRBG");
	lc_rng_zero(drbg_ctx);
}

/***************************************************************
 * Hash invocations requested by DRBG
 ***************************************************************/

static int drbg_hmac(struct lc_drbg_hmac_state *drbg, uint8_t *key,
		     uint8_t *outval, const struct lc_drbg_string *in)
{
	int ret = lc_hmac_init(&drbg->hmac_ctx, key, LC_DRBG_HMAC_STATELEN);

	if (ret)
		return ret;
	for (; in != NULL; in = in->next)
		lc_hmac_update(&drbg->hmac_ctx, in->buf, in->len);
	lc_hmac_final(&drbg->hmac_ctx, outval);

	return 0;
}

/******************************************************************
 * HMAC DRBG callback functions
 ******************************************************************/

/* update function of HMAC DRBG as defined in 10.1.2.2 */
static int drbg_hmac_update(struct lc_drbg_hmac_state *drbg,
			    struct lc_drbg_string *seed)
{
	int ret, i = 0;
	struct lc_drbg_string seed1, seed2, vdata;

	if (!drbg->seeded)
		/* 10.1.2.3 step 2 -- memset(0) of C is implicit with calloc */
		memset(drbg->V, 1, LC_DRBG_HMAC_STATELEN);

	lc_drbg_string_fill(&seed1, drbg->V, LC_DRBG_HMAC_STATELEN);
	/* buffer of seed2 will be filled in for loop below with one byte */
	lc_drbg_string_fill(&seed2, NULL, 1);
	seed1.next = &seed2;
	/* input data of seed is allowed to be NULL at this point */
	seed2.next = seed;

	lc_drbg_string_fill(&vdata, drbg->V, LC_DRBG_HMAC_STATELEN);
	for (i = 2; 0 < i; i--) {
		/* first round uses 0x0, second 0x1 */
		uint8_t prefix = DRBG_PREFIX0;

		if (1 == i)
			prefix = DRBG_PREFIX1;
		/* 10.1.2.2 step 1 and 4 -- concatenation and HMAC for key */
		seed2.buf = &prefix;
		CKINT(drbg_hmac(drbg, drbg->C, drbg->C, &seed1));

		/* 10.1.2.2 step 2 and 5 -- HMAC for V */
		CKINT(drbg_hmac(drbg, drbg->C, drbg->V, &vdata));

		/* 10.1.2.2 step 3 */
		CKNULL(seed, 0);
	}

out:
	return ret;
}

/* generate function of HMAC DRBG as defined in 10.1.2.5 */
static int drbg_hmac_generate_internal(struct lc_drbg_hmac_state *drbg,
				       uint8_t *buf, size_t buflen,
				       struct lc_drbg_string *addtl)
{
	struct lc_drbg_string data;
	int ret = 0;

	/* 10.1.2.5 step 2 */
	if (addtl && addtl->len > 0)
		CKINT(drbg_hmac_update(drbg, addtl));

	lc_drbg_string_fill(&data, drbg->V, LC_DRBG_HMAC_STATELEN);

	while (buflen) {
		size_t todo = min_size(LC_DRBG_MAX_REQUEST_BYTES, buflen);
		size_t len = 0;

		while (len < buflen) {
			size_t outlen = 0;

			/* 10.1.2.5 step 4.1 */
			CKINT(drbg_hmac(drbg, drbg->C, drbg->V, &data));

			outlen = (LC_DRBG_HMAC_BLOCKLEN < (buflen - len)) ?
					 LC_DRBG_HMAC_BLOCKLEN :
					 (buflen - len);

			/* 10.1.2.5 step 4.2 */
			memcpy(buf + len, drbg->V, outlen);
			len += outlen;
		}

		/* 10.1.2.5 step 6 */
		if (addtl)
			addtl->next = NULL;
		drbg_hmac_update(drbg, addtl);

		buf += todo;
		buflen -= todo;
	}

out:
	return ret;
}

static int lc_drbg_hmac_generate(void *_state, const uint8_t *addtl_input,
				 size_t addtl_input_len, uint8_t *out,
				 size_t outlen)
{
	struct lc_drbg_hmac_state *drbg_hmac = _state;
	struct lc_drbg_string addtl_data;
	struct lc_drbg_string *addtl = NULL;

	if (!drbg_hmac)
		return -EINVAL;

	if (outlen > lc_drbg_max_request_bytes())
		return -EINVAL;

	if (addtl_input_len > lc_drbg_max_addtl())
		return -EINVAL;

	if (addtl_input_len && addtl_input) {
		lc_drbg_string_fill(&addtl_data, addtl_input, addtl_input_len);
		addtl = &addtl_data;
	}

	return drbg_hmac_generate_internal(drbg_hmac, out, outlen, addtl);
}

static int lc_drbg_hmac_seed_nocheck(void *_state, const uint8_t *seedbuf,
				     size_t seedlen, const uint8_t *persbuf,
				     size_t perslen)
{
	struct lc_drbg_hmac_state *drbg_hmac = _state;
	struct lc_drbg_string seed;
	struct lc_drbg_string pers;

	if (!drbg_hmac)
		return -EINVAL;

	/* 9.1 / 9.2 / 9.3.1 step 3 */
	if (persbuf && perslen > (lc_drbg_max_addtl()))
		return -EINVAL;

	if (!seedbuf || !seedlen)
		return -EINVAL;
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

	drbg_hmac_update(drbg_hmac, &seed);
	drbg_hmac->seeded = 1;

	return 0;
}

static int lc_drbg_hmac_seed(void *_state, const uint8_t *seedbuf,
			     size_t seedlen, const uint8_t *persbuf,
			     size_t perslen)
{
	drbg_hmac_selftest();
	LC_SELFTEST_COMPLETED(lc_hmac_drbg->algorithm_type);

	return lc_drbg_hmac_seed_nocheck(_state, seedbuf, seedlen, persbuf,
					 perslen);
}

static void lc_drbg_hmac_zero(void *_state)
{
	struct lc_drbg_hmac_state *drbg_hmac = _state;

	if (!drbg_hmac)
		return;

	drbg_hmac->seeded = 0;
	lc_memset_secure((uint8_t *)drbg_hmac +
				 sizeof(struct lc_drbg_hmac_state),
			 0, LC_DRBG_HMAC_STATE_SIZE);
}

LC_INTERFACE_FUNCTION(int, lc_drbg_hmac_alloc, struct lc_rng_ctx **drbg)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!drbg)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_DRBG_HMAC_CTX_SIZE);

	if (ret)
		return -ret;

	LC_DRBG_HMAC_RNG_CTX(out_state);

	lc_drbg_hmac_zero(out_state->rng_state);

	*drbg = out_state;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_drbg_hmac_healthcheck_sanity,
		      struct lc_rng_ctx *drbg)
{
	unsigned char buf[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	size_t max_addtllen, max_request_bytes;
	ssize_t len = 0;
	int ret = -EFAULT;

	if (!drbg)
		return -EINVAL;

	/*
	 * if the following tests fail, it is likely that there is a buffer
	 * overflow as buf is much smaller than the requested or provided
	 * string lengths -- in case the error handling does not succeed
	 * we may get an OOPS. And we want to get an OOPS as this is a
	 * grave bug.
	 */

	max_addtllen = lc_drbg_max_addtl();
	max_request_bytes = lc_drbg_max_request_bytes();

	/* overflow addtllen with additonal info string */
	len = lc_rng_generate(drbg, buf, max_addtllen + 1, buf, sizeof(buf));
	if (len >= 0)
		goto out;

	/* overflow max_bits */
	len = lc_rng_generate(drbg, NULL, 0, buf, (max_request_bytes + 1));
	if (len >= 0)
		goto out;

	/* overflow max addtllen with personalization string */
	len = lc_rng_generate(NULL, NULL, 0, buf, sizeof(buf));
	if (len >= 0)
		goto out;

	ret = 0;

out:
	lc_rng_zero(drbg);
	return ret;
}

static const struct lc_rng _lc_hmac_drbg = {
	.generate = lc_drbg_hmac_generate,
	.seed = lc_drbg_hmac_seed,
	.zero = lc_drbg_hmac_zero,
	.algorithm_type = LC_ALG_STATUS_HMAC_DRBG,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_hmac_drbg) = &_lc_hmac_drbg;
