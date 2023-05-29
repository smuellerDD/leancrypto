/* SP800-90A Hash DRBG generic code
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2022 - 2023
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
#include "bitshift_be.h"
#include "compare.h"
#include "lc_hash_drbg.h"
#include "math_helper.h"
#include "visibility.h"

static void drbg_hash_selftest(int *tested, const char *impl)
{
	static const uint8_t ent_nonce[] = {
		0x9E, 0x28, 0x52, 0xF1, 0xD8, 0xB2, 0x3C, 0x1A,
		0x80, 0xCA, 0x75, 0x29, 0x37, 0xAC, 0x58, 0x54,
		0x61, 0x98, 0xDB, 0x72, 0x81, 0xB7, 0x43, 0xDB,
		0x37, 0x21, 0x8E, 0x86, 0x40, 0x3B, 0x74, 0xF9,
		0x88, 0x45, 0x49, 0xDC, 0x49, 0x26, 0xBB, 0xAA,
		0x83, 0x3E, 0x50, 0x42, 0xA9, 0x52, 0xAE, 0x97,
		0xB2, 0x1B, 0x72, 0x93, 0x7C, 0xC7, 0x29, 0x5C,
		0x47, 0x2B, 0x70, 0xFB, 0xEC, 0xAC, 0xD9, 0x2C
	};
	static const uint8_t pers[] = {
		0x12, 0x6B, 0xE1, 0x49, 0x3F, 0x41, 0x28, 0x9A,
		0xDC, 0x5C, 0x7F, 0x00, 0x43, 0x40, 0xFF, 0x21,
		0xA7, 0xEC, 0x4D, 0xAD, 0xFF, 0xDA, 0x64, 0x2D,
		0xE4, 0x65, 0xAB, 0x2E, 0x98, 0x54, 0x19, 0x1A
	};
	static const uint8_t addtl1[] = {
		0x89, 0x18, 0x8A, 0xB5, 0x82, 0x0B, 0x05, 0x98,
		0xF9, 0x81, 0xB3, 0x34, 0x44, 0x6D, 0xD4, 0x38,
		0x29, 0xCD, 0x50, 0x4E, 0x06, 0xFE, 0x11, 0xF2,
		0x3C, 0x70, 0x0D, 0xAC, 0xA8, 0x28, 0x0E, 0x40
	};
	static const uint8_t addtl2[] = {
		0x67, 0x87, 0xEE, 0x02, 0xA6, 0x0F, 0x2F, 0x8D,
		0x8D, 0xF3, 0x4A, 0xBF, 0xA3, 0x61, 0x7E, 0xD6,
		0xB2, 0xB1, 0x37, 0x61, 0xA5, 0x41, 0xB3, 0x8C,
		0x2A, 0xF9, 0x01, 0x08, 0x3F, 0xC9, 0x0D, 0xCA
	};
	static const uint8_t exp[] = {
		0x4d, 0xa6, 0x34, 0x92, 0x52, 0x48, 0x31, 0x53,
		0x5c, 0x2d, 0xd8, 0xe9, 0xbd, 0x2f, 0x31, 0x9b,
		0x11, 0xc2, 0xda, 0x2f, 0xd7, 0x21, 0x05, 0xed,
		0x2c, 0x67, 0x04, 0x37, 0xbd, 0x53, 0xb3, 0x4e,
		0x9d, 0x0c, 0x16, 0x54, 0x89, 0xca, 0xe3, 0x39,
		0xc0, 0x77, 0xb3, 0xb5, 0xfa, 0xae, 0x9c, 0x59,
		0x90, 0x43, 0x09, 0x43, 0xf1, 0x4c, 0x70, 0x3e,
		0x00, 0x02, 0xa7, 0xf3, 0x13, 0x93, 0x98, 0xba,
		0x8b, 0xf4, 0xdf, 0x9e, 0x3f, 0x8d, 0x65, 0x0f,
		0x7a, 0x35, 0xd7, 0xa1, 0x4d, 0x13, 0x70, 0x50,
		0x01, 0xd8, 0x54, 0x26, 0x74, 0x2a, 0xdc, 0x35,
		0xb6, 0x59, 0xc2, 0xfb, 0x75, 0xfa, 0x47, 0x7c,
		0x06, 0x26, 0xfc, 0xcc, 0x20, 0xa0, 0x11, 0xc4,
		0xc4, 0xe8, 0xe5, 0x79, 0x33, 0x39, 0x30, 0x64,
		0xb3, 0x75, 0x7b, 0x2f, 0x04, 0x52, 0x0a, 0x60,
		0x41, 0x71, 0xcf, 0x3b, 0x1f, 0x30, 0x5b, 0x81,
		0x53, 0x2a, 0x26, 0xde, 0x3a, 0x4c, 0x5a, 0x64,
		0xe2, 0x29, 0x3e, 0x38, 0x8f, 0x8e, 0x1e, 0x76,
		0x08, 0xea, 0x81, 0x9e, 0x5d, 0x7b, 0x3a, 0xad,
		0x64, 0xc7, 0x1c, 0x32, 0x51, 0x9d, 0x67, 0xe3,
		0x75, 0x8f, 0x73, 0x23, 0x55, 0xbd, 0x1b, 0x70,
		0x9a, 0x8b, 0x8f, 0x5d, 0xcf, 0xe5, 0xac, 0x6d,
		0xc9, 0xf9, 0x48, 0xfc, 0xeb, 0xd6, 0x3a, 0x37,
		0x01, 0x4e, 0x6a, 0xae, 0x7b, 0x83, 0xf5, 0x13,
		0x22, 0x97, 0x2b, 0xc8, 0xd0, 0x9d, 0xd4, 0x91,
		0x18, 0xa1, 0x4b, 0x36, 0xf3, 0x0d, 0x3f, 0x4e,
		0x6d, 0x96, 0x8d, 0x79, 0xd8, 0xd7, 0xf0, 0x31,
		0x57, 0xf8, 0x32, 0x93, 0x10, 0xf6, 0xba, 0xab,
		0x57, 0xa6, 0xec, 0xb8, 0xbc, 0x9b, 0x0b, 0xef,
		0xa5, 0x00, 0x78, 0x7f, 0x63, 0x3e, 0x0f, 0x45,
		0x3b, 0x6d, 0xd9, 0xea, 0x58, 0xee, 0x29, 0x48,
		0xad, 0x33, 0xcb, 0x1b, 0xbf, 0xd1, 0x1d, 0x2a
	};
	uint8_t act[sizeof(exp)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(tested);

	LC_DRBG_HASH_CTX_ON_STACK(drbg_ctx);

	lc_rng_seed(drbg_ctx, ent_nonce, sizeof(ent_nonce), pers, sizeof(pers));
	lc_rng_generate(drbg_ctx, addtl1, sizeof(addtl1), act, sizeof(act));
	lc_rng_generate(drbg_ctx, addtl2, sizeof(addtl2), act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
	lc_rng_zero(drbg_ctx);
}

/***************************************************************
 * Hash invocations requested by DRBG
 ***************************************************************/

static void drbg_hash(struct lc_drbg_hash_state *drbg,
		      uint8_t *outval, const struct lc_drbg_string *in)
{
	lc_hash_init(&drbg->hash_ctx);
	for (; in != NULL; in = in->next)
		      lc_hash_update(&drbg->hash_ctx, in->buf, in->len);
	lc_hash_final(&drbg->hash_ctx, outval);
}

/******************************************************************
 * Hash DRBG callback functions
 ******************************************************************/

/*
 * Increment buffer
 *
 * @dst buffer to increment
 * @add value to add
 */
static void drbg_add_buf(uint8_t *dst, size_t dstlen,
			 const uint8_t *add, size_t addlen)
{
	/* implied: dstlen > addlen */
	uint8_t *dstptr;
	const uint8_t *addptr;
	unsigned int remainder = 0;
	size_t len = addlen;

	dstptr = dst + (dstlen-1);
	addptr = add + (addlen-1);
	while (len) {
		remainder += (unsigned int)(*dstptr + *addptr);
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--; addptr--;
	}
	len = dstlen - addlen;
	while (len && remainder > 0) {
		remainder = (unsigned int)(*dstptr + 1);
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--;
	}
}

/*
 * scratchpad usage: as drbg_hash_update and drbg_hash_df are used
 * interlinked, the scratchpad is used as follows:
 * drbg_hash_update
 *	start: drbg->scratchpad
 *	length: DRBG_STATELEN
 * drbg_hash_df:
 *	start: drbg->scratchpad + DRBG_STATELEN
 *	length: DRBG_BLOCKLEN
 *
 * drbg_hash_process_addtl uses the scratchpad, but fully completes
 * before either of the functions mentioned before are invoked. Therefore,
 * drbg_hash_process_addtl does not need to be specifically considered.
 */

/* Derivation Function for Hash DRBG as defined in 10.4.1 */
static void drbg_hash_df(struct lc_drbg_hash_state *drbg,
			 uint8_t *outval, size_t outlen,
			 struct lc_drbg_string *entropylist)
{
	size_t len = 0;
	unsigned char input[5];
	unsigned char *tmp = drbg->scratchpad + LC_DRBG_HASH_STATELEN;
	struct lc_drbg_string data;

	if (!outval || !tmp)
		return;

	/* 10.3.1 step 3 */
	input[0] = 1;
	/* Cast is appropriate as outlen is never larger than 2^16. */
	be32_to_ptr(&input[1], (uint32_t)(outlen * 8));

	/* 10.4.1 step 3.1 -- concatenation of data for input into hash */
	lc_drbg_string_fill(&data, input, 5);
	data.next = entropylist;

	/* 10.4.1 step 4 */
	while (len < outlen) {
		size_t blocklen = min_size(LC_DRBG_HASH_BLOCKLEN,
					   (outlen - len));

		/* shut up -Wstringop-overread */
		if (len + blocklen > outlen)

			break;

		/* shut up -Wstringop-overread */
		//memset(tmp, 0, LC_DRBG_HASH_BLOCKLEN);

		/* 10.3.1 step 4.1 */
		drbg_hash(drbg, tmp, &data);
		/* 10.3.1 step 4.2 */
		input[0]++;
		memcpy(outval + len, tmp, blocklen);
		len += blocklen;
	}

	memset(tmp, 0, LC_DRBG_HASH_BLOCKLEN);
}

/* update function for Hash DRBG as defined in 10.1.1.2 / 10.1.1.3 */
static void drbg_hash_update(struct lc_drbg_hash_state *drbg,
			     struct lc_drbg_string *seed)
{
	struct lc_drbg_string data1, data2;
	uint8_t *V = drbg->scratchpad;
	uint8_t prefix = DRBG_PREFIX1;

	if (drbg->seeded) {
		/* 10.1.1.3 step 1 */
		memcpy(V, drbg->V, LC_DRBG_HASH_STATELEN);
		lc_drbg_string_fill(&data1, &prefix, 1);
		lc_drbg_string_fill(&data2, V, LC_DRBG_HASH_STATELEN);
		data1.next = &data2;
		data2.next = seed;
	} else {
		      lc_drbg_string_fill(&data1, seed->buf, seed->len);
		data1.next = seed->next;
	}

	/* 10.1.1.2 / 10.1.1.3 step 2 and 3 */
	drbg_hash_df(drbg, drbg->V, LC_DRBG_HASH_STATELEN, &data1);

	/* 10.1.1.2 / 10.1.1.3 step 4  */
	prefix = DRBG_PREFIX0;
	lc_drbg_string_fill(&data1, &prefix, 1);
	lc_drbg_string_fill(&data2, drbg->V, LC_DRBG_HASH_STATELEN);
	data1.next = &data2;
	/* 10.1.1.2 / 10.1.1.3 step 4 */
	drbg_hash_df(drbg, drbg->C, LC_DRBG_HASH_STATELEN, &data1);

	memset(drbg->scratchpad, 0, LC_DRBG_HASH_STATELEN);
}

/* processing of additional information string for Hash DRBG */
static void drbg_hash_process_addtl(struct lc_drbg_hash_state *drbg,
				    struct lc_drbg_string *addtl)
{
	struct lc_drbg_string data1, data2;
	uint8_t prefix = DRBG_PREFIX2;

	/* 10.1.1.4 step 2 */
	if (!addtl || addtl->len == 0)
		return;

	/* 10.1.1.4 step 2a */
	lc_drbg_string_fill(&data1, &prefix, 1);
	lc_drbg_string_fill(&data2, drbg->V, LC_DRBG_HASH_STATELEN);
	data1.next = &data2;
	data2.next = addtl;
	addtl->next = NULL;
	drbg_hash(drbg, drbg->scratchpad, &data1);

	/* 10.1.1.4 step 2b */
	drbg_add_buf(drbg->V, LC_DRBG_HASH_STATELEN,
		     drbg->scratchpad, LC_DRBG_HASH_BLOCKLEN);

	memset(drbg->scratchpad, 0, LC_DRBG_HASH_BLOCKLEN);
}

/* Hashgen defined in 10.1.1.4 */
static void drbg_hash_hashgen(struct lc_drbg_hash_state *drbg,
			      uint8_t *buf, size_t buflen)
{
	struct lc_drbg_string data;
	size_t len = 0;
	uint8_t *src = drbg->scratchpad;
	uint8_t *dst = drbg->scratchpad + LC_DRBG_HASH_STATELEN;
	uint8_t prefix = DRBG_PREFIX1;

	/* 10.1.1.4 step hashgen 2 */
	memcpy(src, drbg->V, LC_DRBG_HASH_STATELEN);
	lc_drbg_string_fill(&data, src, LC_DRBG_HASH_STATELEN);

	while (len < buflen) {
		size_t outlen = 0;

		/* 10.1.1.4 step hashgen 4.1 */
		drbg_hash(drbg, dst, &data);
		outlen = (LC_DRBG_HASH_BLOCKLEN < (buflen - len)) ?
			  LC_DRBG_HASH_BLOCKLEN : (buflen - len);

		/* 10.1.1.4 step hashgen 4.2 */
		memcpy(buf + len, dst, outlen);
		len += outlen;
		/* 10.1.1.4 hashgen step 4.3 */
		if (len < buflen)
			drbg_add_buf(src, LC_DRBG_HASH_STATELEN, &prefix, 1);
	}

	memset(drbg->scratchpad, 0,
	       (LC_DRBG_HASH_STATELEN + LC_DRBG_HASH_BLOCKLEN));
}

/* generate function for Hash DRBG as defined in  10.1.1.4 */
static void drbg_hash_generate_internal(struct lc_drbg_hash_state *drbg,
					uint8_t *buf, size_t buflen,
					struct lc_drbg_string *addtl)
{
	struct lc_drbg_string data1, data2;
	uint8_t req[8], prefix = DRBG_PREFIX3;

	drbg->reseed_ctr++;

	/* 10.1.1.4 step 2 */
	drbg_hash_process_addtl(drbg, addtl);

	/* 10.1.1.4 step 3 */
	drbg_hash_hashgen(drbg, buf, buflen);

	/* this is the value H as documented in 10.1.1.4 */
	/* 10.1.1.4 step 4 */
	lc_drbg_string_fill(&data1, &prefix, 1);
	lc_drbg_string_fill(&data2, drbg->V, LC_DRBG_HASH_STATELEN);
	data1.next = &data2;
	drbg_hash(drbg, drbg->scratchpad, &data1);

	/* 10.1.1.4 step 5 */
	drbg_add_buf(drbg->V, LC_DRBG_HASH_STATELEN,
		     drbg->scratchpad, LC_DRBG_HASH_BLOCKLEN);
	drbg_add_buf(drbg->V, LC_DRBG_HASH_STATELEN,
		     drbg->C, LC_DRBG_HASH_STATELEN);
	be64_to_ptr(req, drbg->reseed_ctr);
	drbg_add_buf(drbg->V, LC_DRBG_HASH_STATELEN, req, sizeof(req));

	memset(drbg->scratchpad, 0, LC_DRBG_HASH_BLOCKLEN);
}

static int
lc_drbg_hash_generate(void *_state,
		      const uint8_t *addtl_input, size_t addtl_input_len,
		      uint8_t *out, size_t outlen)
{
	struct lc_drbg_hash_state *drbg_hash = _state;
	struct lc_drbg_string addtl_data;
	struct lc_drbg_string *addtl = NULL;

	if (!drbg_hash)
		return -EINVAL;

	if (outlen > lc_drbg_max_request_bytes())
		return -EINVAL;

	if (addtl_input_len > lc_drbg_max_addtl())
		return -EINVAL;

	if (addtl_input_len && addtl_input) {
		lc_drbg_string_fill(&addtl_data, addtl_input, addtl_input_len);
		addtl = &addtl_data;
	}
	drbg_hash_generate_internal(drbg_hash, out, outlen, addtl);

	return 0;
}

static int
lc_drbg_hash_seed(void *_state,
		  const uint8_t *seedbuf, size_t seedlen,
		  const uint8_t *persbuf, size_t perslen)
{
	struct lc_drbg_hash_state *drbg_hash = _state;
	struct lc_drbg_string seed;
	struct lc_drbg_string pers;
	static int tested = 0;

	if (!drbg_hash)
		return -EINVAL;

	drbg_hash_selftest(&tested, "Hash DRBG");

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

	drbg_hash_update(drbg_hash, &seed);
	drbg_hash->seeded = 1;

	/*
	 * 10.1.1.2 / 10.1.1.3 step 5 - set reseed counter to 0 instead of 1
	 * as the drbg_generate function increments it before the generate
	 * operation.
	 */
	drbg_hash->reseed_ctr = 0;

	return 0;
}

static void lc_drbg_hash_zero(void *_state)
{
	struct lc_drbg_hash_state *drbg_hash = _state;

	if (!drbg_hash)
		return;

	drbg_hash->reseed_ctr = 0;
	drbg_hash->seeded = 0;
	lc_memset_secure(drbg_hash->hash_state, 0,
			 sizeof(drbg_hash->hash_state));
	lc_memset_secure(drbg_hash->V, 0, sizeof(drbg_hash->V));
	lc_memset_secure(drbg_hash->C, 0, sizeof(drbg_hash->C));
	lc_memset_secure(drbg_hash->scratchpad, 0,
			 sizeof(drbg_hash->scratchpad));
}

LC_INTERFACE_FUNCTION(
int, lc_drbg_hash_alloc, struct lc_rng_ctx **drbg)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!drbg)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_DRBG_HASH_CTX_SIZE);
	if (ret)
		return -ret;

	LC_DRBG_HASH_RNG_CTX(out_state);

	lc_drbg_hash_zero(out_state->rng_state);

	*drbg = out_state;

	return 0;
}

LC_INTERFACE_FUNCTION(
int, lc_drbg_hash_healthcheck_sanity, struct lc_rng_ctx *drbg)
{
	unsigned char buf[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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

static const struct lc_rng _lc_hash_drbg = {
	.generate	= lc_drbg_hash_generate,
	.seed		= lc_drbg_hash_seed,
	.zero		= lc_drbg_hash_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_hash_drbg) = &_lc_hash_drbg;
