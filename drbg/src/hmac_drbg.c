/* SP800-90A HMAC DRBG generic code
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2022
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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "lc_hmac_drbg_sha512.h"
#include "visibility.h"

/***************************************************************
 * Hash invocations requested by DRBG
 ***************************************************************/

static void drbg_hmac(struct lc_drbg_hmac_state *drbg, uint8_t *key,
		      uint8_t *outval, const struct lc_drbg_string *in)
{
	lc_hmac_init(&drbg->hmac_ctx, key, LC_DRBG_HMAC_STATELEN);
	for (; in != NULL; in = in->next)
		      lc_hmac_update(&drbg->hmac_ctx, in->buf, in->len);
	lc_hmac_final(&drbg->hmac_ctx, outval);
}

/******************************************************************
 * HMAC DRBG callback functions
 ******************************************************************/

/* update function of HMAC DRBG as defined in 10.1.2.2 */
static void drbg_hmac_update(struct lc_drbg_hmac_state *drbg,
			     struct lc_drbg_string *seed)
{
	int i = 0;
	struct lc_drbg_string seed1, seed2, vdata;

	if (!drbg->drbg.seeded)
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
		drbg_hmac(drbg, drbg->C, drbg->C, &seed1);

		/* 10.1.2.2 step 2 and 5 -- HMAC for V */
		drbg_hmac(drbg, drbg->C, drbg->V, &vdata);

		/* 10.1.2.2 step 3 */
		if (!seed)
			return;
	}
}

/* generate function of HMAC DRBG as defined in 10.1.2.5 */
static size_t drbg_hmac_generate_internal(struct lc_drbg_hmac_state *drbg,
					  uint8_t *buf, size_t buflen,
					  struct lc_drbg_string *addtl)
{
	size_t len = 0;
	struct lc_drbg_string data;

	/* 10.1.2.5 step 2 */
	if (addtl && addtl->len > 0)
		drbg_hmac_update(drbg, addtl);

	lc_drbg_string_fill(&data, drbg->V, LC_DRBG_HMAC_STATELEN);
	while (len < buflen) {
		size_t outlen = 0;

		/* 10.1.2.5 step 4.1 */
		drbg_hmac(drbg, drbg->C, drbg->V, &data);

		outlen = (LC_DRBG_HMAC_BLOCKLEN < (buflen - len)) ?
			  LC_DRBG_HMAC_BLOCKLEN : (buflen - len);

		/* 10.1.2.5 step 4.2 */
		memcpy(buf + len, drbg->V, outlen);
		len += outlen;
	}

	/* 10.1.2.5 step 6 */
	if (addtl)
		addtl->next = NULL;
	drbg_hmac_update(drbg, addtl);

	return len;
}

DSO_PUBLIC
size_t lc_drbg_hmac_generate(struct lc_drbg_state *drbg,
			     uint8_t *buf, size_t buflen,
			     struct lc_drbg_string *addtl)
{
	struct lc_drbg_hmac_state *drbg_hmac = (struct lc_drbg_hmac_state *)drbg;

	return drbg_hmac_generate_internal(drbg_hmac, buf, buflen, addtl);
}

DSO_PUBLIC
void lc_drbg_hmac_seed(struct lc_drbg_state *drbg, struct lc_drbg_string *seed)
{
	struct lc_drbg_hmac_state *drbg_hmac = (struct lc_drbg_hmac_state *)drbg;

	drbg_hmac_update(drbg_hmac, seed);
}

DSO_PUBLIC
void lc_drbg_hmac_zero(struct lc_drbg_state *drbg)
{
	struct lc_drbg_hmac_state *drbg_hmac = (struct lc_drbg_hmac_state *)drbg;
	struct lc_hmac_ctx *hmac_ctx = &drbg_hmac->hmac_ctx;
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)drbg_hmac + sizeof(struct lc_drbg_hmac_state),
				 0, LC_DRBG_HMAC_STATE_SIZE(hash));
}

DSO_PUBLIC
int lc_drbg_hmac_alloc(struct lc_drbg_state **drbg)
{
	struct lc_drbg_hmac_state *tmp;
	int ret = posix_memalign((void *)&tmp, sizeof(uint64_t),
				 LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE));

	if (ret)
		return -ret;
	memset(tmp, 0, LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE));

	LC_DRBG_HMAC_SET_CTX(tmp);

	*drbg = (struct lc_drbg_state *)tmp;

	return 0;
}
