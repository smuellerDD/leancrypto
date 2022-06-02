/* SP800-90A DRBG generic interface functions
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

#include "lc_drbg.h"
#include "visibility.h"

/*************************************************************************
 * DRBG interface functions
 *************************************************************************/
DSO_PUBLIC
int lc_drbg_seed(struct lc_drbg_state *drbg,
		 const uint8_t *seedbuf, size_t seedlen,
		 const uint8_t *persbuf, size_t perslen)
{
	struct lc_drbg_string seed;
	struct lc_drbg_string pers;

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

	drbg->drbg_int_seed(drbg, &seed);
	drbg->seeded = 1;

	return 0;
}

DSO_PUBLIC
ssize_t lc_drbg_generate(struct lc_drbg_state *drbg,
			 uint8_t *buf, size_t buflen,
			 const uint8_t *addtlbuf, size_t addtllen)
{
	struct lc_drbg_string addtl_data;
	struct lc_drbg_string *addtl = NULL;

	if (!drbg)
		return -EINVAL;

	if (!buflen || !buf)
		return -EINVAL;

	if (buflen > lc_drbg_max_request_bytes())
		return -EINVAL;

	if (addtllen > lc_drbg_max_addtl())
		return -EINVAL;

	if (addtlbuf && addtllen) {
		lc_drbg_string_fill(&addtl_data, addtlbuf, addtllen);
		addtl = &addtl_data;
	}

	return (ssize_t)drbg->drbg_int_generate(drbg, buf, buflen, addtl);
}

DSO_PUBLIC
void lc_drbg_zero_free(struct lc_drbg_state *drbg)
{
	if (!drbg)
		return;

	lc_drbg_zero(drbg);

	free(drbg);
}

DSO_PUBLIC
int lc_drbg_healthcheck_sanity(struct lc_drbg_state *drbg)
{
	unsigned char buf[16];
	size_t max_addtllen, max_request_bytes;
	ssize_t len = 0;
	int ret = -EFAULT;

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
	len = lc_drbg_generate(drbg, buf, sizeof(buf), buf, max_addtllen + 1);
	if (len > 0)
		goto out;

	/* overflow max_bits */
	len = lc_drbg_generate(drbg, buf, (max_request_bytes + 1), NULL, 0);
	if (len > 0)
		goto out;

	/* overflow max addtllen with personalization string */
	len = lc_drbg_generate(NULL, buf, sizeof(buf), NULL, 0);
	if (len >= 0)
		goto out;

	ret = 0;

out:
	lc_drbg_zero(drbg);
	return ret;
}
