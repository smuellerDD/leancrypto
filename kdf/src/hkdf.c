/* RFC 5869 HKDF
 *
 * Copyright (C) 2016 - 2022, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "lc_hkdf.h"
#include "memset_secure.h"
#include "visibility.h"

DSO_PUBLIC
int lc_hkdf_extract(struct lc_hmac_ctx *hmac_ctx,
		    const uint8_t *ikm, size_t ikmlen,
		    const uint8_t *salt, size_t saltlen)
{
	size_t h = lc_hmac_macsize(hmac_ctx);
	const uint8_t null_salt[LC_SHA_MAX_SIZE_DIGEST] = { 0 };
	uint8_t prk_tmp[LC_SHA_MAX_SIZE_DIGEST];

	if (!ikm || !ikmlen)
		return -EINVAL;

	/* Extract phase */
	if (salt)
		lc_hmac_init(hmac_ctx, salt, saltlen);
	else
		lc_hmac_init(hmac_ctx, null_salt, h);

	lc_hmac_update(hmac_ctx, ikm, ikmlen);
	lc_hmac_final(hmac_ctx, prk_tmp);

	/* Prepare for expand phase */
	lc_hmac_init(hmac_ctx, prk_tmp, h);

	memset_secure(prk_tmp, 0, h);

	return 0;
}

DSO_PUBLIC
int lc_hkdf_expand(struct lc_hmac_ctx *hmac_ctx,
		   const uint8_t *info, size_t infolen,
		   uint8_t *dst, size_t dlen)
{
	size_t h = lc_hmac_macsize(hmac_ctx);
	uint8_t *prev = NULL;
	uint8_t ctr = 0x01;

	if (dlen > h * 255)
		return -EINVAL;

	/* Expand phase - expects a HMAC handle from the extract phase */

	/* T(1) and following */
	while (dlen) {
		if (prev)
			lc_hmac_update(hmac_ctx, prev, h);

		if (info)
			lc_hmac_update(hmac_ctx, info, infolen);

		lc_hmac_update(hmac_ctx, &ctr, 1);

		if (dlen < h) {
			uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

			lc_hmac_final(hmac_ctx, tmp);
			if (dst)
				memcpy(dst, tmp, dlen);
			memset_secure(tmp, 0, h);

			goto out;
		} else {
			lc_hmac_final(hmac_ctx, dst);
			lc_hmac_reinit(hmac_ctx);

			prev = dst;
			dst += h;
			dlen -= h;
			ctr++;
		}
	}

out:
	lc_hmac_zero(hmac_ctx);
	return 0;
}
