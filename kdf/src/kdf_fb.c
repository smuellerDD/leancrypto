/* Feedback-Mode KDF - SP800-108
 *
 * Copyright (C) 2016 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "conv_be_le.h"
#include "ext_headers.h"
#include "lc_hmac.h"
#include "lc_kdf_fb.h"
#include "lc_memset_secure.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "visibility.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/FeedbackModeNOzeroiv.zip
 */
static void lc_kdf_fb_selftest(int *tested, const char *impl)
{
	static const uint8_t key[] = {
		0x51, 0x5D, 0x42, 0x18, 0x50, 0x32, 0xD6, 0x3D,
		0x41, 0x89, 0x23, 0x71, 0xB6, 0x66, 0xC0, 0xA3
	};
	static const uint8_t iv[] = {
		0x83, 0xAE, 0xC4, 0x0E, 0xC6, 0x5F, 0xE2, 0x0B,
		0x49, 0x4A, 0x88, 0x56, 0x1B, 0xDA, 0x5C, 0x69,
		0x22, 0xF7, 0xBF, 0x6A, 0x4F, 0xD9, 0x4F, 0x19,
		0x9D, 0x87, 0x84, 0xC0, 0xC0, 0x63, 0x6C, 0xCB
	};
	static const uint8_t label[] = {
		0x5e, 0xdb, 0xe4, 0x27, 0xd9, 0x31, 0x90, 0xdf,
		0xac, 0x0e, 0x4b, 0x79, 0x0c, 0x5d, 0x77, 0xab,
		0x66, 0xd6, 0xe9, 0xee, 0x81, 0x92, 0x7c, 0x85,
		0x6b, 0x92, 0xbb, 0x99, 0xc2, 0x62, 0x35, 0xb0
	};
	static const uint8_t exp[] = {
		0xaa
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_kdf_fb(lc_sha256, key, sizeof(key), iv, sizeof(iv),
		  label, sizeof(label), act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

LC_INTERFACE_FUNCTION(
int, lc_kdf_fb_generate, struct lc_hmac_ctx *hmac_ctx,
			 const uint8_t *iv, size_t ivlen,
			 const uint8_t *label, size_t labellen,
			 uint8_t *dst, size_t dlen)
{
	size_t h;
	uint32_t i = 1;

	if (!hmac_ctx)
		return -EINVAL;

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	h = lc_hmac_macsize(hmac_ctx);

	/* require the presence of an IV */
	if (ivlen != h)
		return -EINVAL;

	while (dlen) {
		uint32_t ibe = be_bswap32(i);

		/*
		 * Feedback mode applies to all rounds except first which uses
		 * the IV.
		 */
		if (i == 1)
			lc_hmac_update(hmac_ctx, iv, ivlen);
		else
			lc_hmac_update(hmac_ctx, dst - h, h);

		lc_hmac_update(hmac_ctx, (uint8_t *)&ibe, sizeof(uint32_t));

		if (labellen)
			lc_hmac_update(hmac_ctx, label, labellen);

		if (dlen < h) {
			uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

			lc_hmac_final(hmac_ctx, tmp);
			memcpy(dst, tmp, dlen);
			lc_memset_secure(tmp, 0, sizeof(tmp));

			goto out;
		} else {
			lc_hmac_final(hmac_ctx, dst);
			lc_hmac_reinit(hmac_ctx);

			dlen -= h;
			dst += h;
			i++;
		}
	}

out:
	return 0;
}

LC_INTERFACE_FUNCTION(
int, lc_kdf_fb_init, struct lc_hmac_ctx *hmac_ctx,
		     const uint8_t *key, size_t keylen)
{
	static int tested = 0;

	lc_kdf_fb_selftest(&tested, "SP800-108 FB KDF");
	lc_hmac_init(hmac_ctx, key, keylen);
	return 0;
}


LC_INTERFACE_FUNCTION(
int, lc_kdf_fb, const struct lc_hash *hash,
		const uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen,
		const uint8_t *label, size_t labellen,
		uint8_t *dst, size_t dlen)
{
	int ret;
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	CKINT(lc_kdf_fb_init(hmac_ctx, key, keylen));
	CKINT(lc_kdf_fb_generate(hmac_ctx, iv, ivlen, label, labellen,
				 dst, dlen));

out:
	lc_hmac_zero(hmac_ctx);
	return ret;
}
