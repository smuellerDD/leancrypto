/* Double-Pipeline KDF - SP800-108
 *
 * Copyright (C) 2016 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_kdf_dpi.h"
#include "lc_memset_secure.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/PipelineModewithCounter.zip
 */
static void lc_kdf_dpi_selftest(int *tested, const char *impl)
{
	static const uint8_t key[] = { 0x3D, 0x36, 0x1A, 0x9F, 0x28, 0xAA,
				       0xD7, 0x22, 0xF6, 0x8E, 0xBD, 0xC2,
				       0x98, 0x43, 0x9D, 0xA1 };
	static const uint8_t label[] = { 0x40, 0x53, 0x44, 0xb2, 0xa4, 0xb8,
					 0x31, 0x64, 0xb0, 0x6e, 0xba, 0xc5,
					 0x42, 0x1b, 0xf1, 0x01, 0x83, 0xdc,
					 0x4e, 0x0f, 0x8c, 0x2e, 0x58, 0x72,
					 0x84, 0x72, 0xdd, 0xd5, 0xcc, 0xb1,
					 0x0b, 0xdf };
	static const uint8_t exp[] = { 0x34, 0x22, 0x68, 0x3b, 0x2d,
				       0x4b, 0xed, 0x1a, 0x05 };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_kdf_dpi(lc_sha256, key, sizeof(key), label, sizeof(label), act,
		   sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

LC_INTERFACE_FUNCTION(int, lc_kdf_dpi_generate, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *label, size_t labellen, uint8_t *dst,
		      size_t dlen)
{
	size_t h;
	uint8_t Ai[LC_SHA_MAX_SIZE_DIGEST];
	uint32_t i = 1;

	if (!hmac_ctx)
		return -EINVAL;

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	h = lc_hmac_macsize(hmac_ctx);
	memset(Ai, 0, h);

	/* Timecop: generated data is not sensitive for side-channels. */
	while (dlen) {
		uint32_t ibe = be_bswap32(i);

		/* Calculate A(i) */
		if (i == 1 && label && labellen) {
			/* 5.3 step 4 and 5.a */
			lc_hmac_update(hmac_ctx, label, labellen);
			lc_hmac_final(hmac_ctx, Ai);
			lc_hmac_reinit(hmac_ctx);
		} else {
			/* 5.3 step 5.a */
			lc_hmac_update(hmac_ctx, Ai, h);
			lc_hmac_final(hmac_ctx, Ai);
			lc_hmac_reinit(hmac_ctx);
		}

		/* Calculate K(i) -- step 5.b */
		lc_hmac_update(hmac_ctx, Ai, h);
		lc_hmac_update(hmac_ctx, (uint8_t *)&ibe, sizeof(uint32_t));

		if (label && labellen)
			lc_hmac_update(hmac_ctx, label, labellen);

		if (dlen < h) {
			uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

			lc_hmac_final(hmac_ctx, tmp);
			memcpy(dst, tmp, dlen);
			unpoison(dst, dlen);
			lc_memset_secure(tmp, 0, sizeof(tmp));

			goto out;
		} else {
			lc_hmac_final(hmac_ctx, dst);
			unpoison(dst, h);
			lc_hmac_reinit(hmac_ctx);

			dlen -= h;
			dst += h;
			i++;
		}
	}

out:
	lc_memset_secure(Ai, 0, h);
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_kdf_dpi_init, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *key, size_t keylen)
{
	static int tested = 0;

	/* Timecop: key is sensitive */
	poison(key, keylen);

	lc_kdf_dpi_selftest(&tested, "SP800-108 DPI KDF");
	lc_hmac_init(hmac_ctx, key, keylen);
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_kdf_dpi, const struct lc_hash *hash,
		      const uint8_t *key, size_t keylen, const uint8_t *label,
		      size_t labellen, uint8_t *dst, size_t dlen)
{
	int ret;
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	CKINT(lc_kdf_dpi_init(hmac_ctx, key, keylen));
	CKINT(lc_kdf_dpi_generate(hmac_ctx, label, labellen, dst, dlen));

out:
	lc_hmac_zero(hmac_ctx);
	return ret;
}
