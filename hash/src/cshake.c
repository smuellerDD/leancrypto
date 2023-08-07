/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "lc_cshake.h"
#include "lc_sha3.h"
#include "left_encode.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_cshake_init, struct lc_hash_ctx *ctx,
		      const uint8_t *n, size_t nlen, const uint8_t *s,
		      size_t slen)
{
	static const uint8_t zero[LC_SHAKE_128_SIZE_BLOCK] = { 0 };
	static const uint8_t bytepad_val256[] = { 0x01,
						  LC_SHAKE_256_SIZE_BLOCK },
			     bytepad_val128[] = { 0x01,
						  LC_SHAKE_128_SIZE_BLOCK };
	uint8_t buf[sizeof(nlen) + 1];
	size_t len;
	/* 2 bytes for the bytepad_val that gets inserted */
	size_t added = 2;
	int shake128 =
		(lc_hash_blocksize(ctx) == LC_SHAKE_128_SIZE_BLOCK) ? 1 : 0;

	if (!ctx)
		return;

	/*
	 * When invoked without any additional values, it should operate as a
	 * regular SHAKE as defined in SP800-185 section 3.3. So, change the
	 * algorithm backend accordingly and initialize it.
	 */
	if (!nlen && !slen) {
		LC_HASH_SET_CTX(ctx, shake128 ? lc_shake128 : lc_shake256);
		lc_hash_init(ctx);
		return;
	}

	lc_hash_init(ctx);

	/* bytepad value */
	//len = left_encode(buf, hash_blocksize(ctx));
	//padlen -= len;
	//hash_update(ctx, buf, len);
	if (shake128)
		lc_hash_update(ctx, bytepad_val128, sizeof(bytepad_val128));
	else
		lc_hash_update(ctx, bytepad_val256, sizeof(bytepad_val256));

	/* encode_string n */
	len = lc_left_encode(buf, nlen << 3);
	added += len;
	lc_hash_update(ctx, buf, len);
	lc_hash_update(ctx, n, nlen);
	added += nlen;

	/* encode_string s */
	len = lc_left_encode(buf, slen << 3);
	added += len;
	lc_hash_update(ctx, buf, len);
	lc_hash_update(ctx, s, slen);
	added += slen;

	/* bytepad pad */
	len = (added % lc_hash_blocksize(ctx));
	if (len)
		lc_hash_update(ctx, zero, lc_hash_blocksize(ctx) - len);
}
