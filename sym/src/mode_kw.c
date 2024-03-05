/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "aes_c.h"
#include "aes_internal.h"
#include "bitshift.h"
#include "compare.h"
#include "conv_be_le.h"
#include "ext_headers.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "lc_memset_secure.h"
#include "mode_kw.h"
#include "visibility.h"

#define AES_KW_SEMIBSIZE 8U
#define AES_KW_IV 0xa6a6a6a6a6a6a6a6ULL

struct aes_kw_block {
	uint64_t A;
	uint64_t R;
};

#define LC_AES_KW_BLOCK_SIZE sizeof(struct lc_mode_state)

void mode_kw_selftest(const struct lc_sym *aes, int *tested, const char *impl)
{
	static const uint8_t key256[] = { 0x80, 0xaa, 0x99, 0x73, 0x27, 0xa4,
					  0x80, 0x6b, 0x6a, 0x7a, 0x41, 0xa5,
					  0x2b, 0x86, 0xc3, 0x71, 0x03, 0x86,
					  0xf9, 0x32, 0x78, 0x6e, 0xf7, 0x96,
					  0x76, 0xfa, 0xfb, 0x90, 0xb8, 0x26,
					  0x3c, 0x5f };
	static const uint8_t in[] = { 0x0a, 0x25, 0x6b, 0xa7, 0x5c, 0xfa,
				      0x03, 0xaa, 0xa0, 0x2b, 0xa9, 0x42,
				      0x03, 0xf1, 0x5b, 0xaa };
	static const uint8_t out256[] = { 0xd3, 0x3d, 0x3d, 0x97, 0x7b, 0xf0,
					  0xa9, 0x15, 0x59, 0xf9, 0x9c, 0x8a,
					  0xcd, 0x29, 0x3d, 0x43 };
	static const uint8_t iv[] = { 0x42, 0x3c, 0x96, 0x0d,
				      0x8a, 0x2a, 0xc4, 0xc1 };

	uint8_t out[sizeof(in)];
	char status[25];

	LC_SELFTEST_RUN(tested);

	LC_SYM_CTX_ON_STACK(ctx, aes);

	lc_sym_init(ctx);
	lc_sym_setkey(ctx, key256, sizeof(key256));
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_encrypt(ctx, in, out, sizeof(in));
	snprintf(status, sizeof(status), "%s encrypt", impl);
	lc_compare_selftest(out256, out, sizeof(out256), status);
	lc_sym_zero(ctx);

	lc_sym_init(ctx);
	lc_sym_setkey(ctx, key256, sizeof(key256));
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_decrypt(ctx, out, out, sizeof(out));
	snprintf(status, sizeof(status), "%s decrypt", impl);
	lc_compare_selftest(in, out, sizeof(in), status);
	lc_sym_zero(ctx);
}

static void mode_kw_encrypt(struct lc_mode_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	const struct lc_sym *wrappeded_cipher;
	struct aes_kw_block block;
	uint64_t t = 1;
	size_t rounded_len = len & ~(AES_KW_SEMIBSIZE - 1);
	unsigned int i;

	if (!ctx || !ctx->wrappeded_cipher)
		return;

	wrappeded_cipher = ctx->wrappeded_cipher;

	/*
	 * Require at least 2 semiblocks (note, the 3rd semiblock that is
	 * required by SP800-38F is the IV that occupies the first semiblock.
	 * This means that the dst memory must be one semiblock larger than src.
	 * Also ensure that the given data is aligned to semiblock.
	 */
	if (len < (2 * AES_KW_SEMIBSIZE))
		return;

	if (in != out)
		memcpy(out, in, rounded_len);

	/*
	 * Place the predefined IV into block A -- for encrypt, the caller
	 * does not need to provide an IV, but he needs to fetch the final IV.
	 */
	block.A = be_bswap64(AES_KW_IV);

	for (i = 0; i < 6; i++) {
		size_t nbytes = len;
		uint8_t *out_p = out;

		while (nbytes) {
			/* get the source block */
			block.R = ptr_to_64(out_p);

			/* perform KW operation: encrypt block */
			wrappeded_cipher->encrypt(ctx->wrapped_cipher_ctx,
						  (uint8_t *)&block,
						  (uint8_t *)&block,
						  sizeof(block));
			/* perform KW operation: modify IV with counter */
			block.A ^= be_bswap64(t);
			t++;

			/* Copy block->R into place */
			val64_to_ptr(out_p, block.R);

			nbytes -= AES_KW_SEMIBSIZE;
			out_p += AES_KW_SEMIBSIZE;
		}
	}

	/* establish the IV for the caller to pick up */
	ctx->tag = block.A;

	lc_memset_secure(&block, 0, sizeof(block));
}

static void mode_kw_decrypt(struct lc_mode_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	const struct lc_sym *wrappeded_cipher;
	struct aes_kw_block block;
	uint64_t t = 6 * (len >> 3);
	size_t rounded_len = len & ~(AES_KW_SEMIBSIZE - 1);
	unsigned int i;

	if (!ctx || !ctx->wrappeded_cipher)
		return;

	wrappeded_cipher = ctx->wrappeded_cipher;

	/*
	 * Require at least 2 semiblocks (note, the 3rd semiblock that is
	 * required by SP800-38F is the IV.
	 */
	if (len < (2 * AES_KW_SEMIBSIZE))
		return;

	if (in != out)
		memcpy(out, in, rounded_len);

	/* Place the IV into block A */
	block.A = ctx->tag;

	for (i = 0; i < 6; i++) {
		size_t nbytes = len;
		uint8_t *out_p = out + len;

		while (nbytes) {
			out_p -= AES_KW_SEMIBSIZE;
			nbytes -= AES_KW_SEMIBSIZE;

			/* get the source block */
			block.R = ptr_to_64(out_p);

			/* perform KW operation: modify IV with counter */
			block.A ^= be_bswap64(t);
			t--;

			/* perform KW operation: decrypt block */
			wrappeded_cipher->decrypt(ctx->wrapped_cipher_ctx,
						  (uint8_t *)&block,
						  (uint8_t *)&block,
						  sizeof(block));

			/* Copy block->R into place */
			val64_to_ptr(out_p, block.R);
		}
	}

	ctx->tag = block.A;

	lc_memset_secure(&block, 0, sizeof(block));
}

static void mode_kw_init(struct lc_mode_state *ctx,
			 const struct lc_sym *wrapped_cipher,
			 void *wrapped_cipher_ctx)
{
	if (!ctx || !wrapped_cipher || !wrapped_cipher_ctx ||
	    wrapped_cipher->blocksize != AES_BLOCKLEN)
		return;

	ctx->wrappeded_cipher = wrapped_cipher;
	ctx->wrapped_cipher_ctx = wrapped_cipher_ctx;
}

static int mode_kw_setkey(struct lc_mode_state *ctx, const uint8_t *key,
			  size_t keylen)
{
	const struct lc_sym *wrappeded_cipher;

	if (!ctx || !ctx->wrappeded_cipher)
		return -EINVAL;

	wrappeded_cipher = ctx->wrappeded_cipher;
	return wrappeded_cipher->setkey(ctx->wrapped_cipher_ctx, key, keylen);
}

static int mode_kw_setiv(struct lc_mode_state *ctx, const uint8_t *iv,
			 size_t ivlen)
{
	if (!ctx || ivlen != AES_KW_SEMIBSIZE)
		return -EINVAL;

	ctx->tag = ptr_to_64(iv);
	return 0;
}

static struct lc_sym_mode _lc_mode_kw_c = {
	.init = mode_kw_init,
	.setkey = mode_kw_setkey,
	.setiv = mode_kw_setiv,
	.encrypt = mode_kw_encrypt,
	.decrypt = mode_kw_decrypt,
	.statesize = LC_AES_KW_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
const struct lc_sym_mode *lc_mode_kw_c = &_lc_mode_kw_c;

LC_INTERFACE_FUNCTION(void, lc_aes_kw_encrypt, struct lc_sym_ctx *ctx,
		      const uint8_t *in, uint8_t *out, size_t len)
{
	struct lc_mode_state *state;

	if (!ctx)
		return;
	state = (struct lc_mode_state *)ctx->sym_state;

	/* Output: Tag || Ciphertext */
	lc_sym_encrypt(ctx, in, out + AES_KW_SEMIBSIZE, len);
	val64_to_ptr(out, state->tag);
}

LC_INTERFACE_FUNCTION(int, lc_aes_kw_decrypt, struct lc_sym_ctx *ctx,
		      const uint8_t *in, uint8_t *out, size_t len)
{
	struct lc_mode_state *state;
	int ret;

	if (!ctx)
		return -EINVAL;
	state = (struct lc_mode_state *)ctx->sym_state;

	ret = mode_kw_setiv(state, in, AES_KW_SEMIBSIZE);
	if (ret)
		return ret;

	/* Input: Tag || Ciphertext */
	mode_kw_decrypt(state, in + AES_KW_SEMIBSIZE, out,
			len - AES_KW_SEMIBSIZE);
	/* Perform authentication check */
	if (state->tag != be_bswap64(AES_KW_IV))
		return -EBADMSG;
	return 0;
}
