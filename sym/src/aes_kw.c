/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"
#include "bitshift.h"
#include "conv_be_le.h"
#include "lc_aes.h"
#include "lc_aes_private.h"
#include "lc_sym.h"
#include "memset_secure.h"
#include "visibility.h"

#define AES_KW_SEMIBSIZE	8U
#define AES_KW_IV		0xa6a6a6a6a6a6a6a6ULL

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
	uint64_t tag;
};

struct aes_kw_block {
	uint64_t A;
	uint64_t R;
};

#define LC_AES_KW_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_kw_encrypt(struct lc_sym_state *ctx,
			   const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;
	struct aes_kw_block block;
	uint64_t t = 1;
	size_t rounded_len = len & ~(AES_KW_SEMIBSIZE - 1);
	unsigned int i;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

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
			aes_cipher((state_t*)&block, block_ctx);
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

	memset_secure(&block, 0, sizeof(block));
}

static void aes_kw_decrypt(struct lc_sym_state *ctx,
			   const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;
	struct aes_kw_block block;
	uint64_t t = 6 * (len >> 3);
	size_t rounded_len = len & ~(AES_KW_SEMIBSIZE - 1);
	unsigned int i;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

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
			aes_inv_cipher((state_t*)&block, block_ctx);

			/* Copy block->R into place */
			val64_to_ptr(out_p, block.R);
		}
	}

	ctx->tag = block.A;

	memset_secure(&block, 0, sizeof(block));
}

static void aes_kw_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_kw_setkey(struct lc_sym_state *ctx,
			 const uint8_t *key, size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = aes_set_type(&ctx->block_ctx, keylen);
	if (!ret)
		KeyExpansion(&ctx->block_ctx, key);

	return ret;
}

static int aes_kw_setiv(struct lc_sym_state *ctx,
			const uint8_t *iv, size_t ivlen)
{
	if (!ctx || ivlen != AES_KW_SEMIBSIZE)
		return -EINVAL;

	ctx->tag = ptr_to_64(iv);
	return 0;
}

static struct lc_sym _lc_aes_kw = {
	.init		= aes_kw_init,
	.setkey		= aes_kw_setkey,
	.setiv		= aes_kw_setiv,
	.encrypt	= aes_kw_encrypt,
	.decrypt	= aes_kw_decrypt,
	.statesize	= LC_AES_KW_BLOCK_SIZE,
	.blocksize	= AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_kw) = &_lc_aes_kw;

LC_INTERFACE_FUNCTION(
void, lc_aes_kw_encrypt, struct lc_sym_ctx *ctx,
			 const uint8_t *in, uint8_t *out, size_t len)
{
	struct lc_sym_state *state;

	if (!ctx)
		return;
	state = ctx->sym_state;

	/* Output: Tag || Ciphertext */
	aes_kw_encrypt(state, in, out + AES_KW_SEMIBSIZE, len);
	val64_to_ptr(out, state->tag);
}

LC_INTERFACE_FUNCTION(
int, lc_aes_kw_decrypt, struct lc_sym_ctx *ctx,
			const uint8_t *in, uint8_t *out, size_t len)
{
	struct lc_sym_state *state;
	int ret;

	if (!ctx)
		return -EINVAL;
	state = ctx->sym_state;

	ret = aes_kw_setiv(state, in, AES_KW_SEMIBSIZE);
	if (ret)
		return ret;

	/* Input: Tag || Ciphertext */
	aes_kw_decrypt(state, in + AES_KW_SEMIBSIZE, out,
		       len - AES_KW_SEMIBSIZE);
	/* Perform authentication check */
	if (state->tag != be_bswap64(AES_KW_IV))
		return -EBADMSG;
	return 0;
}
