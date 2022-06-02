/*
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

#include "bitshift.h"
#include "conv_be_le.h"
#include "rotate.h"
#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "lc_sym.h"
#include "math_helper.h"
#include "visibility.h"
#include "xor.h"

/* ChaCha20 block function according to RFC 7539 section 2.3 */
DSO_PUBLIC
void cc20_block(struct lc_sym_state *state, uint32_t *stream)
{
	uint32_t *state_w = &state->constants[0];
	uint32_t i, ws[LC_CC20_BLOCK_SIZE_WORDS], *out = stream;

	for (i = 0; i < LC_CC20_BLOCK_SIZE_WORDS; i++)
		ws[i] = state_w[i];

	for (i = 0; i < 10; i++) {
		/* Quarterround 1 */
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],  16);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],  12);
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],   8);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],   7);

		/* Quarterround 2 */
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],  16);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],  12);
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],   8);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],   7);

		/* Quarterround 3 */
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],  16);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10], 12);
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],   8);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10],  7);

		/* Quarterround 4 */
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],  16);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11], 12);
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],   8);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11],  7);

		/* Quarterround 5 */
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],  16);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10], 12);
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],   8);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10],  7);

		/* Quarterround 6 */
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],  16);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11], 12);
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],   8);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11],  7);

		/* Quarterround 7 */
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],  16);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],  12);
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],   8);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],   7);

		/* Quarterround 8 */
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],  16);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],  12);
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],   8);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],   7);
	}

	for (i = 0; i < LC_CC20_BLOCK_SIZE_WORDS; i++)
		out[i] = le_bswap32(ws[i] + state_w[i]);

	state_w[12]++;
}

static void cc20_init(struct lc_sym_state *ctx)
{
	/* String "expand 32-byte k" */
	ctx->constants[0] = 0x61707865;
	ctx->constants[1] = 0x3320646e;
	ctx->constants[2] = 0x79622d32;
	ctx->constants[3] = 0x6b206574;
	ctx->counter 	  = 1;
}

static int cc20_setkey(struct lc_sym_state *ctx, uint8_t *key, size_t keylen)
{
	if (keylen != 32)
		return -EINVAL;

	ctx->key.u[0] = ptr_to_32(key);
	ctx->key.u[1] = ptr_to_32(key + sizeof(uint32_t));
	ctx->key.u[2] = ptr_to_32(key + sizeof(uint32_t) * 2);
	ctx->key.u[3] = ptr_to_32(key + sizeof(uint32_t) * 3);
	ctx->key.u[4] = ptr_to_32(key + sizeof(uint32_t) * 4);
	ctx->key.u[5] = ptr_to_32(key + sizeof(uint32_t) * 5);
	ctx->key.u[6] = ptr_to_32(key + sizeof(uint32_t) * 6);
	ctx->key.u[7] = ptr_to_32(key + sizeof(uint32_t) * 7);

	return 0;
}

static int cc20_setiv(struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen)
{
	/* IV is counter + nonce */
	if (ivlen != 12)
		return -EINVAL;

	ctx->nonce[0] = ptr_to_32(iv);
	ctx->nonce[1] = ptr_to_32(iv + sizeof(uint32_t));
	ctx->nonce[2] = ptr_to_32(iv + sizeof(uint32_t) * 2);

	return 0;

}

static void cc20_crypt(struct lc_sym_state *ctx,
		       const uint8_t *in, uint8_t *out, size_t len)
{
	uint32_t keystream[LC_CC20_BLOCK_SIZE_WORDS]
				__attribute__((aligned(sizeof(uint64_t))));

	while (len) {
		size_t todo = min_t(size_t, len, sizeof(keystream));

		cc20_block(ctx, keystream);

		if (in != out)
			memcpy(out, in, todo);

		xor_64(out, (uint8_t *)keystream, todo);

		len -= todo;
		in += todo;
		out += todo;
	}

	memset_secure(keystream, 0, sizeof(keystream));
}

static struct lc_sym _lc_chacha20 = {
	.init		= cc20_init,
	.setkey		= cc20_setkey,
	.setiv		= cc20_setiv,
	.encrypt	= cc20_crypt,
	.decrypt	= cc20_crypt,
	.statesize	= LC_CC20_BLOCK_SIZE,
	.blocksize	= LC_CC20_BLOCK_SIZE,
};
DSO_PUBLIC const struct lc_sym *lc_chacha20 = &_lc_chacha20;
