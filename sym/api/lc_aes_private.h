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

#ifndef LC_AES_PRIVATE_H
#define LC_AES_PRIVATE_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Block length in bytes
 */
#define AES_BLOCKLEN 16U

/* AES block algorithm context */
struct aes_block_ctx
{
	/*
	 * AES-256: 240
	 * AES-192: 208
	 * AES-128: 176
	 */
	uint8_t RoundKey[240];
	uint8_t nk;
	uint8_t nr;
};

static inline int aes_set_type(struct aes_block_ctx *ctx, size_t keylen)
{
	switch (keylen) {
	case 16:
		ctx->nk = 4;
		ctx->nr = 10;
		break;
	case 24:
		ctx->nk = 6;
		ctx->nr = 12;
		break;
	case 32:
		ctx->nk = 8;
		ctx->nr = 14;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* state - array holding the intermediate results during decryption. */
typedef uint8_t state_t[4][4];

/* Key expansion operation */
void KeyExpansion(struct aes_block_ctx *block_ctx, const uint8_t* Key);

/* AES block cipher operation */
void aes_cipher(state_t* state, const struct aes_block_ctx *block_ctx);

/* AES inverse block cipher operation */
void aes_inv_cipher(state_t* state, const struct aes_block_ctx *block_ctx);

#ifdef __cplusplus
}
#endif

#endif /* LC_AES_PRIVATE_H */
