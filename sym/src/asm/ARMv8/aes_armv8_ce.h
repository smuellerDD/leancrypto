/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef AES_ARMV8_CE_H
#define AES_ARMV8_CE_H

#include "../../aes_internal.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* AES block algorithm context */
struct aes_v8_block_ctx
{
	uint8_t RoundKey[240];
	uint32_t rounds;
};

int aes_v8_set_encrypt_key(const uint8_t *key, const unsigned int bits,
                          struct aes_v8_block_ctx *aes_ctx);
int aes_v8_set_decrypt_key(const uint8_t *userKey, const unsigned int bits,
                          struct aes_v8_block_ctx *aes_ctx);

void aes_v8_encrypt(const uint8_t *pt, uint8_t *ct,
		    const struct aes_v8_block_ctx *aes_ctx);
void aes_v8_decrypt(const uint8_t *ct, uint8_t *pt,
		    const struct aes_v8_block_ctx *aes_ctx);

void aes_v8_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
				 const struct aes_aes_v8_block_ctx *aes_ctx,
				 const uint8_t *iv);

void aes_v8_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t length,
		        const struct aes_v8_block_ctx *aes_ctx, int enc);
void aes_v8_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
		        const struct aes_v8_block_ctx *aes_ctx, uint8_t *iv,
		        int enc);

#if 0
void aes_v8_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t length,
		        const struct aes_v8_block_ctx *key1,
		        const struct aes_v8_block_ctx *key2,
		        const uint8_t iv[16]);
void aes_v8_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t length,
		        const struct aes_v8_block_ctx *key1,
		        const struct aes_v8_block_ctx *key2,
		        const uint8_t iv[16]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* AES_ARMV8_CE_H */
