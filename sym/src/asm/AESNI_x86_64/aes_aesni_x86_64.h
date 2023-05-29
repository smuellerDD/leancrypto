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

#ifndef AES_AESNI_X86_64_H
#define AES_AESNI_X86_64_H

#include "../../aes_internal.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* AES block algorithm context */
struct aes_aesni_block_ctx
{
	uint8_t RoundKey[240];
	uint32_t rounds;
};

void aesni_encrypt(const uint8_t *pt, uint8_t *ct,
		   const struct aes_aesni_block_ctx *aes_ctx);
void aesni_decrypt(const uint8_t *ct, uint8_t *pt,
		   const struct aes_aesni_block_ctx *aes_ctx);

int aesni_set_encrypt_key(const uint8_t *key, const unsigned int bits,
			  struct aes_aesni_block_ctx *aes_ctx);
int aesni_set_decrypt_key(const uint8_t *key, const unsigned int bits,
			  struct aes_aesni_block_ctx *aes_ctx);

void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
				const struct aes_aesni_block_ctx *aes_ctx,
				const uint8_t *iv);

void aesni_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t length,
		       const struct aes_aesni_block_ctx *aes_ctx, int enc);
void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
		       const struct aes_aesni_block_ctx *aes_ctx, uint8_t *iv,
		       int enc);

#if 0
void aesni_xts_encrypt(const uint8_t *pt, uint8_t *ct, size_t length,
		       const struct aes_aesni_block_ctx *key1,
		       const struct aes_aesni_block_ctx *key2,
		       const uint8_t iv[16]);
void aesni_xts_decrypt(const uint8_t *ct, uint8_t *pt, size_t length,
		       const struct aes_aesni_block_ctx *key1,
		       const struct aes_aesni_block_ctx *key2,
		       const uint8_t iv[16]);

void aesni_ccm64_encrypt_blocks(const uint8_t *pt, uint8_t *ct, size_t blocks,
				const void *key, const uint8_t iv[16],
				uint8_t cmac[16]);
void aesni_ccm64_decrypt_blocks(const uint8_t *ct, uint8_t *pt, size_t blocks,
				const void *key, const uint8_t iv[16],
				uint8_t cmac[16]);

void aesni_ocb_encrypt(const uint8_t *pt,uint8_t *ct,
		       size_t blocks, const void *key,
		       size_t start_block_num,
		       uint8_t offset_i[16],
		       const uint8_t L_[][16],
		       uint8_t checksum[16]);
void aesni_ocb_decrypt(const uint8_t *in, uint8_t *out,
		       size_t blocks, const void *key,
		       size_t start_block_num,
		       uint8_t offset_i[16],
		       const uint8_t L_[][16],
		       uint8_t checksum[16]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* AES_AESNI_X86_64_H */
