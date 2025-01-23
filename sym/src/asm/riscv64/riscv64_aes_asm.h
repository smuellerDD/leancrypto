/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef RISCV64_AES_ASM_H
#define RISCV64_AES_ASM_H

#ifdef __cplusplus
extern "C" {
#endif

/* AES block algorithm context */
struct aes_riscv64_block_ctx {
	uint8_t RoundKey[240];
	uint32_t rounds;
};

int aes_riscv64_set_encrypt_key(const uint8_t *key, const unsigned int bits,
				struct aes_riscv64_block_ctx *aes_ctx);
int aes_riscv64_set_decrypt_key(const uint8_t *userKey, const unsigned int bits,
				struct aes_riscv64_block_ctx *aes_ctx);

void aes_riscv64_encrypt_asm(const uint8_t *pt, uint8_t *ct,
			     const struct aes_riscv64_block_ctx *aes_ctx);
void aes_riscv64_decrypt_asm(const uint8_t *ct, uint8_t *pt,
			     const struct aes_riscv64_block_ctx *aes_ctx);

#ifdef __cplusplus
}
#endif

#endif /* RISCV64_AES_ASM_H */
