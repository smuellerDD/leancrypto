/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef ASCON_INTERNAL_H
#define ASCON_INTERNAL_H

#include "lc_ascon_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_ascon_setkey_int(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *nonce, size_t noncelen, int nocheck,
			int (*setiv)(struct lc_ascon_cryptor *ascon,
				     size_t keylen, int nocheck));
void lc_ascon_encrypt(void *state, const uint8_t *plaintext,
		      uint8_t *ciphertext, size_t datalen, const uint8_t *aad,
		      size_t aadlen, uint8_t *tag, size_t taglen);
int lc_ascon_decrypt(void *state, const uint8_t *ciphertext, uint8_t *plaintext,
		     size_t datalen, const uint8_t *aad, size_t aadlen,
		     const uint8_t *tag, size_t taglen);

void lc_ascon_aad_interface(void *state, const uint8_t *aad, size_t aadlen);
void lc_ascon_enc_update_interface(void *state, const uint8_t *plaintext,
				   uint8_t *ciphertext, size_t datalen);
void lc_ascon_enc_final_interface(void *state, uint8_t *tag, size_t taglen);
void lc_ascon_dec_update_interface(void *state, const uint8_t *ciphertext,
				   uint8_t *plaintext, size_t datalen);
int lc_ascon_dec_final_interface(void *state, const uint8_t *tag,
				 size_t taglen);
void lc_ascon_zero_interface(void *state);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_INTERNAL_H */
