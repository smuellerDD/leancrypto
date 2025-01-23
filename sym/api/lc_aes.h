/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/kokke/tiny-AES-c
 *
 * This is free and unencumbered software released into the public domain.
 */

#ifndef LC_AES_H
#define LC_AES_H

#include "lc_sym.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AES ECB mode */
extern const struct lc_sym *lc_aes_ecb;

/* AES CBC mode */
extern const struct lc_sym *lc_aes_cbc;

/* AES CTR mode */
extern const struct lc_sym *lc_aes_ctr;

/* AES KW mode */
extern const struct lc_sym *lc_aes_kw;

/**
 * @ingroup Symmetric
 * @brief AES KW encrypt
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 * @param [in] in Plaintext to be encrypted
 * @param [out] out Ciphertext resulting of the encryption
 * @param [in] len Size of the input / output buffer
 *
 * The plaintext and the ciphertext buffer may be identical to support
 * in-place cryptographic operations.
 *
 * NOTE: The output buffer MUST be 8 bytes larger than the input buffer!
 *
 * This function is a helper function. It provides the same operation as
 * lc_sym_encrypt. The difference is that it also obtains the tag from the
 * AES KW operation.
 */
void lc_aes_kw_encrypt(struct lc_sym_ctx *ctx, const uint8_t *in, uint8_t *out,
		       size_t len);

/**
 * @ingroup Symmetric
 * @brief AES KW decrypt
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 * @param [in] in Ciphertext to be decrypted
 * @param [out] out Plaintext resulting of the decryption
 * @param [in] len Size of the input / output buffer
 *
 * @return 0 on success, -EBADMSG on authentication error
 *
 * The plaintext and the ciphertext buffer may be identical to support
 * in-place cryptographic operations.
 *
 * NOTE: The output buffer MAY be 8 bytes smaller than the input buffer.
 *
 * This function is a helper function. It provides the same operation as
 * lc_sym_decrypt. The difference is that it also performs the authentication.
 */
int lc_aes_kw_decrypt(struct lc_sym_ctx *ctx, const uint8_t *in, uint8_t *out,
		      size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LC_AES_H */
