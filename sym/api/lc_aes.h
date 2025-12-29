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

/* AES raw block operation */
extern const struct lc_sym *lc_aes;

/* AES XTS mode */
extern const struct lc_sym *lc_aes_xts;

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

/// \cond DO_NOT_DOCUMENT
/*
 * Maximum size of the AES context - sizeof(struct lc_sym_state)
 *
 * Note, there is a separate lc_sym_state per block chaining mode in
 * aes_*_*.c
 */
#define LC_AES_RISCV64_MAX_BLOCK_SIZE (244 * 2)
#define LC_AES_RISCV64_XTS_MAX_BLOCK_SIZE (244 * 3 + 48)
#define LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE (244 * 2 + 48)
#define LC_AES_RISCV64_CTR_MAX_BLOCK_SIZE (244 + 48)

#define LC_AES_C_MAX_BLOCK_SIZE (244)
#define LC_AES_C_XTS_MAX_BLOCK_SIZE (244 * 2 + 48)
#define LC_AES_C_CBC_MAX_BLOCK_SIZE (244 + 48)
#define LC_AES_C_CTR_MAX_BLOCK_SIZE (244 + 48)

#define LC_AES_ARMCE_MAX_BLOCK_SIZE (244 * 2)
#define LC_AES_ARMCE_XTS_MAX_BLOCK_SIZE (244 * 3 + 16 + 1)
#define LC_AES_ARMCE_CBC_MAX_BLOCK_SIZE (244 * 2 + 16)
#define LC_AES_ARMCE_CTR_MAX_BLOCK_SIZE (244 + 16)

#define LC_AES_AESNI_MAX_BLOCK_SIZE (244 * 2)
#define LC_AES_AESNI_XTS_MAX_BLOCK_SIZE (244 * 3 + 16 + 1)
#define LC_AES_AESNI_CBC_MAX_BLOCK_SIZE (244 * 2 + 16)
#define LC_AES_AESNI_CTR_MAX_BLOCK_SIZE (244 + 16)
/// \endcond

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the AES-XTS context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_AES_XTS_CTX_ON_STACK(name)                                          \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf,                              \
				  LC_SYM_CTX_SIZE_LEN(                         \
					  LC_AES_RISCV64_XTS_MAX_BLOCK_SIZE),  \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;         \
	LC_SYM_SET_CTX(name, lc_aes_xts);                                      \
	lc_sym_zero(name);                                                     \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the AES-CBC context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_AES_CBC_CTX_ON_STACK(name)                                          \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf,                              \
				  LC_SYM_CTX_SIZE_LEN(                         \
					  LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE),  \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;         \
	LC_SYM_SET_CTX(name, lc_aes_cbc);                                      \
	lc_sym_zero(name);                                                     \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the AES-CTR context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_AES_CTR_CTX_ON_STACK(name)                                          \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf,                              \
				  LC_SYM_CTX_SIZE_LEN(                         \
					  LC_AES_RISCV64_CTR_MAX_BLOCK_SIZE),  \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;         \
	LC_SYM_SET_CTX(name, lc_aes_ctr);                                      \
	lc_sym_zero(name);                                                     \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the AES block context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_AES_CTX_ON_STACK(name)                                              \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SYM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),      \
			LC_SYM_COMMON_ALIGNMENT);                              \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;         \
	LC_SYM_SET_CTX(name, lc_aes);                                          \
	lc_sym_zero(name);                                                     \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_AES_H */
