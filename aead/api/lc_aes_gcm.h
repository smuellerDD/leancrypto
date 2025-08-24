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

#ifndef LC_AES_GCM_H
#define LC_AES_GCM_H

#include "lc_aead.h"
#include "lc_sym.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_gcm_ctx {
	uint64_t len; // cipher data length processed so far
	uint64_t add_len; // total add data length
	uint64_t HL[16]; // precalculated lo-half HTable
	uint64_t HH[16]; // precalculated hi-half HTable

	/* y and buf must be aligned to 64 bits due to accel */
	uint8_t y[16]; // the current cipher-input IV|Counter value
	uint8_t buf[16]; // buf working value

	uint8_t base_ectr[16]; // first counter-mode cipher output for tag
	uint8_t ectr[16]; // CTR ciphertext
	void (*gcm_gmult_accel)(uint64_t Xi[2], const uint64_t Htable[32]);
};

struct lc_aes_gcm_cryptor {
	struct lc_gcm_ctx gcm_ctx;
	struct lc_sym_ctx sym_ctx;
};

#define LC_AES_GCM_STATE_SIZE(x) (LC_SYM_STATE_SIZE(x))
#define LC_AES_GCM_CTX_SIZE                                                    \
	(sizeof(struct lc_aead) + sizeof(struct lc_aes_gcm_cryptor) +          \
	 LC_AES_GCM_STATE_SIZE(lc_aes))

/* AES-CBC with HMAC based AEAD-algorithm */
extern const struct lc_aead *lc_aes_gcm_aead;

#define _LC_AES_GCM_SET_CTX(name)                                              \
	_LC_SYM_SET_CTX((&name->sym_ctx), lc_aes, name,                        \
			(sizeof(struct lc_aes_gcm_cryptor)))

#define LC_AES_GCM_SET_CTX(name)                                               \
	LC_AEAD_CTX(name, lc_aes_gcm_aead);                                    \
	_LC_AES_GCM_SET_CTX(((struct lc_aes_gcm_cryptor *)name->aead_state))
/// \endcond

/**
 * @brief Allocate AES GCM cryptor context on heap
 *
 * @param [out] ctx Allocated AES GCM cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_aes_gcm_alloc(struct lc_aead_ctx **ctx);

enum lc_aes_gcm_iv_type {
	lc_aes_gcm_iv_generate_new,
};

/**
 * @brief Generate IV, set the IV to the GCM state and return it to the caller
 *
 * The operation copies the fixed_field data into the IV.
 *
 * \note If fixed_field and iv are the same pointer, the fixed field data is not
 * copied to the iv buffer.
 *
 * \note If this API is used then the lc_aead_setkey should be invoked with NULL
 * as IV.
 *
 * \note If this API is to be used, it *must* be invoked after the API call of
 * lc_aead_setkey.
 *
 * @param [in] ctx GCM context to set IV with
 * @param [in] fixed_field Fixed field data
 * @param [in] fixed_field_len Length of fixed field
 * @param [out] iv buffer with fixed_field || random number
 * @param [in] ivlen of the IV to be generated
 *
 * @return 0 on succes, < 0 on error
 */
int lc_aes_gcm_generate_iv(struct lc_aead_ctx *ctx, const uint8_t *fixed_field,
			   size_t fixed_field_len, uint8_t *iv, size_t ivlen,
			   enum lc_aes_gcm_iv_type type);

/**
 * @brief Allocate stack memory for the AES GCM cryptor context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_AES_GCM_CTX_ON_STACK(name)                                               \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf, LC_AES_GCM_CTX_SIZE,      \
					  LC_MEM_COMMON_ALIGNMENT);                 \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_AES_GCM_SET_CTX(name);                                                   \
	lc_aead_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_AES_GCM_H */
