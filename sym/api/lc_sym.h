/*
 * Copyright (C) 2016 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef _LC_SYM_H
#define _LC_SYM_H

#include "ext_headers.h"
#include "lc_memset_secure.h"
#include "lc_memory_support.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_sym_state;
struct lc_sym {
	int (*init)(struct lc_sym_state *ctx);
	int (*init_nocheck)(struct lc_sym_state *ctx);
	int (*setkey)(struct lc_sym_state *ctx, const uint8_t *key,
		      size_t keylen);
	int (*setiv)(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen);
	int (*getiv)(const struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen);
	void (*encrypt)(struct lc_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len);
	void (*decrypt)(struct lc_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len);
	uint64_t algorithm_type;
	unsigned int statesize;
	unsigned int blocksize;
};

struct lc_sym_ctx {
	const struct lc_sym *sym;
	struct lc_sym_state *sym_state;
};

/*
 * Align the lc_sym_state structure to 16 bytes boundary irrespective where
 * it is embedded into. This is achieved by adding 15 more bytes than necessary
 * to LC_ALIGNED_SYM_BUFFER and then adjusting the pointer offset in that range
 * accordingly.
 *
 * TODO: make this adjustable with a lc_sym->alignment setting - but the
 * question is which pre-processor macro to use to select the proper
 * LC_ALIGN_PTR_XX macro depending on lc_sym->alignment during compile time.
 */
#ifndef LC_SYM_COMMON_ALIGNMENT
#define LC_SYM_COMMON_ALIGNMENT (16)
#endif
#define LC_SYM_ALIGNMENT(symname) LC_SYM_COMMON_ALIGNMENT
#define LC_SYM_ALIGNMASK(symname) (LC_SYM_ALIGNMENT(symname) - 1)

#define LC_ALIGN_SYM_MASK(p, symname)                                          \
	LC_ALIGN_PTR_64(p, LC_SYM_ALIGNMASK(symname))

/*
 * This is the source of the compiler warning of using Variable-Length-Arrays
 * (VLA). It is considered to be harmless to have this VLA here, because all
 * length definitions are defined by leancrypto at compile time. If you do not
 * want it, you have the following options:
 *
 * 1. Use the type-specific LC_AES_*_CTX_ON_STACK
 * 2. Do not use stack-allocation function.
 * 3. Ignore the warning by using
 * #pragma GCC diagnostic push
 * #pragma GCC diagnostic ignored "-Wvla"
 * LC_HASH_CTX_ON_STACK()
 * #pragma GCC diagnostic pop
 */
#define LC_SYM_STATE_SIZE_NONALIGNED(x) ((unsigned long)(x->statesize))
#define LC_SYM_STATE_SIZE(x)                                                   \
	(LC_SYM_STATE_SIZE_NONALIGNED(x) + LC_SYM_COMMON_ALIGNMENT)
#define LC_SYM_CTX_SIZE_NONALIGNED(x)                                          \
	(sizeof(struct lc_sym_ctx) + LC_SYM_STATE_SIZE_NONALIGNED(x))
#define LC_SYM_CTX_SIZE(x) (sizeof(struct lc_sym_ctx) + LC_SYM_STATE_SIZE(x))

#define LC_SYM_STATE_SIZE_LEN(len) ((len) + LC_SYM_COMMON_ALIGNMENT)
#define LC_SYM_CTX_SIZE_LEN(len)                                               \
	(sizeof(struct lc_sym_ctx) + LC_SYM_STATE_SIZE_LEN(len))

#define _LC_SYM_SET_CTX(name, symname, ctx, offset)                            \
	name->sym_state = (struct lc_sym_state *)LC_ALIGN_SYM_MASK(            \
		((uint8_t *)(ctx)) + (offset), symname);                       \
	name->sym = symname

#define LC_SYM_SET_CTX(name, symname)                                          \
	_LC_SYM_SET_CTX(name, symname, name, sizeof(struct lc_sym_ctx))
/// \endcond

/** @defgroup Symmetric Symmetric Unauthenticated Encryption Algorithms
 *
 * Concept of symmetric algorithms in leancrypto
 *
 * All symmetric can be used with the API calls documented below. However,
 * the allocation part is symmetric-algorithm-specific. Thus, perform the
 * following steps
 *
 * 1. Allocation: Use the stack or heap allocation functions documented in
 *    lc_aes.h, lc_chacha20.h.
 *
 * 2. Use the returned cipher handle with the API calls below.
 */

/**
 * @ingroup Symmetric
 * @brief Initialize symmetric context
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 *
 * The caller must provide an allocated \p ctx.
 */
int lc_sym_init(struct lc_sym_ctx *ctx);

/**
 * @ingroup Symmetric
 * @brief Set key
 *
 * \note For XTS, it is required that this function call MUST come BEFORE the
 * \p lc_sym_setiv invocation as the tweak value is immediately calculated from
 * the IV using the XTS key.
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   set the key.
 * @param [in] key Key to be set
 * @param [in] keylen Key length to be set
 *
 * @return 0 on success, < 0 on error
 */
int lc_sym_setkey(struct lc_sym_ctx *ctx, const uint8_t *key, size_t keylen);

/**
 * @ingroup Symmetric
 * @brief Set IV
 *
 * \note For XTS, it is required that this function call MUST come AFTER the
 * \p lc_sym_setkey invocation as the tweak value is immediately calculated from
 * the IV using the XTS key.
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   set the IV.
 * @param [in] iv IV to be set
 * @param [in] ivlen IV length to be set
 *
 * @return 0 on success, < 0 on error
 */
int lc_sym_setiv(struct lc_sym_ctx *ctx, const uint8_t *iv, size_t ivlen);

/**
 * @ingroup Symmetric
 * @brief Get IV
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   set the IV.
 * @param [in] iv buffer to be filled with IV
 * @param [in] ivlen length of buffer
 *
 * @return 0 on success, < 0 on error
 */
int lc_sym_getiv(const struct lc_sym_ctx *ctx, uint8_t *iv, size_t ivlen);

/**
 * @ingroup Symmetric
 * @brief Symmetric encryption
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
 * \note This call is allowed to be called multiple times to operate in
 * stream mode. However, the caller must enforce the following:
 * 1. All invocations except for the last data block must contain data that
 *    is always a multiple of 16 bytes.
 * 2. Only the last invocation is allowed to be not a multiple of 16 bytes for
 *    algorithms that allow it (e.g. XTS, CTR)
 */
void lc_sym_encrypt(struct lc_sym_ctx *ctx, const uint8_t *in, uint8_t *out,
		    size_t len);

/**
 * @ingroup Symmetric
 * @brief Symmetric decryption
 *
 * @param [in] ctx Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 * @param [in] in Ciphertext to be decrypted
 * @param [out] out Plaintext resulting of the decryption
 * @param [in] len Size of the input / output buffer
 *
 * The plaintext and the ciphertext buffer may be identical to support
 * in-place cryptographic operations.
 *
 * \note This call is allowed to be called multiple times to operate in
 * stream mode. However, the caller must enforce the following:
 * 1. All invocations except for the last data block must contain data that
 *    is always a multiple of 16 bytes.
 * 2. Only the last invocation is allowed to be not a multiple of 16 bytes for
 *    algorithms that allow it (e.g. XTS, CTR)
 */
void lc_sym_decrypt(struct lc_sym_ctx *ctx, const uint8_t *in, uint8_t *out,
		    size_t len);

/**
 * @ingroup Symmetric
 * @brief Zeroize symmetric context allocated with either LC_SYM_CTX_ON_STACK
 *	  or lc_sym_alloc
 *
 * @param [in] ctx Symmetric context to be zeroized
 */
void lc_sym_zero(struct lc_sym_ctx *ctx);

/**
 * @ingroup Symmetric
 * @brief Allocate symmetric algorithm context on heap
 *
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 * @param [out] ctx Allocated symmetrc algorithm context
 *
 * @return 0 on success, < 0 on error
 */
int lc_sym_alloc(const struct lc_sym *sym, struct lc_sym_ctx **ctx);

/**
 * @ingroup Symmetric
 * @brief Symmetric algorithm deallocation and properly zeroization function to
 *	  frees all buffers and the cipher handle
 *
 * @param [in] ctx Symmtric algorithm context handle
 */
void lc_sym_zero_free(struct lc_sym_ctx *ctx);

/**
 * @ingroup Symmetric
 * @brief Obtain algorithm type usable with lc_alg_status
 *
 * @param [in] sym AEAD algorithm instance
 *
 * @return algorithm type
 */
uint64_t lc_sym_algorithm_type(const struct lc_sym *sym);

/**
 * @ingroup Symmetric
 * @brief Obtain algorithm type usable with lc_alg_status
 *
 * @param [in] ctx Symmetric context handle
 *
 * @return algorithm type
 */
uint64_t lc_sym_ctx_algorithm_type(const struct lc_sym_ctx *ctx);

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the sym context
 *
 * @param [in] name Name of the stack variable
 * @param [in] symname Pointer of type struct sym referencing the sym
 *		       implementation to be used
 */
#define LC_SYM_CTX_ON_STACK(name, symname)                                          \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_SYM_CTX_SIZE(symname),                 \
					  LC_SYM_COMMON_ALIGNMENT);                 \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;              \
	LC_SYM_SET_CTX(name, symname);                                              \
	lc_sym_zero(name);                                                          \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* _LC_SYM_H */
