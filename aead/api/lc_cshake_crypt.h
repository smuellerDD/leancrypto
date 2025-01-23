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

#ifndef LC_CSHAKE_CRYPT_H
#define LC_CSHAKE_CRYPT_H

#include "lc_aead.h"
#include "lc_memory_support.h"

/*
 * This is the CSHAKE crypt cipher operation using the CSHAKE output as
 * keystream
 */
#include "lc_cshake.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_cc_cryptor {
	struct lc_hash_ctx cshake;
	struct lc_cshake_ctx auth_ctx;
	size_t keystream_ptr;
	uint8_t *keystream;
};

/*
 * The block size of the algorithm for generating the key stream. It must be
 * a multiple of the cSHAKE block size.
 */
#define LC_CC_KEYSTREAM_BLOCK LC_SHA3_256_SIZE_BLOCK

#define LC_CSHAKE_CRYPT_ALIGNMENT LC_XOR_ALIGNMENT(LC_HASH_COMMON_ALIGNMENT)

#define LC_ALIGN_CSHAKE_CRYPT_MASK(p)                                          \
	LC_ALIGN_PTR_8(p, LC_ALIGNMENT_MASK(LC_CSHAKE_CRYPT_ALIGNMENT))

/*
 * One block LC_CSHAKE_CRYPT_ALIGNMENT is required to ensure the
 * ->keystream pointer is aligned
 */
#define LC_CC_STATE_SIZE(x)                                                    \
	(LC_HASH_STATE_SIZE(x) + LC_CSHAKE_STATE_SIZE_REINIT(x) +              \
	 LC_CC_KEYSTREAM_BLOCK + LC_CSHAKE_CRYPT_ALIGNMENT)
#define LC_CC_CTX_SIZE(x)                                                      \
	(sizeof(struct lc_aead) + sizeof(struct lc_cc_cryptor) +               \
	 LC_CC_STATE_SIZE(x))

/* CSHAKE-based AEAD-algorithm */
extern const struct lc_aead *lc_cshake_aead;

/* Ensure that ->keystream is aligned to XOR alignment requirement */
#define _LC_CC_SET_CTX(name, hashname)                                         \
	_LC_HASH_SET_CTX((&name->cshake), hashname, name,                      \
			 (sizeof(struct lc_cc_cryptor)));                      \
	_LC_CSHAKE_SET_CTX_REINIT((&name->auth_ctx), hashname, name,           \
				  (sizeof(struct lc_cc_cryptor) +              \
				   LC_HASH_STATE_SIZE(hashname)));             \
	name->keystream = LC_ALIGN_CSHAKE_CRYPT_MASK(                          \
		(uint8_t *)((uint8_t *)name +                                  \
			    (sizeof(struct lc_cc_cryptor) +                    \
			     LC_HASH_STATE_SIZE(hashname) +                    \
			     LC_CSHAKE_STATE_SIZE_REINIT(hashname))))

#define LC_CC_SET_CTX(name, hashname)                                          \
	LC_AEAD_CTX(name, lc_cshake_aead);                                     \
	_LC_CC_SET_CTX(((struct lc_cc_cryptor *)name->aead_state), hashname)
/// \endcond

/**
 * @brief Allocate cSHAKE cryptor context on heap
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param [in] hash Hash implementation of type struct hash used for the HMAC
 *		    authentication
 * @param [out] ctx Allocated cSHAKE cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_cc_alloc(const struct lc_hash *hash, struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the cSHAKE cryptor context
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param [in] name Name of the stack variable
 * @param [in] hash Hash implementation of type struct hash used for the cSHAKE
 *		    authentication
 */
#define LC_CC_CTX_ON_STACK(name, hash)                                              \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CC_CTX_SIZE(hash),                     \
					  LC_CSHAKE_CRYPT_ALIGNMENT);               \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_CC_SET_CTX(name, hash);                                                  \
	_Pragma("GCC diagnostic pop")
/* invocation of lc_cc_zero_free(name); not needed */

#ifdef __cplusplus
}
#endif

#endif /* LC_CSHAKE_CRYPT_H */
