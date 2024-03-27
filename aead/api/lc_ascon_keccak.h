/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_ASCON_KECCAK_H
#define LC_ASCON_KECCAK_H

#include "lc_aead.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_ak_cryptor {
	uint64_t keccak_state[LC_SHA3_STATE_WORDS];
	uint8_t key[64];
	uint8_t keylen;
	uint8_t rate_offset;
	const struct lc_hash *hash;
};

#define LC_ASCON_KECCAK_ALIGNMENT LC_XOR_ALIGNMENT(LC_HASH_COMMON_ALIGNMENT)

#define LC_AK_STATE_SIZE                                                       \
	(LC_SHA3_STATE_SIZE + LC_ASCON_KECCAK_ALIGNMENT)
#define LC_AK_CTX_SIZE(x)                                                      \
	(sizeof(struct lc_aead) + sizeof(struct lc_ak_cryptor))

/* Ascon-Keccak-based AEAD-algorithm */
extern const struct lc_aead *lc_ascon_keccak_aead;

#define _LC_AK_SET_CTX(name, hashname)                                         \
	name->hash = hashname

#define LC_AK_SET_CTX(name, hashname)                                          \
	LC_AEAD_HASH_ALIGN_CTX(name, lc_ascon_keccak_aead);                    \
	_LC_AK_SET_CTX(((struct lc_ak_cryptor *)name->aead_state), hashname)

/**
 * @brief Allocate Ascon Keccak cryptor context on heap
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param [in] hash Hash implementation of type struct hash used for the
 *		    Ascon-Keccak algorithm
 * @param [out] ctx Allocated Ascon-Keccak cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_ak_alloc(const struct lc_hash *hash, struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the Ascon-Keccak cryptor context
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param [in] name Name of the stack variable
 * @param [in] hash Hash implementation of type struct hash used for the
 *		    Ascon-Keccak algorithm
 */
#define LC_AK_CTX_ON_STACK(name, hash)                                              \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_AK_CTX_SIZE(hash),                     \
					  LC_ASCON_KECCAK_ALIGNMENT);               \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_AK_SET_CTX(name, hash);                                                  \
	_Pragma("GCC diagnostic pop")
/* invocation of lc_ak_zero_free(name); not needed */

#ifdef __cplusplus
}
#endif

#endif /* LC_ASCON_KECCAK_H */
