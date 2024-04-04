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

#include "lc_ascon_aead.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_AK_STATE_SIZE (LC_SHA3_STATE_SIZE + LC_ASCON_ALIGNMENT)
#define LC_AK_CTX_SIZE(x)                                                      \
	(sizeof(struct lc_aead) + sizeof(struct lc_ascon_cryptor) +            \
	 LC_AK_STATE_SIZE)

/**
 * @brief Allocate Ascon Keccak cryptor context on heap
 *
 * NOTE: This is defined for lc_sha3_512 and lc_sha3_256.
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
 * NOTE: This is defined for lc_sha3_512 and lc_sha3_256.
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
					  LC_ASCON_ALIGNMENT);                      \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_ASCON_SET_CTX(name, hash);                                               \
	struct lc_ascon_cryptor *__name_ascon_crypto = name->aead_state;            \
	__name_ascon_crypto->statesize = LC_SHA3_STATE_SIZE;                        \
	_Pragma("GCC diagnostic pop")
/* invocation of lc_ak_zero_free(name); not needed */

#ifdef __cplusplus
}
#endif

#endif /* LC_ASCON_KECCAK_H */
