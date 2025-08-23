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

#ifndef LC_CHACHA20_POLY1305_H
#define LC_CHACHA20_POLY1305_H

#include "lc_aead.h"
#include "lc_chacha20.h"
#include "lc_memset_secure.h"
#include "lc_poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_chacha20_poly1305_cryptor {
	struct lc_sym_ctx chacha20;
	struct lc_poly1305_context poly1305_ctx;
	size_t datalen;
	size_t aadlen;
};

#define LC_CHACHA20_POLY1305_STATE_SIZE (LC_SYM_STATE_SIZE(lc_chacha20))
#define LC_CHACHA20_POLY1305_CTX_SIZE                                          \
	(sizeof(struct lc_aead) +                                              \
	 sizeof(struct lc_chacha20_poly1305_cryptor) +                         \
	 LC_CHACHA20_POLY1305_STATE_SIZE)

/* AES-CBC with HMAC based AEAD-algorithm */
extern const struct lc_aead *lc_chacha20_poly1305_aead;

#define _LC_CHACHA20_POLY1305_SET_CTX(name)                                    \
	_LC_SYM_SET_CTX((&name->chacha20), lc_chacha20, name,                  \
			(sizeof(struct lc_chacha20_poly1305_cryptor)));        \
	(name)->datalen = 0;                                                   \
	(name)->aadlen = 0

#define LC_CHACHA20_POLY1305_SET_CTX(name)                                     \
	LC_AEAD_CTX(name, lc_chacha20_poly1305_aead);                          \
	_LC_CHACHA20_POLY1305_SET_CTX(                                         \
		((struct lc_chacha20_poly1305_cryptor *)name->aead_state))
/// \endcond

/**
 * @brief Allocate ChaCha20 Poly1305 cryptor context on heap
 *
 * @param [out] ctx Allocated ChaCha20 Poly1305 cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_chacha20_poly1305_alloc(struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the ChaCha20 Poly1305 cryptor context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_CHACHA20_POLY1305_CTX_ON_STACK(name)                                     \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CHACHA20_POLY1305_CTX_SIZE,            \
					  LC_MEM_COMMON_ALIGNMENT);                 \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_CHACHA20_POLY1305_SET_CTX(name);                                         \
	lc_aead_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_CHACHA20_POLY1305_H */
