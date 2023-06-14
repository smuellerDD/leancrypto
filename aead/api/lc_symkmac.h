/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_SYMKMAC_H
#define LC_SYMKMAC_H

#include "lc_aead.h"
#include "lc_sym.h"
#include "lc_kmac.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_kh_cryptor {
	struct lc_sym_ctx sym;
	struct lc_kmac_ctx auth_ctx;
};

#define LC_KH_STATE_SIZE(sym, hash)					       \
	(LC_SYM_STATE_SIZE(sym) + LC_KMAC_STATE_SIZE(hash))
#define LC_KH_CTX_SIZE(sym, hash)					       \
	(sizeof(struct lc_aead) +					       \
	 sizeof(struct lc_kh_cryptor) +					       \
	 LC_KH_STATE_SIZE(sym, hash))

/* AES-CBC with KMAC based AEAD-algorithm */
extern const struct lc_aead *lc_symkmac_aead;

#define _LC_KH_SET_CTX(name, symalgo, hash)				       \
	_LC_SYM_SET_CTX((&name->sym), symalgo, name,			       \
			(sizeof(struct lc_kh_cryptor)));		       \
	_LC_KMAC_SET_CTX((&name->auth_ctx), hash, name,			       \
			 (sizeof(struct lc_kh_cryptor) +		       \
			 LC_SYM_STATE_SIZE(symalgo)))

#define LC_KH_SET_CTX(name, sym, hash)					       \
	LC_AEAD_CTX(name, lc_symkmac_aead);				       \
	_LC_KH_SET_CTX(((struct lc_kh_cryptor *)name->aead_state), sym, hash)

/**
 * @brief Allocate symmetric algorithm with KMAC cryptor context on heap
 *
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash KMAC implementation KMAC authentication - use lc_cshake256
 *		    for now
 * @param [out] ctx Allocated symmetric/KMAC cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_kh_alloc(const struct lc_sym *sym, const struct lc_hash *hash,
		struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the symmetric/KMAC cryptor context
 *
 * @param [in] name Name of the stack variable
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash KMAC implementation KMAC authentication - use lc_cshake256
 *		    or lc_cshake128 (though, note: the lc_cshake256 has a lower
 *		    memory footprint, is faster and has a higher security
 *		    strength which implies that it would be the natural choice)
 */
#define LC_KH_CTX_ON_STACK(name, sym, hash)		      		       \
	_Pragma("GCC diagnostic push")					       \
	_Pragma("GCC diagnostic ignored \"-Wvla\"")	      		       \
	_Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_KH_CTX_SIZE(sym, hash),	       \
			  LC_HASH_COMMON_ALIGNMENT);			       \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *) name ## _ctx_buf;    \
	LC_KH_SET_CTX(name, sym, hash);					       \
	lc_aead_zero(name);						       \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_SYMKMAC_H */
