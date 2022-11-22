/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_SYMHMAC_H
#define LC_SYMHMAC_H

#include "lc_aead.h"
#include "lc_sym.h"
#include "lc_hmac.h"
#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_sh_cryptor {
	struct lc_sym_ctx sym;
	struct lc_hmac_ctx auth_ctx;
};

#define LC_SH_STATE_SIZE(sym, hash)					       \
	(LC_SYM_STATE_SIZE(sym) + LC_HMAC_STATE_SIZE(hash))
#define LC_SH_CTX_SIZE(sym, hash)					       \
	(sizeof(struct lc_aead) +					       \
	 sizeof(struct lc_sh_cryptor) +					       \
	 LC_SH_STATE_SIZE(sym, hash))

/* AES-CBC with HMAC based AEAD-algorithm */
extern const struct lc_aead *lc_symhmac_aead;

#define _LC_SH_SET_CTX(name, symalgo, hash)				       \
	_LC_SYM_SET_CTX((&name->sym), symalgo, name,			       \
			(sizeof(struct lc_sh_cryptor)));		       \
	_LC_HMAC_SET_CTX((&name->auth_ctx), hash, name,			       \
			 (sizeof(struct lc_sh_cryptor) +		       \
			 LC_SYM_STATE_SIZE(symalgo)))

#define LC_SH_SET_CTX(name, sym, hash)					       \
	LC_AEAD_CTX(name, lc_symhmac_aead);				       \
	_LC_SH_SET_CTX(((struct lc_sh_cryptor *)name->aead_state), sym, hash)

/**
 * @brief Allocate symmetric algorithm with HMAC cryptor context on heap
 *
 * @param sym [in] Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param hash [in] HMAC implementation of type struct lc_hmac used for the HMAC
 *		    authentication
 * @param ctx [out] Allocated symmetric/HMAC cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_sh_alloc(const struct lc_sym *sym, const struct lc_hash *hash,
		struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the symmetric/HMAC cryptor context
 *
 * @param name [in] Name of the stack variable
 * @param sym [in] Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param hash [in] HMAC implementation of type struct lc_hmac used for the HMAC
 *		    authentication
 */
#define LC_SH_CTX_ON_STACK(name, sym, hash)		      		       \
	_Pragma("GCC diagnostic push")					       \
	_Pragma("GCC diagnostic ignored \"-Wvla\"")	      		       \
	_Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_SH_CTX_SIZE(sym, hash),	       \
			  LC_HASH_COMMON_ALIGNMENT);			       \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *) name ## _ctx_buf;    \
	LC_SH_SET_CTX(name, sym, hash);					       \
	lc_aead_zero(name);						       \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_SYMHMAC_H */
