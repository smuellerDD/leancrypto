/*
 * Copyright (C) 2016 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <stdint.h>

#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_sym_state;
struct lc_sym {
	void (*init)(struct lc_sym_state *ctx);
	int (*setkey)(struct lc_sym_state *ctx,
		      const uint8_t *key, size_t keylen);
	int (*setiv)(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen);
	void (*encrypt)(struct lc_sym_state *ctx,
			const uint8_t *in, uint8_t *out, size_t len);
	void (*decrypt)(struct lc_sym_state *ctx,
			const uint8_t *in, uint8_t *out, size_t len);
	unsigned int statesize;
	unsigned int blocksize;
};

struct lc_sym_ctx {
	const struct lc_sym *sym;
	struct lc_sym_state *sym_state;
};

#define LC_SYM_STATE_SIZE(x)	(x->statesize)
#define LC_SYM_CTX_SIZE(x)	(sizeof(struct lc_sym_ctx) +		       \
				 LC_SYM_STATE_SIZE(x))

/*
 * Align the lc_sym_state structure to 8 bytes boundary irrespective where
 * it is embedded into. This is achieved by adding 7 more bytes than necessary
 * to LC_ALIGNED_SYM_BUFFER and then adjusting the pointer offset in that range
 * accordingly.
 *
 * TODO: make this adjustable with a lc_sym->alignment setting - but the
 * question is which pre-processor macro to use to select the proper
 * LC_ALIGN_PTR_XX macro depending on lc_sym->alignment during compile time.
 */
#define LC_SYM_ALIGNMENT(symname)	(8)
#define LC_SYM_ALIGNMASK(symname)	(LC_SYM_ALIGNMENT(symname) - 1)

#define LC_ALIGN_APPLY(x, mask)	(((x) + (mask)) & ~(mask))
#define LC_ALIGN(x, a)		LC_ALIGN_APPLY((x), (unsigned long)(a))
#define LC_ALIGN_PTR_64(p, a)	((uint64_t *)LC_ALIGN((unsigned long)(p), (a)))
#define LC_ALIGN_PTR_32(p, a)	((uint32_t *)LC_ALIGN((unsigned long)(p), (a)))
#define LC_ALIGN_PTR_16(p, a)	((uint16_t *)LC_ALIGN((unsigned long)(p), (a)))
#define LC_ALIGN_PTR_8(p, a)	((uint8_t *)LC_ALIGN((unsigned long)(p), (a)))
#define LC_ALIGN_SYM_MASK(p, symname)	LC_ALIGN_PTR_64(p, LC_SYM_ALIGNMASK(symname))

/**
 * Get aligned buffer with additional spare size of LC_SYM_ALIGNMASK to
 * ensure that the underlying symmetric algorithm implementation buffer is
 * aligned to proper size.
 */
#define LC_ALIGNED_SYM_BUFFER(name, symname, size, type)		       \
	type name[(size + LC_SYM_ALIGNMASK(symname) + sizeof(type) - 1) /      \
		   sizeof(type)] __attribute__((aligned(sizeof(type))))

#define _LC_SYM_SET_CTX(name, symname, ctx, offset)			       \
	name->sym_state = (struct lc_sym_state *)			       \
			   LC_ALIGN_SYM_MASK(((uint8_t *)(ctx)) + (offset),    \
			   symname);					       \
        name->sym = symname

#define LC_SYM_SET_CTX(name, symname)					       \
	_LC_SYM_SET_CTX(name, symname, name, sizeof(struct lc_sym_ctx))

/**
 * @brief Initialize symmetric context
 *
 * @param sym_ctx [in] Reference to sym context implementation to be used to
 *		       perform sym calculation with.
 *
 * The caller must provide an allocated sym_ctx. This can be achieved by
 * using LCSYM_CTX_ON_STACK or by using sym_alloc.
 */
static inline void lc_sym_init(struct lc_sym_ctx *ctx)
{
	const struct lc_sym *sym = ctx->sym;

	sym->init(ctx->sym_state);
}

/**
 * @brief lc_sym_setkey - Set key
 *
 * @param ctx [in] Reference to sym context implementation to be used to
 *		   set the IV.
 * @param key [in] Key to be set
 * @param keylen [in] Key length to be set
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_sym_setkey(struct lc_sym_ctx *ctx,
				const uint8_t *key, size_t keylen)
{
	const struct lc_sym *sym = ctx->sym;

	return sym->setkey(ctx->sym_state, key, keylen);
}

/**
 * @brief lc_sym_setiv - Set IV
 *
 * @param ctx [in] Reference to sym context implementation to be used to
 *		   set the IV.
 * @param iv [in] IV to be set
 * @param ivlen [in] IV length to be set
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_sym_setiv(struct lc_sym_ctx *ctx,
			       const uint8_t *iv, size_t ivlen)
{
	const struct lc_sym *sym = ctx->sym;

	return sym->setiv(ctx->sym_state, iv, ivlen);
}

/**
 * @brief lc_sym_encrypt - Symmetric encryption
 *
 * @param ctx [in] Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 * @param in [in] Plaintext to be encrypted
 * @param out [out] Ciphertext resulting of the encryption
 * @param len [in] Size of the input / output buffer
 *
 * The plaintext and the ciphertext buffer may be identical to support
 * in-place cryptographic operations.
 */
static inline void lc_sym_encrypt(struct lc_sym_ctx *ctx,
			          const uint8_t *in, uint8_t *out, size_t len)
{
	const struct lc_sym *sym = ctx->sym;

	sym->encrypt(ctx->sym_state, in, out, len);
}

/**
 * @brief lc_sym_decrypt - AES KW decrypt
 *
 * @param ctx [in] Reference to sym context implementation to be used to
 *		   perform sym calculation with.
 * @param in [in] Ciphertext to be decrypted
 * @param out [out] Plaintext resulting of the decryption
 * @param len [in] Size of the input / output buffer
 *
 * The plaintext and the ciphertext buffer may be identical to support
 * in-place cryptographic operations.
 */
static inline void lc_sym_decrypt(struct lc_sym_ctx *ctx,
				  const uint8_t *in, uint8_t *out, size_t len)
{
	const struct lc_sym *sym = ctx->sym;

	sym->decrypt(ctx->sym_state, in, out, len);
}

/**
 * @brief Zeroize symmetric context allocated with either LC_SYM_CTX_ON_STACK
 *	  or lc_sym_alloc
 *
 * @param ctx [in] Symmetric context to be zeroized
 */
static inline void lc_sym_zero(struct lc_sym_ctx *ctx)
{
	const struct lc_sym *sym = ctx->sym;

	memset_secure((uint8_t *)ctx + sizeof(struct lc_sym_ctx), 0,
		      LC_SYM_STATE_SIZE(sym));
}

/**
 * @brief Allocate symmetric algorithm context on heap
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param sym [in] Symmetric algorithm implementation of type struct lc_sym
 * @param ctx [out] Allocated symmetrc algorithm context
 *
 * @return 0 on success, < 0 on error
 */
int lc_sym_alloc(const struct lc_sym *sym, struct lc_sym_ctx **ctx);

/**
 * @brief Symmetric algorithm deallocation and properly zeroization function to
 *	  frees all buffers and the cipher handle
 *
 * @param ctx [in] Symmtric algorithm context handle
 */
void lc_sym_zero_free(struct lc_sym_ctx *ctx);

/**
 * @brief Allocate stack memory for the sym context
 *
 * @param name [in] Name of the stack variable
 * @param symname [in] Pointer of type struct sym referencing the sym
 *			 implementation to be used
 */
#define LC_SYM_CTX_ON_STACK(name, symname)				       \
	LC_ALIGNED_SYM_BUFFER(name ## _ctx_buf, symname,		       \
			      LC_SYM_CTX_SIZE(symname), uint64_t);	       \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *) name ## _ctx_buf;      \
	LC_SYM_SET_CTX(name, symname);					       \
	lc_sym_zero(name)

#ifdef __cplusplus
}
#endif

#endif /* _LC_SYM_H */
