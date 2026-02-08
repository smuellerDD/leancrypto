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

#ifndef _LC_CHACHA20_DRNG_H
#define _LC_CHACHA20_DRNG_H

#include "ext_headers.h"
#include "lc_chacha20.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_chacha20_drng_ctx {
	struct lc_sym_ctx cc20;
};

/* ChaCha20-based DRNG */
extern const struct lc_rng *lc_cc20_drng;

#define LC_CC20_DRNG_SYM_STATE_SIZE (LC_SYM_CTX_SIZE_NONALIGNED(lc_chacha20))
#define LC_CC20_DRNG_STATE_SIZE                                                \
	(LC_CC20_DRNG_SYM_STATE_SIZE + sizeof(struct lc_chacha20_drng_ctx))
#define LC_CC20_DRNG_CTX_SIZE (sizeof(struct lc_rng) + LC_CC20_DRNG_STATE_SIZE)

#define _LC_CC20_DRNG_SET_CTX(name, ctx, offset)                               \
	_LC_SYM_SET_CTX((&name->cc20), lc_chacha20, ctx, offset)

#define LC_CC20_DRNG_SET_CTX(name)                                             \
	LC_RNG_CTX(name, lc_cc20_drng);                                        \
	struct lc_chacha20_drng_ctx *__name = name->rng_state;                 \
	_LC_CC20_DRNG_SET_CTX(__name, __name,                                  \
			      sizeof(struct lc_chacha20_drng_ctx));            \
	lc_cc20_drng->zero(name->rng_state)
/// \endcond

/**
 * @brief Allocate stack memory for the ChaCha20 context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_CC20_DRNG_CTX_ON_STACK(name)                                             \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CC20_DRNG_CTX_SIZE,                    \
					  LC_SYM_COMMON_ALIGNMENT);                 \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;              \
	LC_CC20_DRNG_SET_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocation of a ChaCha20 DRNG context
 *
 * @param [out] state RNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_cc20_drng_alloc(struct lc_rng_ctx **state);

#ifdef __cplusplus
}
#endif

#endif /* _LC_CHACHA20_DRNG_H */
