/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_CTR_DRBG_H
#define LC_CTR_DRBG_H

#include "lc_aes.h"
#include "lc_drbg.h"
#include "lc_memory_support.h"
#include "lc_rng.h"
#include "lc_sym.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT

#define LC_DRBG_KEYLEN (256 / 8) /* Only support CTR-DRBG 256 */
#define LC_DRBG_CTR_STATELEN (384 / 8)
#define LC_DRBG_CTR_BLOCKLEN (128 / 8)

#define LC_DRBG_CTR_SYM_STATE (244 + 48)

#define LC_DRBG_CTR_SCRATCHPAD_UPDATE                                          \
	(LC_DRBG_CTR_STATELEN + LC_DRBG_CTR_BLOCKLEN)
#define LC_DRBG_CTR_SCRATCHPAD_DF                                              \
	(2 * LC_DRBG_CTR_STATELEN + 3 * LC_DRBG_CTR_BLOCKLEN)
#define LC_DRBG_CTR_SCRATCHPAD_NODF LC_DRBG_CTR_STATELEN
#define LC_DRBG_CTR_SCRATCHPAD_USE_DF                                          \
	(LC_DRBG_CTR_SCRATCHPAD_UPDATE + LC_DRBG_CTR_SCRATCHPAD_DF +           \
	 LC_SYM_COMMON_ALIGNMENT)
#define LC_DRBG_CTR_SCRATCHPAD_NO_DF                                           \
	(LC_DRBG_CTR_SCRATCHPAD_UPDATE + LC_DRBG_CTR_SCRATCHPAD_NODF +         \
	 LC_SYM_COMMON_ALIGNMENT)

struct lc_drbg_ctr_state {
	struct lc_sym_ctx ctr_ctx; /* CTR Cipher handle */
	uint8_t ctr_state[LC_SYM_STATE_SIZE_LEN(LC_DRBG_CTR_SYM_STATE)];
	union { /* internal state 10.1.1.1 1a) */
		uint8_t V[LC_DRBG_CTR_BLOCKLEN];
		uint64_t V_64[LC_DRBG_CTR_BLOCKLEN / sizeof(uint64_t)];
	} ctr;
	uint8_t C[LC_DRBG_KEYLEN]; /* static value 10.1.1.1 1b) */

	unsigned int seeded : 1;
	unsigned int use_df : 1;

	/* working mem */
	uint8_t scratchpad_size;
	uint8_t *scratchpad;
};

#define LC_DRBG_CTR_STATE_SIZE_USE_DF                                          \
	(sizeof(struct lc_drbg_ctr_state) + LC_DRBG_CTR_SCRATCHPAD_USE_DF)
#define LC_DRBG_CTR_CTX_SIZE_USE_DF                                            \
	((unsigned long)(LC_DRBG_CTR_STATE_SIZE_USE_DF + sizeof(struct lc_rng)))

#define LC_DRBG_CTR_STATE_SIZE_NO_DF                                           \
	(sizeof(struct lc_drbg_ctr_state) + LC_DRBG_CTR_SCRATCHPAD_NO_DF)
#define LC_DRBG_CTR_CTX_SIZE_NO_DF                                             \
	((unsigned long)(LC_DRBG_CTR_STATE_SIZE_NO_DF + sizeof(struct lc_rng)))

#define _LC_DRBG_CTR_SET_CTX(name, ctx, offset, _use_df, _scratchpad_size)     \
	LC_SYM_SET_CTX((&(name)->ctr_ctx), lc_aes_ctr);                        \
	(name)->use_df = _use_df;                                              \
	(name)->scratchpad_size =                                              \
		(_scratchpad_size - LC_SYM_COMMON_ALIGNMENT);                  \
	(name)->scratchpad =                                                   \
		LC_ALIGN_PTR_8((uint8_t *)ctx + offset,                        \
			       LC_ALIGNMENT_MASK(LC_SYM_COMMON_ALIGNMENT));    \
	(name)->seeded = 0

#define LC_DRBG_CTR_SET_CTX(name, _use_df, _scratchpad_size)                   \
	_LC_DRBG_CTR_SET_CTX(name, name, sizeof(struct lc_drbg_ctr_state),     \
			     _use_df, _scratchpad_size)

extern const struct lc_rng *lc_ctr_drbg;

#define LC_DRBG_CTR_RNG_CTX(name, _use_df, _scratchpad_size)                   \
	LC_RNG_CTX(name, lc_ctr_drbg);                                         \
	LC_DRBG_CTR_SET_CTX((struct lc_drbg_ctr_state *)name->rng_state,       \
			    _use_df, _scratchpad_size);                        \
	lc_ctr_drbg->zero(name->rng_state)
/// \endcond

/**
 * @brief Allocate stack memory for the CTR DRBG with Derivation Function
 *	  context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_DRBG_CTR_USE_DF_CTX_ON_STACK(name)                                  \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_DRBG_CTR_CTX_SIZE_USE_DF, \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_DRBG_CTR_RNG_CTX(name, 1, LC_DRBG_CTR_SCRATCHPAD_USE_DF);           \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate stack memory for the CTR DRBG without Derivation Function
 *	  context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_DRBG_CTR_NO_DF_CTX_ON_STACK(name)                                   \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_DRBG_CTR_CTX_SIZE_NO_DF,  \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_DRBG_CTR_RNG_CTX(name, 0, LC_DRBG_CTR_SCRATCHPAD_NO_DF);            \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate CTR DRBG with Derivation Function context on heap
 *
 * @param [out] drbg Allocated CTR DRBG context
 *
 * \warning You MUST seed the DRNG!
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_ctr_use_df_alloc(struct lc_rng_ctx **drbg);

/**
 * @brief Allocate CTR DRBG without Derivation Function context on heap
 *
 * @param [out] drbg Allocated CTR DRBG context
 *
 * \warning You MUST seed the DRNG!
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_ctr_no_df_alloc(struct lc_rng_ctx **drbg);

#ifdef __cplusplus
}
#endif

#endif /* LC_CTR_DRBG_H */
