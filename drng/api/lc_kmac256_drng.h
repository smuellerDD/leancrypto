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

#ifndef LC_KMAC256_DRNG_H
#define LC_KMAC256_DRNG_H

#include "lc_kmac.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_KMAC256_DRNG_KEYSIZE 64

struct lc_kmac256_drng_state {
	uint8_t initially_seeded;
	uint8_t key[LC_KMAC256_DRNG_KEYSIZE];
};

#define LC_KMAC256_DRNG_MAX_CHUNK (LC_SHA3_256_SIZE_BLOCK * 2)
#define LC_KMAC256_DRNG_STATE_SIZE (sizeof(struct lc_kmac256_drng_state))
#define LC_KMAC256_DRNG_CTX_SIZE                                               \
	(sizeof(struct lc_rng) + LC_KMAC256_DRNG_STATE_SIZE)

/* KMAC256-based DRNG */
extern const struct lc_rng *lc_kmac256_drng;

#define LC_KMAC256_RNG_CTX(name)                                               \
	LC_RNG_CTX(name, lc_kmac256_drng);                                     \
	lc_kmac256_drng->zero(name->rng_state)
/// \endcond

/**
 * @brief Allocate stack memory for the KMAC256 DRNG context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_KMAC256_DRNG_CTX_ON_STACK(name)                                     \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_KMAC256_DRNG_CTX_SIZE,    \
				  LC_HASH_COMMON_ALIGNMENT);                   \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_KMAC256_RNG_CTX(name);                                              \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocation of a KMAC DRNG context
 *
 * @param [out] state KMAC DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_kmac256_drng_alloc(struct lc_rng_ctx **state);

#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC256_DRNG_H */
