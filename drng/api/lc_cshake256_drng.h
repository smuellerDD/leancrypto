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

#ifndef LC_CSHAKE256_DRNG_H
#define LC_CSHAKE256_DRNG_H

#include "lc_cshake.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LC_CSHAKE256_DRNG_KEYSIZE	64

struct lc_cshake256_drng_state {
	uint8_t key[LC_CSHAKE256_DRNG_KEYSIZE];
};

#define LC_CSHAKE256_DRNG_MAX_CHUNK	(LC_SHA3_256_SIZE_BLOCK * 100)
#define LC_CSHAKE256_DRNG_STATE_SIZE	(sizeof(struct lc_cshake256_drng_state))
#define LC_CSHAKE256_DRNG_CTX_SIZE	(sizeof(struct lc_rng) +	       \
					 LC_CSHAKE256_DRNG_STATE_SIZE)

/* CSHAKE256-based DRNG */
extern const struct lc_rng *lc_cshake256_drng;

#define LC_CSHAKE256_RNG_CTX(name)					       \
	LC_RNG_CTX(name, lc_cshake256_drng);				       \
	lc_cshake256_drng->zero(name->rng_state)

/**
 * @brief Allocate stack memory for the CSHAKE256 DRNG context
 *
 * @param name [in] Name of the stack variable
 */
#define LC_CSHAKE256_DRNG_CTX_ON_STACK(name)				       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf,				       \
			  LC_CSHAKE256_DRNG_CTX_SIZE, uint64_t);	       \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name ## _ctx_buf;       \
	LC_CSHAKE256_RNG_CTX(name)

/**
 * @brief Allocation of a CSHAKE DRNG context
 *
 * @param state [out] CSHAKE DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * You need to seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_cshake256_drng_alloc(struct lc_rng_ctx **state);

#ifdef __cplusplus
}
#endif

#endif /* LC_CSHAKE256_DRNG_H */
