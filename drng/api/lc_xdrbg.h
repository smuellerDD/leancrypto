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

#ifndef LC_XDRBG256_DRNG_H
#define LC_XDRBG256_DRNG_H

#include "lc_ascon_hash.h"
#include "lc_sha3.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_XDRBG_DRNG_INITIALLY_SEEDED 0x80
#define LC_XDRBG_DRNG_KEYSIZE_MASK 0x7F

struct lc_xdrbg_drng_state {
	uint16_t chunksize;
	uint8_t status;
	/*
	 * NOTE: keep the lc_hash pointer before the v variable, because
	 * lc_hash is aligned to 8 bytes and has a size of 8 bytes. This ensures
	 * that v is aligned to 8 bytes as well.
	 */
	const struct lc_hash *xof;
	uint8_t v[];
};

/* XDRBG-based DRNG */
extern const struct lc_rng *lc_xdrbg_drng;

/* Helper, do not call directly */
#define LC_XDRBG_DRNG_CTX_ON_STACK(name)                                       \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_XDRBG256_DRNG_CTX_SIZE,   \
				  LC_HASH_COMMON_ALIGNMENT);                   \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	_Pragma("GCC diagnostic pop")

#define LC_XDRBG256_DRNG_KEYSIZE 64
/*
 * For streamlining the access requests, the max chunk size plus the key size
 * should be a full multiple of the SHAKE rate. As the key size is not
 * exactly the rate size, the chunk size needs to consider it
 */
#define LC_XDRBG256_DRNG_MAX_CHUNK                                             \
	(LC_SHAKE_256_SIZE_BLOCK * 2 - LC_XDRBG256_DRNG_KEYSIZE)
#define LC_XDRBG256_DRNG_STATE_SIZE                                            \
	(sizeof(struct lc_xdrbg_drng_state) + LC_XDRBG256_DRNG_KEYSIZE)
#define LC_XDRBG256_DRNG_CTX_SIZE                                              \
	(sizeof(struct lc_rng) + LC_XDRBG256_DRNG_STATE_SIZE)

#define LC_XDRBG256_RNG_CTX(name)                                              \
	LC_RNG_CTX(name, lc_xdrbg_drng);                                       \
	struct lc_xdrbg_drng_state *__name = name->rng_state;                  \
	__name->status = LC_XDRBG256_DRNG_KEYSIZE;                             \
	__name->xof = lc_shake256;                                             \
	__name->chunksize = LC_XDRBG256_DRNG_MAX_CHUNK;                        \
	lc_xdrbg_drng->zero(name->rng_state);
/// \endcond

/**
 * @brief Allocate stack memory for the XDRBG256 DRNG context
 *
 * XDRBG 256 definition using SHAKE-256 providing the following security level:
 *
 * 	* classical: 256 bits of security
 *
 * 	* quantum (Grover): 128 bits of security
 *
 * 	* category: NIST level 5
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_XDRBG256_DRNG_CTX_ON_STACK(name)                                    \
	LC_XDRBG_DRNG_CTX_ON_STACK(name);                                      \
	LC_XDRBG256_RNG_CTX(name)

/**
 * @brief Allocation of a XDRBG256 DRNG context using SHAKE-256
 *
 * @param [out] state XDRBG256 DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_xdrbg256_drng_alloc(struct lc_rng_ctx **state);

/// \cond DO_NOT_DOCUMENT
#define LC_XDRBG128_DRNG_KEYSIZE 32

/*
 * For streamlining the access requests, the max chunk size plus the key size
 * should be a full multiple of the Ascon rate. As the key size is already
 * exactly the rate size, the chunk size does not need to consider it.
 */
#define LC_XDRBG128_DRNG_MAX_CHUNK (LC_ASCON_HASH_RATE * 32)
#define LC_XDRBG128_DRNG_STATE_SIZE                                            \
	(sizeof(struct lc_xdrbg_drng_state) + LC_XDRBG128_DRNG_KEYSIZE)
#define LC_XDRBG128_DRNG_CTX_SIZE                                              \
	(sizeof(struct lc_rng) + LC_XDRBG128_DRNG_STATE_SIZE)

#define LC_XDRBG128_RNG_CTX(name)                                              \
	LC_RNG_CTX(name, lc_xdrbg_drng);                                       \
	struct lc_xdrbg_drng_state *__name = name->rng_state;                  \
	__name->status = LC_XDRBG128_DRNG_KEYSIZE;                             \
	__name->xof = lc_ascon_xof;                                            \
	__name->chunksize = LC_XDRBG128_DRNG_MAX_CHUNK;                        \
	lc_xdrbg_drng->zero(name->rng_state);
/// \endcond

/**
 * @brief Allocate stack memory for the XDRBG128 DRNG context
 *
 * XDRBG 128 definition using Ascon-XOF to provide a lightweight algorithm
 * providing the following security level:
 *
 * 	* classical: 128 bits of security
 *
 * 	* quantum (Grover): 64 bits of security
 *
 * 	* category: NIST level 1
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_XDRBG128_DRNG_CTX_ON_STACK(name)                                    \
	LC_XDRBG_DRNG_CTX_ON_STACK(name);                                      \
	LC_XDRBG128_RNG_CTX(name)

/**
 * @brief Allocation of a XDRBG128 DRNG context using Ascon-XOF
 *
 * @param [out] state XDRBG128 DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_xdrbg128_drng_alloc(struct lc_rng_ctx **state);

#ifdef __cplusplus
}
#endif

#endif /* LC_XDRBG256_DRNG_H */
