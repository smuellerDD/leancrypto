/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_HASH_H
#define LC_HASH_H

#include "ext_headers.h"
#include "lc_memset_secure.h"
#include "lc_memory_support.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_hash {
	/* SHA3 / SHAKE interface */
	void (*init)(void *state);
	void (*update)(void *state, const uint8_t *in, size_t inlen);
	void (*final)(void *state, uint8_t *digest);
	void (*set_digestsize)(void *state, size_t digestsize);
	size_t (*get_digestsize)(void *state);

	/* Keccak interface */
	void (*keccak_permutation)(void *state);
	void (*keccak_add_bytes)(void *state, const uint8_t *data,
				 unsigned int offset, unsigned int length);
	void (*keccak_extract_bytes)(const void *state, uint8_t *data,
				     size_t offset, size_t length);
	void (*keccak_newstate)(void *state, const uint8_t *newstate,
				size_t offset, size_t length);

	uint8_t rate;
	unsigned short statesize;
};

struct lc_hash_ctx {
	const struct lc_hash *hash;
	void *hash_state;
};

/*
 * Align the hash_state pointer to 8 bytes boundary irrespective where
 * it is embedded into. This is achieved by adding 7 more bytes than necessary
 * to LC_ALIGNED_SYM_BUFFER and then adjusting the pointer offset in that range
 * accordingly.
 *
 * It is permissible to set the alignment requirement with compile-time
 * arguments.
 */
#ifndef LC_HASH_COMMON_ALIGNMENT
#ifdef __arm__
/* Required by NEON 32-bit implementation */
#define LC_HASH_COMMON_ALIGNMENT (32)
#else
#define LC_HASH_COMMON_ALIGNMENT (8)
#endif
#endif

#define LC_ALIGN_HASH_MASK(p)                                                  \
	LC_ALIGN_PTR_64(p, LC_ALIGNMENT_MASK(LC_HASH_COMMON_ALIGNMENT))

#define LC_SHA_MAX_SIZE_DIGEST 64

/*
 * This is the source of the compiler warning of using Variable-Length-Arrays
 * (VLA). It is considered to be harmless to have this VLA here. If you do not
 * want it, you have the following options:
 *
 * 1. Define a hard-coded value here, e.g. sizeof(struct lc_sha3_224_state)
 *    as the SHA3-224 has the largest structure.
 * 2. Only use the SHA-specific stack allocation functions
 *    (e.g. LC_SHA3_256_CTX_ON_STACK) instead of the generic
 *    LC_HASH_CTX_ON_STACK call.
 * 3. Do not use stack-allocation function.
 * 4. Ignore the warning by using
 * #pragma GCC diagnostic ignored "-Wvla"
 * #pragma GCC diagnostic push
 * LC_HASH_CTX_ON_STACK()
 * #pragma pop
 */
#define LC_HASH_STATE_SIZE_NONALIGNED(x) ((unsigned long)(x->statesize))
#define LC_HASH_STATE_SIZE(x)                                                  \
	(LC_HASH_STATE_SIZE_NONALIGNED(x) + LC_HASH_COMMON_ALIGNMENT)
#define LC_HASH_CTX_SIZE(x) (sizeof(struct lc_hash_ctx) + LC_HASH_STATE_SIZE(x))

#define _LC_HASH_SET_CTX(name, hashname, ctx, offset)                          \
	name->hash_state = LC_ALIGN_HASH_MASK(((uint8_t *)(ctx)) + (offset));  \
	name->hash = hashname

#define LC_HASH_SET_CTX(name, hashname)                                        \
	_LC_HASH_SET_CTX(name, hashname, name, sizeof(struct lc_hash_ctx))

/**
 * Concept of hashes in leancrypto
 *
 * All hashes can be used with the API calls documented below. However,
 * the allocation part is hash-specific. Thus, perform the following steps
 *
 * 1. Allocation: Use the stack or heap allocation functions documented in
 *    lc_cshake256.h, lc_sha3.h, lc_sha256.h, lc_sha512.h.
 *
 * 2. Use the returned cipher handle with the API calls below.
 */

/**
 * @brief Initialize hash context
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 *
 * The caller must provide an allocated hash_ctx. This can be achieved by
 * using LC_HASH_CTX_ON_STACK or by using hash_alloc.
 */
static inline void lc_hash_init(struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	hash->init(hash_ctx->hash_state);
}

/**
 * @brief Update hash
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
static inline void lc_hash_update(struct lc_hash_ctx *hash_ctx,
				  const uint8_t *in, size_t inlen)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	hash->update(hash_ctx->hash_state, in, inlen);
}

/**
 * @brief Calculate message digest
 *
 * For SHAKE, it is permissible to calculate the final digest in chunks by
 * invoking the message digest calculation multiple times. The following code
 * example illustrates it:
 *
 * ```
 * size_t outlen = full_size;
 *
 * lc_hash_init(ctx);
 * lc_hash_update(ctx, msg, msg_len);
 * // Set an arbitrary digest size as needed
 * lc_hash_set_digestsize(ctx, 42);
 * for (len = outlen; len > 0;
 *      len -= lc_hash_digestsize(ctx),
 *      out += lc_hash_digestsize(ctx)) {
 *          if (len < lc_hash_digestsize(ctx))
 *                  lc_hash_set_digestsize(ctx, len);
 *          lc_hash_final(ctx, out);
 * }
 * ```
 *
 * See the test `shake_squeeze_more_tester.c` for an example.
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [out] digest Buffer with at least the size of the message digest.
 */
static inline void lc_hash_final(struct lc_hash_ctx *hash_ctx, uint8_t *digest)
{
	const struct lc_hash *hash;

	if (!hash_ctx || !digest)
		return;

	hash = hash_ctx->hash;
	hash->final(hash_ctx->hash_state, digest);
}

/**
 * @brief Set the size of the message digest - this call is intended for SHAKE
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [in] digestsize Size of the requested digest.
 */
static inline void lc_hash_set_digestsize(struct lc_hash_ctx *hash_ctx,
					  size_t digestsize)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	if (hash->set_digestsize)
		hash->set_digestsize(hash_ctx->hash_state, digestsize);
}

/**
 * @brief Get the size of the message digest
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 */
static inline size_t lc_hash_digestsize(struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->get_digestsize(hash_ctx->hash_state);
}

/**
 * @brief Get the block size of the message digest (or the "rate" in terms of
 *	  Keccak-based algorithms)
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 */
static inline unsigned int lc_hash_blocksize(struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->rate;
}

/**
 * @brief Get the context size of the message digest implementation
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 */
static inline unsigned int lc_hash_ctxsize(struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->statesize;
}

/**
 * @brief Zeroize Hash context allocated with either LC_HASH_CTX_ON_STACK or
 *	  lc_hmac_alloc
 *
 * @param [in] hash_state Hash context to be zeroized
 */
static inline void lc_hash_zero(struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	lc_memset_secure((uint8_t *)hash_ctx + sizeof(struct lc_hash_ctx), 0,
			 hash->statesize);
}

/**
 * @brief Allocate stack memory for the hash context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_HASH_CTX_ON_STACK(name, hashname)                                        \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_HASH_CTX_SIZE(hashname),               \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;            \
	LC_HASH_SET_CTX(name, hashname);                                            \
	lc_hash_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate Hash context on heap
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    hash calculation with.
 * @param [out] hash_ctx Allocated hash context
 *
 * @return: 0 on success, < 0 on error
 */
int lc_hash_alloc(const struct lc_hash *hash, struct lc_hash_ctx **hash_ctx);

/**
 * @brief Zeroize and free hash context
 *
 * @param [in] hash_ctx hash context to be zeroized and freed
 */
void lc_hash_zero_free(struct lc_hash_ctx *hash_ctx);

/**
 * @brief Calculate message digest - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    hash calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [out] digest Buffer with at least the size of the message digest.
 *
 * The hash calculation operates entirely on the stack.
 */
void lc_hash(const struct lc_hash *hash, const uint8_t *in, size_t inlen,
	     uint8_t *digest);

/**
 * @brief Calculate message digest for SHAKE - one-shot
 *
 * @param [in] shake Reference to hash implementation to be used to perform
 *		     hash calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [out] digest Buffer with at least the size of the message digest.
 * @param [in] digestlen Size of the message digest to calculate.
 *
 * The hash calculation operates entirely on the stack.
 */
void lc_shake(const struct lc_hash *shake, const uint8_t *in, size_t inlen,
	      uint8_t *digest, size_t digestlen);

/**
 * @brief Perform Keccak permutation on buffer
 *
 * WARNING: This call does NOT constitude SHA-3, or SHAKE. It is ONLY a raw
 *	    Keccak permutation with the accelerated implementation of the given
 *	    hash reference. If you do not understand this comment, you
 *	    MUST NOT use this interface.
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    Keccak calculation with.
 * @param [in] state State buffer of 200 bytes aligned to
 *		     LC_HASH_COMMON_ALIGNMENT.
 *
 * @return: 0 on success, < 0 on error
 */
static inline int lc_keccak(const struct lc_hash *hash, void *state)
{
	if (!state || !hash || !hash->keccak_permutation)
		return -EOPNOTSUPP;

	hash->keccak_permutation(state);

	return 0;
}

/**
 * @brief Function to add (in GF(2), using bitwise exclusive-or) data given
 *	  as bytes into the state.
 *
 * The bit positions that are affected by this function are
 * from @a offset*8 to @a offset*8 + @a length*8.
 *
 * (The bit positions, the x,y,z coordinates and their link are defined in the
 * "Keccak reference".)
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    Keccak calculation with.
 * @param [in] state Pointer to the state.
 * @param [in] data Pointer to the input data.
 * @param [in] offset Offset in bytes within the state.
 * @param [in] length Number of bytes.
 *
 * WARNING: The caller is responsible that offset / length points to data
 * within the state (within the size of LC_SHA3_STATE_SIZE).
 *
 * @pre 0 ≤ @a offset < (width in bytes)
 * @pre 0 ≤ @a offset + @a length ≤ (width in bytes)
 *
 * @return: 0 on success, < 0 on error
 */
static inline int lc_keccak_add_bytes(const struct lc_hash *hash, void *state,
				      const uint8_t *data, unsigned int offset,
				      unsigned int length)
{
	if (!state || !hash || !hash->keccak_add_bytes)
		return -EOPNOTSUPP;

	hash->keccak_add_bytes(state, data, offset, length);

	return 0;
}

/**
 * @brief Function to retrieve data from the state. The bit positions that are
 *	  retrieved by this function are from
 *	  @a offset*8 to @a offset*8 + @a length*8.
 *	  (The bit positions, the x,y,z coordinates and their link are defined
 *	  in the "Keccak reference".)
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    Keccak calculation with.
 * @param [in] state Pointer to the state.
 * @param [out] data Pointer to the area where to store output data.
 * @param [in] offset Offset in bytes within the state.
 * @param [in] length Number of bytes.
 *
 * WARNING: The caller is responsible that offset / length points to data
 * within the state (within the size of LC_SHA3_STATE_SIZE).
 *
 * @pre 0 ≤ @a offset < (width in bytes)
 * @pre 0 ≤ @a offset + @a length ≤ (width in bytes)
 *
 * @return: 0 on success, < 0 on error
 */
static inline int lc_keccak_extract_bytes(const struct lc_hash *hash,
					  const void *state, uint8_t *data,
					  size_t offset, size_t length)
{
	if (!state || !hash || !hash->keccak_extract_bytes)
		return -EOPNOTSUPP;

	hash->keccak_extract_bytes(state, data, offset, length);

	return 0;
}

/**
 * @brief Function to insert a complete new Keccak state
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    Keccak calculation with.
 * @param [in] state Pointer to the state.
 * @param [out] data Pointer to new state
 * @param [in] offset Offset in bytes within the state.
 * @param [in] length Number of bytes.
 *
 * WARNING: The caller is responsible that offset / length points to data
 * within the state (within the size of LC_SHA3_STATE_SIZE).
 *
 * @return: 0 on success, < 0 on error
 */
static inline int lc_keccak_newstate(const struct lc_hash *hash, void *state,
				     const uint8_t *data, size_t offset,
				     size_t length)
{
	if (!state || !hash || !hash->keccak_newstate)
		return -EOPNOTSUPP;

	hash->keccak_newstate(state, data, offset, length);

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_H */
