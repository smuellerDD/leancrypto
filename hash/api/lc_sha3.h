/*
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_SHA3_H
#define LC_SHA3_H

#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_SHA3_SIZE_RATE(bits) ((1600 - 2 * bits) >> 3)
#define LC_SHA3_STATE_WORDS 25
#define LC_SHA3_STATE_SIZE (LC_SHA3_STATE_WORDS * sizeof(uint64_t))

#define LC_SHA3_STATE_SIZE_ALIGN(x) (x + LC_HASH_COMMON_ALIGNMENT)
/// \endcond

/********************************** SHA3-224 **********************************/

/**
 * @var lc_sha3_224
 * @brief SHA3-224 algorithm reference
 */
extern const struct lc_hash *lc_sha3_224;

/// \cond DO_NOT_DOCUMENT
#define LC_SHA3_224_SIZE_DIGEST_BITS 224
#define LC_SHA3_224_SIZE_DIGEST (LC_SHA3_224_SIZE_DIGEST_BITS >> 3)
#define LC_SHA3_224_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHA3_224_SIZE_DIGEST_BITS)

struct lc_sha3_224_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	uint8_t offset;
	uint8_t r;
	uint8_t rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;
};

#define LC_SHA3_224_STATE_SIZE (sizeof(struct lc_sha3_224_state))
#define LC_SHA3_224_CTX_SIZE                                                   \
	(sizeof(struct lc_hash_ctx) + LC_SHA3_224_STATE_SIZE)

#define LC_SHA3_224_CTX(name)                                                  \
	LC_HASH_SET_CTX(name, lc_sha3_224);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHA3_224 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHA3_224_CTX_ON_STACK(name)                                         \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_224_CTX_SIZE),        \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHA3_224_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/********************************** SHA3-256 **********************************/

/**
 * @var lc_sha3_256
 * @brief SHA3-256 algorithm reference
 */
extern const struct lc_hash *lc_sha3_256;

/// \cond DO_NOT_DOCUMENT
#define LC_SHA3_256_SIZE_DIGEST_BITS 256
#define LC_SHA3_256_SIZE_DIGEST (LC_SHA3_256_SIZE_DIGEST_BITS >> 3)
#define LC_SHA3_256_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHA3_256_SIZE_DIGEST_BITS)

struct lc_sha3_256_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	uint8_t offset;
	uint8_t r;
	uint8_t rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;
};

#define LC_SHA3_256_STATE_SIZE (sizeof(struct lc_sha3_256_state))
#define LC_SHA3_256_CTX_SIZE (sizeof(struct lc_hash) + LC_SHA3_256_STATE_SIZE)

#define LC_SHA3_256_CTX(name)                                                  \
	LC_HASH_SET_CTX(name, lc_sha3_256);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHA3_256 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHA3_256_CTX_ON_STACK(name)                                         \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_256_CTX_SIZE),        \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHA3_256_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/********************************** SHA3-384 **********************************/

/**
 * @var lc_sha3_384
 * @brief SHA3-384 algorithm reference
 */
extern const struct lc_hash *lc_sha3_384;

/// \cond DO_NOT_DOCUMENT
#define LC_SHA3_384_SIZE_DIGEST_BITS 384
#define LC_SHA3_384_SIZE_DIGEST (LC_SHA3_384_SIZE_DIGEST_BITS >> 3)
#define LC_SHA3_384_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHA3_384_SIZE_DIGEST_BITS)

struct lc_sha3_384_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	uint8_t offset;
	uint8_t r;
	uint8_t rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;
};

#define LC_SHA3_384_STATE_SIZE (sizeof(struct lc_sha3_384_state))
#define LC_SHA3_384_CTX_SIZE (sizeof(struct lc_hash) + LC_SHA3_384_STATE_SIZE)

#define LC_SHA3_384_CTX(name)                                                  \
	LC_HASH_SET_CTX(name, lc_sha3_384);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHA3_384 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHA3_384_CTX_ON_STACK(name)                                         \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_384_CTX_SIZE),        \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHA3_384_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/********************************** SHA3-512 **********************************/

/**
 * @var lc_sha3_512
 * @brief SHA3-512 algorithm reference
 */
extern const struct lc_hash *lc_sha3_512;

/// \cond DO_NOT_DOCUMENT
#define LC_SHA3_512_SIZE_DIGEST_BITS 512
#define LC_SHA3_512_SIZE_DIGEST (LC_SHA3_512_SIZE_DIGEST_BITS >> 3)
#define LC_SHA3_512_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHA3_512_SIZE_DIGEST_BITS)

struct lc_sha3_512_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	uint8_t offset;
	uint8_t r;
	uint8_t rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;
};

#define LC_SHA3_512_STATE_SIZE (sizeof(struct lc_sha3_512_state))
#define LC_SHA3_512_CTX_SIZE (sizeof(struct lc_hash) + LC_SHA3_512_STATE_SIZE)

#define LC_SHA3_512_CTX(name)                                                  \
	LC_HASH_SET_CTX(name, lc_sha3_512);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHA3_512 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHA3_512_CTX_ON_STACK(name)                                         \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_512_CTX_SIZE),        \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHA3_512_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/********************************* SHAKE-128 **********************************/

/**
 * @var lc_shake128
 * @brief SHAKE128 algorithm reference
 */
extern const struct lc_hash *lc_shake128;

/// \cond DO_NOT_DOCUMENT
#define LC_SHAKE_128_SIZE_DIGEST_BITS 128
#define LC_SHAKE_128_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHAKE_128_SIZE_DIGEST_BITS)

struct lc_shake_128_state {
	uint64_t state[LC_SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	uint8_t offset;
	uint8_t r;
	uint8_t rword;
	uint8_t padding;
	uint8_t squeeze_more : 1;
};

#define LC_SHAKE_128_STATE_SIZE (sizeof(struct lc_shake_128_state))
#define LC_SHAKE_128_CTX_SIZE (sizeof(struct lc_hash) + LC_SHAKE_128_STATE_SIZE)

#define LC_SHAKE_128_CTX(name)                                                 \
	LC_HASH_SET_CTX(name, lc_shake128);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHAKE-128 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHAKE_128_CTX_ON_STACK(name)                                        \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHAKE_128_CTX_SIZE),       \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHAKE_128_CTX(name);                                                \
	_Pragma("GCC diagnostic pop")

/********************************* SHAKE-256 **********************************/

/**
 * @var lc_shake256
 * @brief SHAKE256 algorithm reference
 */
extern const struct lc_hash *lc_shake256;

/// \cond DO_NOT_DOCUMENT
#define LC_SHAKE_256_SIZE_DIGEST_BITS 256
#define LC_SHAKE_256_SIZE_BLOCK LC_SHA3_SIZE_RATE(LC_SHAKE_256_SIZE_DIGEST_BITS)

#define LC_SHAKE_256_CTX_SIZE LC_SHA3_256_CTX_SIZE

#define LC_SHAKE_256_CTX(name)                                                 \
	LC_HASH_SET_CTX(name, lc_shake256);                                    \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHAKE-256 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHAKE_256_CTX_ON_STACK(name)                                        \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHAKE_256_CTX_SIZE),       \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_SHAKE_256_CTX(name);                                                \
	_Pragma("GCC diagnostic pop")

/********************************* cSHAKE-256 *********************************/

/**
 * @var lc_cshake256
 * @brief cSHAKE256 algorithm reference
 */
extern const struct lc_hash *lc_cshake256;

/// \cond DO_NOT_DOCUMENT

#define LC_CSHAKE_256_CTX(name)                                                \
	LC_HASH_SET_CTX(name, lc_cshake256);                                   \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the cSHAKE-256 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_CSHAKE_256_CTX_ON_STACK(name)                                       \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_256_CTX_SIZE),        \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_CSHAKE_256_CTX(name);                                               \
	_Pragma("GCC diagnostic pop")

/********************************* cSHAKE-128 *********************************/

/**
 * @var lc_cshake128
 * @brief cSHAKE128 algorithm reference
 */
extern const struct lc_hash *lc_cshake128;

/// \cond DO_NOT_DOCUMENT
#define LC_CSHAKE_128_CTX(name)                                                \
	LC_HASH_SET_CTX(name, lc_cshake128);                                   \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the cSHAKE-256 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_CSHAKE_128_CTX_ON_STACK(name)                                       \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(                                             \
			name##_ctx_buf,                                        \
			LC_SHA3_STATE_SIZE_ALIGN(LC_SHAKE_128_CTX_SIZE),       \
			LC_HASH_COMMON_ALIGNMENT);                             \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;       \
	LC_CSHAKE_128_CTX(name);                                               \
	_Pragma("GCC diagnostic pop")

/* Largest block size we support */
#define LC_SHA3_MAX_SIZE_BLOCK LC_SHA3_224_SIZE_BLOCK

#ifdef __cplusplus
}
#endif

#endif /* LC_SHA3_H */
