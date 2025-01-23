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

#ifndef LC_SHA256_H
#define LC_SHA256_H

#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @var lc_sha256
 * @brief SHA2-256 algorithm reference
 */
extern const struct lc_hash *lc_sha256;

/// \cond DO_NOT_DOCUMENT
#define LC_SHA256_SIZE_BLOCK 64
#define LC_SHA256_SIZE_DIGEST 32

struct lc_sha256_state {
	uint32_t H[8];
	size_t msg_len;
	uint8_t partial[LC_SHA256_SIZE_BLOCK];
};

#define LC_SHA256_STATE_SIZE (sizeof(struct lc_sha256_state))
#define LC_SHA256_CTX_SIZE (sizeof(struct lc_hash) + LC_SHA256_STATE_SIZE)

#define LC_SHA256_CTX(name)                                                    \
	LC_HASH_SET_CTX(name, lc_sha256);                                      \
	lc_hash_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the SHA256 context without VLA
 *
 * @param [in] name Name of the stack variable
 */
#define LC_SHA256_CTX_ON_STACK(name)                                                \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf, LC_SHA256_CTX_SIZE,       \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name##_ctx_buf;            \
	LC_SHA256_CTX(name);                                                        \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_SHA256_H */
