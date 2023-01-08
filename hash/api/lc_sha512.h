/*
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_SHA512_H
#define LC_SHA512_H

#include "lc_hash.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LC_SHA512_SIZE_BLOCK	128
#define LC_SHA512_SIZE_DIGEST	64

struct lc_sha512_state {
	uint64_t H[8];
	size_t msg_len;
	uint8_t partial[LC_SHA512_SIZE_BLOCK];
};

#define LC_SHA512_STATE_SIZE		(sizeof(struct lc_sha512_state))
#define LC_SHA512_CTX_SIZE		(sizeof(struct lc_hash) +	       \
					 LC_SHA512_STATE_SIZE)

extern const struct lc_hash *lc_sha512;

#define LC_SHA512_CTX(name)						       \
	LC_HASH_CTX(name, lc_sha512);					       \
	lc_hash_zero(name)

/**
 * @brief Allocate stack memory for the SHA512 context without VLA
 *
 * @param name [in] Name of the stack variable
 */
#define LC_SHA512_CTX_ON_STACK(name)					       \
	_Pragma("GCC diagnostic push")					       \
	_Pragma("GCC diagnostic ignored \"-Wvla\"")	      		       \
	_Pragma("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_SHA512_CTX_SIZE,		       \
			  LC_HASH_COMMON_ALIGNMENT);			       \
	struct lc_hash_ctx *name = (struct lc_hash_ctx *)name ## _ctx_buf;     \
	LC_SHA512_CTX(name);						       \
	_Pragma("GCC diagnostic pop")


#ifdef __cplusplus
}
#endif

#endif /* LC_SHA512_H */
