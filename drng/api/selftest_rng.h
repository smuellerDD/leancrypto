/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef SELFTEST_RNG_H
#define SELFTEST_RNG_H

#include "lc_hash.h"
#include "lc_rng.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_SELFTEST_DRNG_STATE_SIZE (LC_SHAKE_128_CTX_SIZE)
#define LC_SELFTEST_DRNG_CTX_SIZE                                              \
	(sizeof(struct lc_rng) + LC_SELFTEST_DRNG_STATE_SIZE)

extern const struct lc_rng *lc_selftest_drng;

#define LC_SELFTEST_HASH_SET_CTX(name) LC_SHAKE_128_CTX((name))

#define LC_SELFTEST_RNG_CTX(name)                                              \
	LC_RNG_CTX(name, lc_selftest_drng);                                    \
	LC_SELFTEST_HASH_SET_CTX((struct lc_hash_ctx *)name->rng_state);       \
	lc_rng_zero(name);                                                     \
	lc_hash_init(name->rng_state)

/*
 * The testing is based on the fact that,
 * - this "RNG" produces identical output
 *
 * WARNING: This RNG state is NOT meant to be used for any other purpose than
 * self tests!
 */
#define LC_SELFTEST_DRNG_CTX_ON_STACK(name)                                    \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_SELFTEST_DRNG_CTX_SIZE,   \
				  LC_HASH_COMMON_ALIGNMENT);                   \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_SELFTEST_RNG_CTX(name);                                             \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* SELFTEST_RNG_H */
