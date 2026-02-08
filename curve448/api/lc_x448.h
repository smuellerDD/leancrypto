/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_X448_H
#define LC_X448_H

#include "lc_rng.h"
#include "lc_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_X448_SECRETKEYBYTES (56U)
#define LC_X448_PUBLICKEYBYTES (56U)
#define LC_X448_SSBYTES (56U)

struct lc_x448_sk {
	uint8_t sk[LC_X448_SECRETKEYBYTES];
};

struct lc_x448_pk {
	uint8_t pk[LC_X448_PUBLICKEYBYTES];
};

struct lc_x448_ss {
	uint8_t ss[LC_X448_SSBYTES];
};

int lc_x448_keypair(struct lc_x448_pk *pk, struct lc_x448_sk *sk,
		    struct lc_rng_ctx *rng_ctx);
int lc_x448_ss(struct lc_x448_ss *ss, const struct lc_x448_pk *pk,
	       const struct lc_x448_sk *sk);

enum lc_x448_alg_operation {
	/** Unknown operation */
	lc_alg_operation_x448_unknown,
	/** ED448: key generation operation */
	lc_alg_operation_x448_keygen,
	/** ED448: shared secret generation operation */
	lc_alg_operation_x448_ss,
};

/**
 * @brief Obtain algorithm status
 *
 * @param [in] operation X448 algorithm type
 *
 * @return algorithm status
 */
enum lc_alg_status_val
lc_x448_alg_status(const enum lc_x448_alg_operation operation);

#ifdef __cplusplus
}
#endif

#endif /* LC_X448_H */
