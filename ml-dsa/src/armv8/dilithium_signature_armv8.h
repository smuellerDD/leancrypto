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

#ifndef DILITHIUM_SIGNATURE_ARMV8_H
#define DILITHIUM_SIGNATURE_ARMV8_H

#include "dilithium_type.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_dilithium_keypair_armv8(struct lc_dilithium_pk *pk,
			       struct lc_dilithium_sk *sk,
			       struct lc_rng_ctx *rng_ctx);
int lc_dilithium_keypair_from_seed_armv8(struct lc_dilithium_pk *pk,
					 struct lc_dilithium_sk *sk,
					 const uint8_t *seed, size_t seedlen);

int lc_dilithium_sign_armv8(struct lc_dilithium_sig *sig, const uint8_t *m,
			    size_t mlen, const struct lc_dilithium_sk *sk,
			    struct lc_rng_ctx *rng_ctx);

int lc_dilithium_sign_ctx_armv8(struct lc_dilithium_sig *sig,
				struct lc_dilithium_ctx *ctx, const uint8_t *m,
				size_t mlen, const struct lc_dilithium_sk *sk,
				struct lc_rng_ctx *rng_ctx);
int lc_dilithium_sign_init_armv8(struct lc_dilithium_ctx *ctx,
				 const struct lc_dilithium_sk *sk);
int lc_dilithium_sign_update_armv8(struct lc_dilithium_ctx *ctx,
				   const uint8_t *m, size_t mlen);
int lc_dilithium_sign_final_armv8(struct lc_dilithium_sig *sig,
				  struct lc_dilithium_ctx *ctx,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx);

int lc_dilithium_verify_armv8(const struct lc_dilithium_sig *sig,
			      const uint8_t *m, size_t mlen,
			      const struct lc_dilithium_pk *pk);
int lc_dilithium_verify_ctx_armv8(const struct lc_dilithium_sig *sig,
				  struct lc_dilithium_ctx *ctx,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_pk *pk);
int lc_dilithium_verify_init_armv8(struct lc_dilithium_ctx *ctx,
				   const struct lc_dilithium_pk *pk);
int lc_dilithium_verify_update_armv8(struct lc_dilithium_ctx *ctx,
				     const uint8_t *m, size_t mlen);
int lc_dilithium_verify_final_armv8(const struct lc_dilithium_sig *sig,
				    struct lc_dilithium_ctx *ctx,
				    const struct lc_dilithium_pk *pk);

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SIGNATURE_ARMV8_H */
