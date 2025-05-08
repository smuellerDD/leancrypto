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

#include "armv8_helper.h"
#include "dilithium_type.h"
#include "dilithium_signature_armv8.h"
#include "visibility.h"

/* We need twice the buffer size as we have a 2 lane SHAKE SIMD implemenation */
#define LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER 2

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_armv8.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_armv8.h"
#include "dilithium_pack.h"
#include "dilithium_signature_impl.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed_armv8,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_keypair_from_seed_impl(pk, sk, seed, seedlen);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_armv8,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_keypair_impl(pk, sk, rng_ctx);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_armv8,
		      struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_sign_impl(sig, m, mlen, sk, rng_ctx);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx_armv8,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_sign_ctx_impl(sig, ctx, m, mlen, sk, rng_ctx);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init_armv8,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_sign_init_impl(ctx, sk);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update_armv8,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_sign_update_impl(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final_armv8,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_sign_final_impl(sig, ctx, sk, rng_ctx);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_armv8,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_verify_impl(sig, m, mlen, pk);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx_armv8,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_verify_ctx_impl(sig, ctx, m, mlen, pk);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init_armv8,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_verify_init_impl(ctx, pk);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update_armv8,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_verify_update_impl(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final_armv8,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_verify_final_impl(sig, ctx, pk);
	reload_fp_regs(saved_regs);
	lc_memset_secure(saved_regs, 0, sizeof(saved_regs));

	return ret;
}
