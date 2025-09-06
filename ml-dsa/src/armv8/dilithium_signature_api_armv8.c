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

#include "compare.h"
#include "dilithium_type.h"
#include "dilithium_selftest.h"
#include "dilithium_signature_armv8.h"
#include "../dilithium_signature_c.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	dilithium_keypair_tester(lc_dilithium_keypair_from_seed_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_KEYGEN);

	return lc_dilithium_keypair_from_seed_armv8(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair, struct lc_dilithium_pk *pk,
		      struct lc_dilithium_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	dilithium_keypair_tester(lc_dilithium_keypair_from_seed_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_KEYGEN);

	return lc_dilithium_keypair_armv8(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign, struct lc_dilithium_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	dilithium_siggen_tester(lc_dilithium_sign_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_armv8(sig, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx, struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	dilithium_siggen_tester(lc_dilithium_sign_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_ctx_armv8(sig, ctx, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init, struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	dilithium_siggen_tester(lc_dilithium_sign_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGGEN);

	return lc_dilithium_sign_init_armv8(ctx, sk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_sign_update_armv8(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_final_armv8(sig, ctx, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	dilithium_sigver_tester(lc_dilithium_verify_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_armv8(sig, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	dilithium_sigver_tester(lc_dilithium_verify_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_ctx_armv8(sig, ctx, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	dilithium_sigver_tester(lc_dilithium_verify_ctx_armv8);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_init_armv8(ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_verify_update_armv8(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_final_armv8(sig, ctx, pk);
}
