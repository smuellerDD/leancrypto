/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "dilithium_signature_c.h"
#include "visibility.h"

/* We need once the buffer size to handle the hashing */
#define LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER 1

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_c.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_c.h"
#include "dilithium_pack.h"
#include "dilithium_signature_impl.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed_c,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	return lc_dilithium_keypair_from_seed_impl(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_c, struct lc_dilithium_pk *pk,
		      struct lc_dilithium_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_keypair_impl(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_c, struct lc_dilithium_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_impl(sig, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx_c,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_ctx_impl(sig, ctx, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init_c,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	return lc_dilithium_sign_init_impl(ctx, sk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init_ctx_c,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	return lc_dilithium_sign_init_ctx_impl(ctx, sk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update_c,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_sign_update_impl(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final_c,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_final_impl(sig, ctx, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_c,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_impl(sig, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx_c,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_ctx_impl(sig, ctx, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init_c,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_init_impl(ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init_ctx_c,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_init_ctx_impl(ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update_c,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_verify_update_impl(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final_c,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_final_impl(sig, ctx, pk);
}
