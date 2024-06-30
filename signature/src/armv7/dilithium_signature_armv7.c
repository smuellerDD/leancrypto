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

#include "dilithium_type.h"
#include "dilithium_signature_armv7.h"
#include "visibility.h"

/* We need twice the buffer size as we have a 2 lane SHAKE SIMD implemenation */
#define LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER 1

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_armv7.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_armv7.h"
#include "dilithium_pack.h"
#include "dilithium_signature_impl.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed_armv7,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	return lc_dilithium_keypair_from_seed_impl(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_armv7,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_keypair_impl(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_armv7,
		      struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_impl(sig, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init_armv7,
		      struct lc_hash_ctx *hash_ctx,
		      const struct lc_dilithium_sk *sk)
{
	return lc_dilithium_sign_init_impl(hash_ctx, sk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update_armv7,
		      struct lc_hash_ctx *hash_ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_sign_update_impl(hash_ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final_armv7,
		      struct lc_dilithium_sig *sig,
		      struct lc_hash_ctx *hash_ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_dilithium_sign_final_impl(sig, hash_ctx, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_armv7,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_impl(sig, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init_armv7,
		      struct lc_hash_ctx *hash_ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_init_impl(hash_ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update_armv7,
		      struct lc_hash_ctx *hash_ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_verify_update_impl(hash_ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final_armv7,
		      const struct lc_dilithium_sig *sig,
		      struct lc_hash_ctx *hash_ctx,
		      const struct lc_dilithium_pk *pk)
{
	return lc_dilithium_verify_final_impl(sig, hash_ctx, pk);
}
