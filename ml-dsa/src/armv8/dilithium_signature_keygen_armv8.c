/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_signature_keygen_armv8.h"
#include "visibility.h"

/* We need twice the buffer size as we have a 2 lane SHAKE SIMD implemenation */
#define LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER 2

/* The C implementation of invntt produces small enough integers */
#define LC_DILITHIUM_INVNTT_SMALL

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_armv8.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_armv8.h"
#include "dilithium_pack.h"
#include "dilithium_signature_keygen_impl.h"

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

LC_INTERFACE_FUNCTION(int, lc_dilithium_pk_from_sk_armv8,
		      struct lc_dilithium_pk *pk,
		      const struct lc_dilithium_sk *sk)
{
	uint64_t saved_regs[8];
	int ret;

	store_fp_regs(saved_regs);
	ret = lc_dilithium_pk_from_sk_impl(pk, sk);
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
