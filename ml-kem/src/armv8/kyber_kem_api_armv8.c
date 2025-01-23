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

#include "kyber_internal.h"
#include "kyber_kem_armv8.h"
#include "kyber_kem_c.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair_from_seed, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, const uint8_t *seed,
		      size_t seedlen)
{
	return lc_kyber_keypair_from_seed_armv8(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	return lc_kyber_keypair_armv8(pk, sk, rng_ctx);
}

int lc_kyber_enc_internal(struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
			  const struct lc_kyber_pk *pk,
			  struct lc_rng_ctx *rng_ctx)
{
	return lc_kyber_enc_armv8(ct, ss, pk, rng_ctx);
}

int lc_kyber_enc_kdf_internal(struct lc_kyber_ct *ct, uint8_t *ss,
			      size_t ss_len, const struct lc_kyber_pk *pk,
			      struct lc_rng_ctx *rng_ctx)
{
	return lc_kyber_enc_kdf_armv8(ct, ss, ss_len, pk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc, struct lc_kyber_ct *ct,
		      struct lc_kyber_ss *ss, const struct lc_kyber_pk *pk)
{
	return lc_kyber_enc_internal(ct, ss, pk, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_kdf, struct lc_kyber_ct *ct,
		      uint8_t *ss, size_t ss_len, const struct lc_kyber_pk *pk)
{
	return lc_kyber_enc_kdf_internal(ct, ss, ss_len, pk, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec, struct lc_kyber_ss *ss,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	return lc_kyber_dec_armv8(ss, ct, sk);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	return lc_kyber_dec_kdf_armv8(ss, ss_len, ct, sk);
}
