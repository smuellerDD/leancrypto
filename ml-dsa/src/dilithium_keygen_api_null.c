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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "ext_headers_internal.h"
#include "lc_dilithium.h"
#include "dilithium_pct.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair, struct lc_dilithium_pk *pk,
		      struct lc_dilithium_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_dilithium_type dilithium_type)
{
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	(void)dilithium_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen,
		      enum lc_dilithium_type dilithium_type)
{
	(void)pk;
	(void)sk;
	(void)seed;
	(void)seedlen;
	(void)dilithium_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_pk_from_sk, struct lc_dilithium_pk *pk,
		      const struct lc_dilithium_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_pct, const struct lc_dilithium_pk *pk,
		      const struct lc_dilithium_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_keypair,
		      struct lc_dilithium_ed25519_pk *pk,
		      struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx,
		      enum lc_dilithium_type dilithium_type)
{
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	(void)dilithium_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_pk_from_sk,
		      struct lc_dilithium_ed25519_pk *pk,
		      const struct lc_dilithium_ed25519_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}

#endif /* LC_DILITHIUM_ED25519_SIG */

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED448_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_keypair,
		      struct lc_dilithium_ed448_pk *pk,
		      struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx,
		      enum lc_dilithium_type dilithium_type)
{
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	(void)dilithium_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_pk_from_sk,
		      struct lc_dilithium_ed448_pk *pk,
		      const struct lc_dilithium_ed448_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}

#endif /* LC_DILITHIUM_ED448_SIG */
