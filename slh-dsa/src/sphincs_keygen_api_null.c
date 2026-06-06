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

#include "lc_sphincs.h"
#include "sphincs_pct.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair, struct lc_sphincs_pk *pk,
		      struct lc_sphincs_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_sphincs_type sphincs_type)
{
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	(void)sphincs_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair_from_seed,
		      struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk,
		      const uint8_t *seed, size_t seedlen,
		      enum lc_sphincs_type sphincs_type)
{
	(void)pk;
	(void)sk;
	(void)seed;
	(void)seedlen;
	(void)sphincs_type;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_from_sk, struct lc_sphincs_pk *pk,
		      const struct lc_sphincs_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pct, const struct lc_sphincs_pk *pk,
		      const struct lc_sphincs_sk *sk)
{
	(void)pk;
	(void)sk;
	return -EOPNOTSUPP;
}
