/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "lc_x448.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "x448_scalarmult.h"

LC_INTERFACE_FUNCTION(int, lc_x448_keypair, struct lc_x448_pk *pk,
		      struct lc_x448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk,
			      LC_X448_SECRETKEYBYTES));

	/* Timecop: the random number is the sentitive data */
	poison(sk->sk, LC_X448_SECRETKEYBYTES);

	CKINT(x448_derive_public_key(pk->pk, sk->sk));

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, LC_X448_SECRETKEYBYTES);
	unpoison(pk->pk, LC_X448_PUBLICKEYBYTES);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x448_ss, struct lc_x448_ss *ss,
		      const struct lc_x448_pk *pk, const struct lc_x448_sk *sk)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ss, -EINVAL);

	/* Timecop: mark the secret key as sensitive */
	poison(sk->sk, LC_X448_SECRETKEYBYTES);

	CKINT(x448_scalarmult(ss->ss, pk->pk, sk->sk));

	/* Timecop: ss and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, LC_X448_SECRETKEYBYTES);
	unpoison(ss->ss, LC_X448_SSBYTES);

out:
	return ret;
}
