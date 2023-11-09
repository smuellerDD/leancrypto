/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#include "lc_rng.h"
#include "ret_checkers.h"
#include "x25519.h"
#include "x25519_scalarmult.h"

int lc_x25519_keypair(struct lc_x25519_pk *pk, struct lc_x25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk,
			      LC_X25519_SECRETKEYBYTES));
	CKINT(crypto_scalarmult_curve25519_base(pk->pk, sk->sk));

out:
	return ret;
}

int lc_x25519_ss(struct lc_x25519_ss *ss, const struct lc_x25519_pk *pk,
		 const struct lc_x25519_sk *sk)
{
	int ret;

	CKINT(crypto_scalarmult_curve25519(ss->ss, sk->sk, pk->pk));

out:
	return ret;
}
