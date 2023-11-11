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

#include "ed25519.h"
#include "lc_dilithium.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_keypair,
		      struct lc_dilithium_ed25519_pk *pk,
		      struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(lc_dilithium_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_ed25519_keypair(&pk->pk_ed25519, &sk->sk_ed25519, rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign,
		      struct lc_dilithium_ed25519_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	CKINT(lc_dilithium_sign(&sig->sig, m, mlen, &sk->sk, rng_ctx));
	CKINT(lc_ed25519_sign(&sig->sig_ed25519, m, mlen, &sk->sk_ed25519,
			      rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify,
		      const struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	int retd, rete;

	retd = lc_dilithium_verify(&sig->sig, m, mlen, &pk->pk);
	rete = lc_ed25519_verify(&sig->sig_ed25519, m, mlen, &pk->pk_ed25519);

	if (rete == -EBADMSG || retd == -EBADMSG)
		return -EBADMSG;
	else if (rete == -EINVAL || retd == -EINVAL)
		return -EINVAL;
	else
		return rete | retd;
}
