/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "asn1.h"
#include "asn1_debug.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "public_key_sphincs.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"

int public_key_verify_signature_sphincs(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig, unsigned int fast)
{
	struct lc_sphincs_pk sphincs_pk;
	struct lc_sphincs_sig sphincs_sig;
	const struct lc_hash *hash_algo;
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(lc_sphincs_pk_load(&sphincs_pk, pkey->key, pkey->keylen));
	if (fast) {
		CKINT(lc_sphincs_pk_set_keytype_fast(&sphincs_pk));
	} else {
		CKINT(lc_sphincs_pk_set_keytype_small(&sphincs_pk));
	}

	CKINT(lc_sphincs_sig_load(&sphincs_sig, sig->s, sig->s_size));

	/*
	 * NOTE We apply the HashML-DSA here as the hash was calculated, but
	 * we set no ctx.
	 *
	 * This may change depending on the official specifications.
	 */
	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
	lc_sphincs_ctx_hash(ctx, hash_algo);

	CKINT(lc_sphincs_verify_ctx(&sphincs_sig, ctx, sig->digest,
				    sig->digest_size, &sphincs_pk));

out:
	lc_sphincs_ctx_zero(ctx);
	lc_memset_secure(&sphincs_pk, 0, sizeof(sphincs_pk));
	lc_memset_secure(&sphincs_sig, 0, sizeof(sphincs_sig));
	return ret;
}
