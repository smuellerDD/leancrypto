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
#include "public_key_dilithium.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"

int public_key_verify_signature_dilithium(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct lc_dilithium_pk dilithium_pk;
	struct lc_dilithium_sig dilithium_sig;
	const struct lc_hash *hash_algo;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(lc_dilithium_pk_load(&dilithium_pk, pkey->key, pkey->keylen));
	CKINT(lc_dilithium_sig_load(&dilithium_sig, sig->s, sig->s_size));

	/*
	 * NOTE We apply the HashML-DSA here as the hash was calculated, but
	 * we set no ctx.
	 *
	 * This may change depending on the official specifications.
	 */
	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
	lc_dilithium_ctx_hash(ctx, hash_algo);

	/*
	 * Verify the signature
	 */
	CKINT(lc_dilithium_verify_ctx(&dilithium_sig, ctx, sig->digest,
				      sig->digest_size, &dilithium_pk));

out:
	lc_dilithium_ctx_zero(ctx);
	lc_memset_secure(&dilithium_pk, 0, sizeof(dilithium_pk));
	lc_memset_secure(&dilithium_sig, 0, sizeof(dilithium_sig));
	return ret;
}

int public_key_generate_signature_dilithium(
	const struct lc_x509_generate_data *gen_data,
	struct lc_x509_certificate *x509)
{
	struct lc_dilithium_sig dilithium_sig;
	struct lc_dilithium_sk *dilithium_sk = gen_data->sk.dilithium_sk;
	struct lc_public_key_signature *sig = &x509->sig;
	const struct lc_hash *hash_algo;
	uint8_t *sigptr, *sigdstptr;
	size_t siglen;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);

	/*
	 * NOTE We apply the HashML-DSA here as the hash was calculated, but
	 * we set no ctx.
	 *
	 * This may change depending on the official specifications.
	 */
	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
	lc_dilithium_ctx_hash(ctx, hash_algo);

	/*
	 * Sign the hash
	 */
	CKINT(lc_dilithium_sign_ctx(&dilithium_sig, ctx, sig->digest,
				    sig->digest_size, dilithium_sk,
				    lc_seeded_rng));
	/*
	 * Extract the signature
	 */
	CKINT(lc_dilithium_sig_ptr(&sigptr, &siglen, &dilithium_sig));

	/*
	 * Consistency check
	 *
	 * We have to add one to the actual size, because the original buffer is
	 * a BIT STRING which has a zero as prefix
	 */
	if (x509->raw_sig_size != siglen) {
		printf_debug(
			"Signature length mismatch: expected %zu, actual %zu\n",
			x509->raw_sig_size, siglen);
		ret = -ENOPKG;
		goto out;
	}

	/*
	 * Copy the signature to its destination
	 * We can unconstify the raw_sig pointer here, because we know the
	 * data buffer is in the just parsed data.
	 *
	 * We also skip the leading BIT STRING prefix byte
	 */
	sigdstptr = (uint8_t *)x509->raw_sig;
	memcpy(sigdstptr, sigptr, siglen);

out:
	lc_dilithium_ctx_zero(ctx);
	lc_memset_secure(&dilithium_sig, 0, sizeof(dilithium_sig));
	return ret;
}
