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
	 * Select hash-based signature if there was a hash
	 */
	if (sig->digest_size) {
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
		CKNULL(hash_algo, -EOPNOTSUPP);
		lc_sphincs_ctx_hash(ctx, hash_algo);

		/*
		 * Verify the signature
		 */
		CKINT(lc_sphincs_verify_ctx(&sphincs_sig, ctx, sig->digest,
					    sig->digest_size, &sphincs_pk));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_sphincs_verify_ctx(&sphincs_sig, ctx, sig->raw_data,
					    sig->raw_data_len, &sphincs_pk));
	}

out:
	lc_sphincs_ctx_zero(ctx);
	lc_memset_secure(&sphincs_pk, 0, sizeof(sphincs_pk));
	lc_memset_secure(&sphincs_sig, 0, sizeof(sphincs_sig));
	return ret;
}

int public_key_generate_signature_sphincs(
	const struct lc_x509_generate_data *gen_data,
	struct lc_x509_certificate *x509, unsigned int fast)
{
	struct lc_sphincs_sig sphincs_sig;
	struct lc_sphincs_sk *sphincs_sk = gen_data->sk.sphincs_sk;
	struct lc_public_key_signature *sig = &x509->sig;
	const struct lc_hash *hash_algo;
	uint8_t *sigptr, *sigdstptr;
	size_t siglen;
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	if (fast) {
		CKINT(lc_sphincs_sk_set_keytype_fast(sphincs_sk));
	} else {
		CKINT(lc_sphincs_sk_set_keytype_small(sphincs_sk));
	}

	/*
	 * Select hash-based signature if there was a hash
	 */
	if (sig->digest_size) {
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
		CKNULL(hash_algo, -EOPNOTSUPP);
		lc_sphincs_ctx_hash(ctx, hash_algo);

		/*
		 * Sign the hash
		 */
		CKINT(lc_sphincs_sign_ctx(&sphincs_sig, ctx, sig->digest,
					    sig->digest_size, sphincs_sk,
					    lc_seeded_rng));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_sphincs_sign_ctx(&sphincs_sig, ctx, sig->raw_data,
					    sig->raw_data_len, sphincs_sk,
					    lc_seeded_rng));
	}

	/*
	 * Extract the signature
	 */
	CKINT(lc_sphincs_sig_ptr(&sigptr, &siglen, &sphincs_sig));

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
	lc_sphincs_ctx_zero(ctx);
	lc_memset_secure(&sphincs_sig, 0, sizeof(sphincs_sig));
	return ret;
}
