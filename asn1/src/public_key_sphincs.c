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
#include "asn1_encoder.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "public_key_sphincs.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"
#include "x509_slhdsa_privkey.asn1.h"

int public_key_verify_signature_sphincs(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig, unsigned int fast)
{
	struct lc_sphincs_pk sphincs_pk;
	struct lc_sphincs_sig sphincs_sig;
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
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		/*
		 * https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sphincs-plus#name-signed-data-conventions
		 * suggests to always use the pure signature schema.
		 * Therefore, do not apply the HashML-DSA step here.
		 */
#if 0
		const struct lc_hash *hash_algo;

		if (sig->hash_algo)
			hash_algo = sig->hash_algo;
		else
			CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo,
						       &hash_algo));

		CKNULL(hash_algo, -EOPNOTSUPP);

		lc_sphincs_ctx_hash(ctx, hash_algo);
#endif
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
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len, unsigned int fast)
{
	struct lc_sphincs_sig sphincs_sig;
	struct lc_sphincs_sk *sphincs_sk = gen_data->sk.sphincs_sk;
	uint8_t *sigptr;
	size_t siglen;
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	if (fast) {
		CKINT(lc_sphincs_sk_set_keytype_fast(sphincs_sk));
	} else {
		CKINT(lc_sphincs_sk_set_keytype_small(sphincs_sk));
	}

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		/* See above for the reason */
#if 0
		const struct lc_hash *hash_algo;

		if (sig->hash_algo)
			hash_algo = sig->hash_algo;
		else
			CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo,
						       &hash_algo));

		CKNULL(hash_algo, -EOPNOTSUPP);

		lc_sphincs_ctx_hash(ctx, hash_algo);
#endif

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
	if (*available_len < siglen) {
		printf_debug("Signature too long: expected %zu, actual %zu\n",
			     siglen, *available_len);
		ret = -ENOPKG;
		goto out;
	}

	/*
	 * Copy the signature to its destination
	 * We can unconstify the raw_sig pointer here, because we know the
	 * data buffer is in the just parsed data.
	 */
	memcpy(sig_data, sigptr, siglen);
	*available_len -= siglen;

out:
	lc_sphincs_ctx_zero(ctx);
	lc_memset_secure(&sphincs_sig, 0, sizeof(sphincs_sig));
	return ret;
}

int x509_slhdsa_private_key_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_generate_data *gen_data = ctx->gendata;
	size_t pqc_pklen;
	uint8_t *pqc_ptr;
	int ret;

	(void)tag;

	CKINT(lc_sphincs_sk_ptr(&pqc_ptr, &pqc_pklen, gen_data->sk.sphincs_sk));

	CKINT(x509_set_bit_string(data, avail_datalen, pqc_ptr, pqc_pklen));

	printf_debug("Set SLH-DSA private key of size %zu\n", pqc_pklen);

out:
	return ret;
}

int private_key_encode_sphincs(uint8_t *data, size_t *avail_datalen,
			       struct x509_generate_privkey_context *ctx)
{
	int ret;

	CKINT(asn1_ber_encoder(&x509_slhdsa_privkey_encoder, ctx, data,
			       avail_datalen));

out:
	return ret;
}

int x509_slhdsa_private_key(void *context, size_t hdrlen, unsigned char tag,
			    const uint8_t *value, size_t vlen)
{
	struct lc_x509_key_input_data *key_input_data = context;
	struct lc_sphincs_sk *sphincs_sk = &key_input_data->sk.sphincs_sk;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_sphincs_sk_load(sphincs_sk, value + 1, vlen - 1));

	printf_debug("Loaded SLH-DSA secret key of size %zu\n", vlen - 1);

out:
	return ret;
}

int private_key_decode_sphincs(struct lc_x509_key_input_data *key_input_data,
			       const uint8_t *data, size_t datalen)
{
	int ret;

	CKINT(asn1_ber_decoder(&x509_slhdsa_privkey_decoder, key_input_data,
			       data, datalen));

out:
	return ret;
}
