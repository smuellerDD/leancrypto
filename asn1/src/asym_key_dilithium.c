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
#include "asym_key_dilithium.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"
#include "x509_mldsa_privkey.asn1.h"

static int
public_key_set_prehash_dilithium(const struct lc_public_key_signature *sig,
				 struct lc_dilithium_ctx *ctx)
{
	const struct lc_hash *hash_algo;
	int ret = 0;

	/*
	 * https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sphincs-plus#name-signed-data-conventions
	 * suggests to always use the pure signature schema. Therefore, do not
	 * apply the HashML-DSA step here unless explicitly requested.
	 */
	if (!sig->request_prehash)
		return 0;

	if (sig->hash_algo)
		hash_algo = sig->hash_algo;
	else
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));

	CKNULL(hash_algo, -EOPNOTSUPP);

	lc_dilithium_ctx_hash(ctx, hash_algo);

out:
	return ret;
}

int public_key_verify_signature_dilithium(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct lc_dilithium_pk dilithium_pk;
	struct lc_dilithium_sig dilithium_sig;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(lc_dilithium_pk_load(&dilithium_pk, pkey->key, pkey->keylen));
	CKINT(lc_dilithium_sig_load(&dilithium_sig, sig->s, sig->s_size));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium(sig, ctx));

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_verify_ctx(&dilithium_sig, ctx, sig->digest,
					      sig->digest_size, &dilithium_pk));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_verify_ctx(&dilithium_sig, ctx,
					      sig->raw_data, sig->raw_data_len,
					      &dilithium_pk));
	}

out:
	lc_dilithium_ctx_zero(ctx);
	lc_memset_secure(&dilithium_pk, 0, sizeof(dilithium_pk));
	lc_memset_secure(&dilithium_sig, 0, sizeof(dilithium_sig));
	return ret;
}

int public_key_generate_signature_dilithium(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
	struct lc_dilithium_sig dilithium_sig;
	struct lc_dilithium_sk *dilithium_sk = keys->sk.dilithium_sk;
	uint8_t *sigptr;
	size_t siglen;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium(sig, ctx));

		/*
		 * Sign the hash
		 */
		CKINT(lc_dilithium_sign_ctx(&dilithium_sig, ctx, sig->digest,
					    sig->digest_size, dilithium_sk,
					    lc_seeded_rng));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_sign_ctx(&dilithium_sig, ctx, sig->raw_data,
					    sig->raw_data_len, dilithium_sk,
					    lc_seeded_rng));
	}

	/*
	 * Extract the signature
	 */
	CKINT(lc_dilithium_sig_ptr(&sigptr, &siglen, &dilithium_sig));

	/*
	 * Ensure that sufficient size is present
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
	lc_dilithium_ctx_zero(ctx);
	lc_memset_secure(&dilithium_sig, 0, sizeof(dilithium_sig));
	return ret;
}

int x509_mldsa_private_key_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t pqc_pklen;
	uint8_t *pqc_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_sk_ptr(&pqc_ptr, &pqc_pklen, keys->sk.dilithium_sk));

	CKINT(x509_set_bit_string(data, avail_datalen, pqc_ptr, pqc_pklen));

	printf_debug("Set ML-DSA private key of size %zu\n", pqc_pklen);

out:
	return ret;
}

int private_key_encode_dilithium(uint8_t *data, size_t *avail_datalen,
				 struct x509_generate_privkey_context *ctx)
{
	int ret;

	CKINT(asn1_ber_encoder(&x509_mldsa_privkey_encoder, ctx, data,
			       avail_datalen));

out:
	return ret;
}

int x509_mldsa_private_key(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_sk *dilithium_sk = keys->sk.dilithium_sk;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_sk_load(dilithium_sk, value + 1, vlen - 1));

	printf_debug("Loaded ML-DSA secret key of size %zu\n", vlen - 1);

out:
	return ret;
}

int private_key_decode_dilithium(struct lc_x509_key_data *keys,
				 const uint8_t *data, size_t datalen)
{
	int ret;

	CKINT(asn1_ber_decoder(&x509_mldsa_privkey_decoder, keys, data,
			       datalen));

out:
	return ret;
}
