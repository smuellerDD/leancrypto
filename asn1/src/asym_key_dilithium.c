/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "ext_headers_internal.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"
#include "x509_mldsa_privkey_asn1.h"

static int
public_key_set_prehash_dilithium(const struct lc_public_key_signature *sig,
				 struct lc_dilithium_ctx *ctx)
{
	const struct lc_hash *hash_algo;
	int ret = 0;

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
	struct workspace {
		struct lc_dilithium_pk dilithium_pk;
		struct lc_dilithium_sig dilithium_sig;
	};
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(lc_dilithium_pk_load(&ws->dilithium_pk, pkey->key, pkey->keylen));
	CKINT(lc_dilithium_sig_load(&ws->dilithium_sig, sig->s, sig->s_size));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium(sig, ctx));

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_verify_ctx(&ws->dilithium_sig, ctx,
					      sig->digest, sig->digest_size,
					      &ws->dilithium_pk));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_verify_ctx(&ws->dilithium_sig, ctx,
					      sig->raw_data, sig->raw_data_len,
					      &ws->dilithium_pk));
	}

out:
	lc_dilithium_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_dilithium(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
#ifdef LC_X509_GENERATOR
	struct workspace {
		struct lc_dilithium_sig dilithium_sig;
	};
	struct lc_dilithium_sk *dilithium_sk = keys->sk.dilithium_sk;
	uint8_t *sigptr;
	size_t siglen;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium(sig, ctx));

		/*
		 * Sign the hash
		 */
		CKINT(lc_dilithium_sign_ctx(&ws->dilithium_sig, ctx,
					    sig->digest, sig->digest_size,
					    dilithium_sk, lc_seeded_rng));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_sign_ctx(&ws->dilithium_sig, ctx,
					    sig->raw_data, sig->raw_data_len,
					    dilithium_sk, lc_seeded_rng));
	}

	/*
	 * Extract the signature
	 */
	CKINT(lc_dilithium_sig_ptr(&sigptr, &siglen, &ws->dilithium_sig));

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
	 */
	memcpy(sig_data, sigptr, siglen);
	*available_len -= siglen;

out:
	lc_dilithium_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
#else
	(void)keys;
	(void)sig;
	(void)sig_data;
	(void)available_len;
	return -EOPNOTSUPP;
#endif
}

int x509_mldsa_private_key_expanded_enc(void *context, uint8_t *data,
					size_t *avail_datalen, uint8_t *tag)
{
#ifdef LC_X509_GENERATOR
	const struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t pqc_pklen;
	uint8_t *pqc_ptr;
	int ret;

	(void)tag;

	/* Only write out the full key if there was no seed. */
	if (keys->sk_seed_set)
		return 0;

	CKINT(lc_dilithium_sk_ptr(&pqc_ptr, &pqc_pklen, keys->sk.dilithium_sk));

	/* Set OCTET STRING */
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, pqc_ptr,
					  pqc_pklen));

	printf_debug("Set ML-DSA private key of size %zu\n", pqc_pklen);

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)context;
	(void)tag;
	return -EOPNOTSUPP;
#endif
}

int x509_mldsa_private_key_seed_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
#ifdef LC_X509_GENERATOR
	const struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	int ret;

	(void)tag;

	/* Only write out the seed if there was a seed */
	if (!keys->sk_seed_set)
		return 0;

	/* Set OCTET STRING of priv key seed */
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, keys->sk_seed,
					  sizeof(keys->sk_seed)));

	printf_debug("Set ML-DSA private key seed of size %zu\n",
		     sizeof(keys->sk_seed));

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)context;
	(void)tag;
	return -EOPNOTSUPP;
#endif
}

int private_key_encode_dilithium(uint8_t *data, size_t *avail_datalen,
				 struct x509_generate_privkey_context *ctx)
{
#ifdef LC_X509_GENERATOR
	int ret;

	CKINT(asn1_ber_encoder(&x509_mldsa_privkey_encoder, ctx, data,
			       avail_datalen));

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
}

int x509_mldsa_private_key_expanded(void *context, size_t hdrlen,
				    unsigned char tag, const uint8_t *value,
				    size_t vlen)
{
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_sk *dilithium_sk = keys->sk.dilithium_sk;
	int ret;

	(void)hdrlen;
	(void)tag;

	if (keys->sk_seed_set) {
		uint8_t *dilithium_src_key;
		size_t dilithium_src_key_len;

		/*
		 * Sanity check that the presented key data is consistent: The
		 * ML-DSA key derived from the seed must be identical to the
		 * ML-DSA key presented in the PKCS#8.
		 */
		CKINT(lc_dilithium_sk_ptr(&dilithium_src_key,
					  &dilithium_src_key_len,
					  dilithium_sk));
		if (lc_memcmp_secure(dilithium_src_key, dilithium_src_key_len,
				     value, vlen))
			return -EBADMSG;

		return 0;
	}

	CKINT(lc_dilithium_sk_load(dilithium_sk, value, vlen));

	printf_debug("Loaded ML-DSA secret key of size %zu\n", vlen);

out:
	return ret;
}

int x509_mldsa_private_key_seed(void *context, size_t hdrlen, unsigned char tag,
				const uint8_t *value, size_t vlen)
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
	};
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_sk *dilithium_sk = keys->sk.dilithium_sk;
	uint8_t *dilithium_src_key;
	size_t dilithium_src_key_len;
	enum lc_dilithium_type dilithium_type = LC_DILITHIUM_UNKNOWN;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	(void)hdrlen;
	(void)tag;

	if (vlen != LC_X509_PQC_SK_SEED_SIZE)
		return -EBADMSG;

	printf_debug("Loaded ML-DSA secret seed of size %u\n",
		     LC_X509_PQC_SK_SEED_SIZE);

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
		dilithium_type = LC_DILITHIUM_44;
		break;
	case LC_SIG_DILITHIUM_65:
		dilithium_type = LC_DILITHIUM_65;
		break;
	case LC_SIG_DILITHIUM_87:
		dilithium_type = LC_DILITHIUM_87;
		break;

	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
	case LC_SIG_DILITHIUM_44_ED448:
	case LC_SIG_DILITHIUM_65_ED448:
	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_SM2:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_UNKNOWN:
		ret = -ENOPKG;
		goto out;
	}

	/*
	 * Store the seed
	 */
	memcpy(keys->sk_seed, value, LC_X509_PQC_SK_SEED_SIZE);
	keys->sk_seed_set = 1;

	/*
	 * Only load the secret key
	 */
	CKINT(lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, keys->sk_seed,
					     LC_X509_PQC_SK_SEED_SIZE,
					     dilithium_type));
	CKINT(lc_dilithium_sk_ptr(&dilithium_src_key, &dilithium_src_key_len,
				  &ws->sk));

	CKINT(lc_dilithium_sk_load(dilithium_sk, dilithium_src_key,
				   dilithium_src_key_len));

	printf_debug("Reestablished ML-DSA secret key of size %zu\n",
		     dilithium_src_key_len);

out:
	LC_RELEASE_MEM(ws);
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

int asym_set_dilithium_keypair(struct lc_x509_key_data *gen_data,
			       struct lc_dilithium_pk *pk,
			       struct lc_dilithium_sk *sk)
{
	uint8_t *pk_ptr;
	size_t pk_len;
	enum lc_dilithium_type dilithium_type = LC_DILITHIUM_UNKNOWN;

	int ret = 0;

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		dilithium_type = lc_dilithium_pk_type(pk);

		gen_data->pk.dilithium_pk = pk;

		CKINT(lc_dilithium_pk_ptr(&pk_ptr, &pk_len, pk));
		CKINT(lc_hash(LC_X509_SKID_DEFAULT_HASH, pk_ptr, pk_len,
			      gen_data->pk_digest));
	}

	if (sk) {
		if (dilithium_type != LC_DILITHIUM_UNKNOWN) {
			enum lc_dilithium_type tmp = lc_dilithium_sk_type(sk);
			if (tmp != dilithium_type) {
				printf_debug(
					"Public and private key types mismatch\n");
				ret = -EINVAL;
				goto out;
			}
		} else {
			dilithium_type = lc_dilithium_sk_type(sk);
		}

		gen_data->sk.dilithium_sk = sk;
	}

	switch (dilithium_type) {
	case LC_DILITHIUM_44:
		gen_data->sig_type = LC_SIG_DILITHIUM_44;
		break;
	case LC_DILITHIUM_65:
		gen_data->sig_type = LC_SIG_DILITHIUM_65;
		break;
	case LC_DILITHIUM_87:
		gen_data->sig_type = LC_SIG_DILITHIUM_87;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium type\n");
		return -ENOPKG;
	}

out:
	return ret;
}
