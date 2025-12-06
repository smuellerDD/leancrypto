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
#include "asym_key_sphincs.h"
#include "ext_headers_internal.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "pkcs7_internal.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"

static int
public_key_set_prehash_sphincs(const struct lc_public_key_signature *sig,
			       struct lc_sphincs_ctx *ctx)
{
	const struct lc_hash *hash_algo;
	int ret = 0;

	if (sig->hash_algo)
		hash_algo = sig->hash_algo;
	else
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));

	CKNULL(hash_algo, -EOPNOTSUPP);

	lc_sphincs_ctx_hash(ctx, hash_algo);

out:
	return ret;
}

int public_key_verify_signature_sphincs(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig, unsigned int fast)
{
	struct workspace {
		struct lc_sphincs_pk sphincs_pk;
		struct lc_sphincs_sig sphincs_sig;
	};
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(lc_sphincs_pk_load(&ws->sphincs_pk, pkey->key, pkey->keylen));
	if (fast) {
		printf_debug("SLH-DSA use fast key type\n");
		CKINT(lc_sphincs_pk_set_keytype_fast(&ws->sphincs_pk));
	} else {
		printf_debug("SLH-DSA use small key type\n");
		CKINT(lc_sphincs_pk_set_keytype_small(&ws->sphincs_pk));
	}

	CKINT(lc_sphincs_sig_load(&ws->sphincs_sig, sig->s, sig->s_size));

	/*
	 * Select the data to be signed
	 */
	if (sig->authattrs) {
		uint8_t aa[LC_PKCS7_AUTHATTRS_MAX_SIZE];

		/*
		 * The size of the buffer aa must be sufficient to keep the
		 * original AA data plus one byte.
		 */
		if (sig->authattrs_size >= sizeof(aa)) {
			ret = -EOVERFLOW;
			goto out;
		}

		printf_debug(
			"SLH-DSA signature verification of authenticated attributes\n");

		/*
		 * SLH-DSA init/update/final operates like a pre-hash variant
		 * and thus cannot be used here. This implies, we need to use
		 * the one-shot operation.
		 */
		aa[0] = lc_pkcs7_authattr_tag;
		memcpy(aa + 1, sig->authattrs, sig->authattrs_size);
		CKINT(lc_sphincs_verify_ctx(&ws->sphincs_sig, ctx, aa,
					    sig->authattrs_size + 1,
					    &ws->sphincs_pk));
	} else if (sig->digest_size) {
		printf_debug(
			"SLH-DSA signature verification of pre-hashed data\n");

		CKINT(public_key_set_prehash_sphincs(sig, ctx));

		/*
		 * Verify the signature of a pre-hashed message
		 */
		CKINT(lc_sphincs_verify_ctx(&ws->sphincs_sig, ctx, sig->digest,
					    sig->digest_size, &ws->sphincs_pk));
	} else {
		printf_debug("SLH-DSA signature verification of raw data\n");

		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature of raw data
		 */
		CKINT(lc_sphincs_verify_ctx(&ws->sphincs_sig, ctx,
					    sig->raw_data, sig->raw_data_len,
					    &ws->sphincs_pk));
	}

out:
	lc_sphincs_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_sphincs(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len, unsigned int fast)
{
#ifdef LC_X509_GENERATOR
	struct workspace {
		struct lc_sphincs_sig sphincs_sig;
	};
	struct lc_sphincs_sk *sphincs_sk = keys->sk.sphincs_sk;
	uint8_t *sigptr;
	size_t siglen;
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (fast) {
		printf_debug("SLH-DSA use fast key type\n");
		CKINT(lc_sphincs_sk_set_keytype_fast(sphincs_sk));
	} else {
		printf_debug("SLH-DSA use small key type\n");
		CKINT(lc_sphincs_sk_set_keytype_small(sphincs_sk));
	}

	/*
	 * Select the data to be signed
	 */
	if (sig->authattrs) {
		printf_debug(
			"SLH-DSA signature generation of authenticated attributes\n");

		/*
		 * Sign the authenticated attributes data
		 */
		CKINT(lc_sphincs_sign_ctx(&ws->sphincs_sig, ctx, sig->authattrs,
					  sig->authattrs_size, sphincs_sk,
					  lc_seeded_rng));
	} else if (sig->digest_size) {
		printf_debug(
			"SLH-DSA signature generation of pre-hashed data\n");

		CKINT(public_key_set_prehash_sphincs(sig, ctx));

		/*
		 * Sign the hash
		 */
		CKINT(lc_sphincs_sign_ctx(&ws->sphincs_sig, ctx, sig->digest,
					  sig->digest_size, sphincs_sk,
					  lc_seeded_rng));
	} else {
		printf_debug("SLH-DSA signature generation of raw data\n");

		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Sign the registered data
		 */
		CKINT(lc_sphincs_sign_ctx(&ws->sphincs_sig, ctx, sig->raw_data,
					  sig->raw_data_len, sphincs_sk,
					  lc_seeded_rng));
	}

	/*
	 * Extract the signature
	 */
	CKINT(lc_sphincs_sig_ptr(&sigptr, &siglen, &ws->sphincs_sig));

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
	 * Copy the signature to its destination.
	 */
	memcpy(sig_data, sigptr, siglen);
	*available_len -= siglen;

out:
	lc_sphincs_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
#else
	(void)keys;
	(void)sig;
	(void)sig_data;
	(void)available_len;
	(void)fast;
	return -EOPNOTSUPP;
#endif
}

int private_key_encode_sphincs(uint8_t *data, size_t *avail_datalen,
			       struct x509_generate_privkey_context *ctx)
{
#ifdef LC_X509_GENERATOR
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t pqc_pklen;
	uint8_t *pqc_ptr;
	int ret;

	CKINT(lc_sphincs_sk_ptr(&pqc_ptr, &pqc_pklen, keys->sk.sphincs_sk));

	/* Set OCTET STRING of priv key seed */
	CKINT(lc_x509_concatenate_bit_string(&data, avail_datalen, pqc_ptr,
					     pqc_pklen));

	printf_debug("Set SLH-DSA private key of size %zu\n", pqc_pklen);

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
}

int private_key_decode_sphincs(struct lc_x509_key_data *keys,
			       const uint8_t *data, size_t datalen)
{
	struct lc_sphincs_sk *sphincs_sk = keys->sk.sphincs_sk;
	int ret;

	CKINT(lc_sphincs_sk_load(sphincs_sk, data, datalen));

	printf_debug("Loaded SLH-DSA secret key of size %zu\n", datalen);

out:
	return ret;
}

int asym_set_sphincs_keypair(struct lc_x509_key_data *gen_data,
			     struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk)
{
	uint8_t *pk_ptr;
	size_t pk_len;
	enum lc_sphincs_type sphincs_type = LC_SPHINCS_UNKNOWN;

	int ret = 0;

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		sphincs_type = lc_sphincs_pk_type(pk);

		gen_data->pk.sphincs_pk = pk;

		CKINT(lc_sphincs_pk_ptr(&pk_ptr, &pk_len, pk));
		CKINT(lc_hash(LC_X509_SKID_DEFAULT_HASH, pk_ptr, pk_len,
			      gen_data->pk_digest));
	}

	if (sk) {
		if (sphincs_type != LC_SPHINCS_UNKNOWN) {
			enum lc_sphincs_type tmp = lc_sphincs_sk_type(sk);
			if (tmp != sphincs_type) {
				printf_debug(
					"Public and private key types mismatch\n");
				ret = -EINVAL;
				goto out;
			}
		} else {
			sphincs_type = lc_sphincs_sk_type(sk);
		}

		gen_data->sk.sphincs_sk = sk;
	}

	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_128f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_128F;
		break;
	case LC_SPHINCS_SHAKE_128s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_128S;
		break;
	case LC_SPHINCS_SHAKE_192f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_192F;
		break;
	case LC_SPHINCS_SHAKE_192s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_192S;
		break;
	case LC_SPHINCS_SHAKE_256f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_256F;
		break;
	case LC_SPHINCS_SHAKE_256s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_256S;
		break;
	case LC_SPHINCS_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium type\n");
		return -ENOPKG;
	}

out:
	return ret;
}

int asym_keypair_gen_sphincs(struct lc_x509_certificate *cert,
			     struct lc_x509_key_data *keys,
			     enum lc_sphincs_type sphincs_key_type)
{
	int ret;

	CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk, keys->sk.sphincs_sk,
				 lc_seeded_rng, sphincs_key_type));
	CKINT(asym_set_sphincs_keypair(&cert->sig_gen_data, keys->pk.sphincs_pk,
				       keys->sk.sphincs_sk));
	CKINT(asym_set_sphincs_keypair(&cert->pub_gen_data, keys->pk.sphincs_pk,
				       NULL));

out:
	return ret;
}
