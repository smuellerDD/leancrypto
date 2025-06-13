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

#include "asym_key_dilithium_ed448.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"

static int public_key_set_prehash_dilithium_ed448(
	const struct lc_public_key_signature *sig,
	struct lc_dilithium_ed448_ctx *ctx)
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

	lc_dilithium_ed448_ctx_hash(ctx, hash_algo);

out:
	return ret;
}

int private_key_encode_dilithium_ed448(uint8_t *data, size_t *avail_datalen,
				       struct x509_generate_privkey_context *ctx)
{
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ml_dsa_sklen, ed448_sklen;
	uint8_t *ml_dsa_ptr, *ed448_ptr;
	int ret;

	CKINT(lc_dilithium_ed448_sk_ptr(&ml_dsa_ptr, &ml_dsa_sklen, &ed448_ptr,
					&ed448_sklen,
					keys->sk.dilithium_ed448_sk));

	/*
	 * Concatenate the signature data into the buffer according to
	 * draft version 5.
	 */
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, ml_dsa_ptr,
					  ml_dsa_sklen));
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, ed448_ptr,
					  ed448_sklen));

	printf_debug("Set composite secret key of size %zu\n",
		     ml_dsa_sklen + ed448_sklen);

out:
	return ret;
}

int private_key_decode_dilithium_ed448(struct lc_x509_key_data *keys,
				       const uint8_t *data, size_t datalen)
{
	struct lc_dilithium_ed448_sk *dilithium_sk =
		keys->sk.dilithium_ed448_sk;
	const uint8_t *dilithium_src_key, *ed448_src_key;
	size_t dilithium_src_key_len, ed448_src_key_len;
	int ret;

	if (datalen < LC_ED448_SECRETKEYBYTES)
		return -EINVAL;

	/* See draft version 5:
	 * Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)
	 *
	 * First the ML-DSA PK, then the traditional PK. As we have ED448,
	 * the code takes the ED448 PK size and the remainder is the
	 * ML-DSA PK.
	 */
	dilithium_src_key = data;
	dilithium_src_key_len = datalen - LC_ED448_SECRETKEYBYTES;

	ed448_src_key = dilithium_src_key + dilithium_src_key_len;
	ed448_src_key_len = LC_ED448_SECRETKEYBYTES;

	CKINT(lc_dilithium_ed448_sk_load(dilithium_sk, dilithium_src_key,
					 dilithium_src_key_len, ed448_src_key,
					 ed448_src_key_len));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

int public_key_encode_dilithium_ed448(uint8_t *data, size_t *avail_datalen,
				      struct x509_generate_context *ctx)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_key_data *gen_data = &cert->pub_gen_data;
	size_t ml_dsa_pklen, ed448_pklen;
	uint8_t *ml_dsa_ptr, *ed448_ptr;
	int ret;

	CKINT(lc_dilithium_ed448_pk_ptr(&ml_dsa_ptr, &ml_dsa_pklen, &ed448_ptr,
					&ed448_pklen,
					gen_data->pk.dilithium_ed448_pk));

	/*
	 * Concatenate the signature data into the buffer according to
	 * draft version 5.
	 */
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, ml_dsa_ptr,
					  ml_dsa_pklen));
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, ed448_ptr,
					  ed448_pklen));

	printf_debug("Set composite public key of size %zu\n",
		     ml_dsa_pklen + ed448_pklen);

out:
	return ret;
}

int public_key_decode_dilithium_ed448(
	struct lc_dilithium_ed448_pk *dilithium_ed448_pk, const uint8_t *data,
	size_t datalen)
{
	const uint8_t *dilithium_src, *ed448_src;
	size_t dilithium_src_len, ed448_src_len;
	int ret;

	if (datalen < LC_ED448_PUBLICKEYBYTES)
		return -EINVAL;

	/*
	 * See draft version 5:
	 * Composite-ML-DSA.DeserializePublicKey(bytes) -> (mldsaKey, tradKey)
	 *
	 * First the ML-DSA PK, then the traditional PK. As we have ED448,
	 * the code takes the ED448 PK size and the remainder is the
	 * ML-DSA PK.
	 */
	dilithium_src = data;
	dilithium_src_len = datalen - LC_ED448_PUBLICKEYBYTES;
	ed448_src = dilithium_src + dilithium_src_len;
	ed448_src_len = LC_ED448_PUBLICKEYBYTES;
	CKINT(lc_dilithium_ed448_pk_load(dilithium_ed448_pk, dilithium_src,
					 dilithium_src_len, ed448_src,
					 ed448_src_len));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

int public_key_verify_signature_dilithium_ed448(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct workspace {
		struct lc_dilithium_ed448_pk dilithium_pk;
		struct lc_dilithium_ed448_sig dilithium_sig;
	};
	const uint8_t *dilithium_src, *ed448_src;
	size_t dilithium_src_len, ed448_src_len;
	int ret;
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	if (sig->s_size < LC_ED448_SIGBYTES)
		return -EINVAL;

	CKINT(public_key_decode_dilithium_ed448(&ws->dilithium_pk, pkey->key,
						pkey->keylen));

	/*
	 * See draft version 5:
	 * Composite-ML-DSA.DeserializeSignatureValue(bytes) ->
	 * (mldsaSig, tradSig)
	 *
	 * First the ML-DSA PK, then the traditional PK. As we have ED448,
	 * the code takes the ED448 PK size and the remainder is the
	 * ML-DSA PK.
	 */
	dilithium_src = sig->s;
	dilithium_src_len = sig->s_size - LC_ED448_SIGBYTES;
	ed448_src = dilithium_src + dilithium_src_len;
	ed448_src_len = LC_ED448_SIGBYTES;
	CKINT(lc_dilithium_ed448_sig_load(&ws->dilithium_sig, dilithium_src,
					  dilithium_src_len, ed448_src,
					  ed448_src_len));

	printf_debug("Loaded composite signature of size %zu\n", sig->s_size);

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium_ed448(sig, ctx));

		if (sig->request_prehash) {
			/*
			 * Verify the signature using HashComposite-ML-DSA
			 */
			CKINT(lc_dilithium_ed448_verify_init(
				ctx, &ws->dilithium_pk));
			CKINT(lc_dilithium_ed448_verify_update(
				ctx, sig->digest, sig->digest_size));
			CKINT(lc_dilithium_ed448_verify_final(
				&ws->dilithium_sig, ctx, &ws->dilithium_pk));
		} else {
			/*
			 * Verify the signature using Composite-ML-DSA
			 */
			CKINT(lc_dilithium_ed448_verify_ctx(
				&ws->dilithium_sig, ctx, sig->digest,
				sig->digest_size, &ws->dilithium_pk));
		}
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature using Composite-ML-DSA
		 */
		CKINT(lc_dilithium_ed448_verify_ctx(
			&ws->dilithium_sig, ctx, sig->raw_data,
			sig->raw_data_len, &ws->dilithium_pk));
	}

out:
	lc_dilithium_ed448_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_dilithium_ed448(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
	//TODO reduce buffer size
#define LC_ASYM_DILITHIUM_ED448_SIGBUF_SIZE 8192
	struct workspace {
		uint8_t sigbuf[LC_ASYM_DILITHIUM_ED448_SIGBUF_SIZE];
		struct lc_dilithium_ed448_sig dilithium_ed448_sig;
	};
	struct lc_dilithium_ed448_sk *dilithium_ed448_sk =
		keys->sk.dilithium_ed448_sk;
	size_t ml_dsa_siglen, ed448_siglen;
	uint8_t *ml_dsa_ptr, *ed448_ptr;
	int ret;
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium_ed448(sig, ctx));

		if (sig->request_prehash) {
			/*
			 * Sign the hash using HashComposite-ML-DSA
			 */
			CKINT(lc_dilithium_ed448_sign_init(ctx,
							   dilithium_ed448_sk));
			CKINT(lc_dilithium_ed448_sign_update(ctx, sig->digest,
							     sig->digest_size));
			CKINT(lc_dilithium_ed448_sign_final(
				&ws->dilithium_ed448_sig, ctx,
				dilithium_ed448_sk, lc_seeded_rng));
		} else {
			/*
			 * Sign the signature using Composite-ML-DSA
			 */
			CKINT(lc_dilithium_ed448_sign_ctx(
				&ws->dilithium_ed448_sig, ctx, sig->digest,
				sig->digest_size, dilithium_ed448_sk,
				lc_seeded_rng));
		}
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Sign the signature using Composite-ML-DSA
		 */
		CKINT(lc_dilithium_ed448_sign_ctx(
			&ws->dilithium_ed448_sig, ctx, sig->raw_data,
			sig->raw_data_len, dilithium_ed448_sk, lc_seeded_rng));
	}

	CKINT(lc_dilithium_ed448_sig_ptr(&ml_dsa_ptr, &ml_dsa_siglen,
					 &ed448_ptr, &ed448_siglen,
					 &ws->dilithium_ed448_sig));

	/*
	 * Concatenate the signature data into the buffer according to
	 * draft version 5.
	 */
	CKINT(x509_concatenate_bit_string(&sig_data, available_len, ml_dsa_ptr,
					  ml_dsa_siglen));
	CKINT(x509_concatenate_bit_string(&sig_data, available_len, ed448_ptr,
					  ed448_siglen));

	printf_debug("Set composite signature of size %zu\n",
		     ml_dsa_siglen + ed448_siglen);

out:
	lc_dilithium_ed448_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_signature_size_dilithium_ed448(
	enum lc_dilithium_type dilithium_type, size_t *size)
{
	/* sig sizes of both components */
	*size = lc_dilithium_sig_size(dilithium_type) + LC_ED448_SIGBYTES;
	return 0;
}

int asym_set_dilithium_ed448_keypair(struct lc_x509_key_data *gen_data,
				     struct lc_dilithium_ed448_pk *pk,
				     struct lc_dilithium_ed448_sk *sk)
{
	uint8_t *dilithium_pk_ptr, *ed448_pk_ptr;
	size_t dilithium_pk_len, ed448_pk_len;
	enum lc_dilithium_type dilithium_ed448_type = LC_DILITHIUM_UNKNOWN;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_X509_SKID_DEFAULT_HASH);

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		dilithium_ed448_type = lc_dilithium_ed448_pk_type(pk);

		gen_data->pk.dilithium_ed448_pk = pk;

		CKINT(lc_dilithium_ed448_pk_ptr(
			&dilithium_pk_ptr, &dilithium_pk_len, &ed448_pk_ptr,
			&ed448_pk_len, pk));
		lc_hash_init(hash_ctx);
		lc_hash_update(hash_ctx, dilithium_pk_ptr, dilithium_pk_len);
		lc_hash_update(hash_ctx, ed448_pk_ptr, ed448_pk_len);
		lc_hash_final(hash_ctx, gen_data->pk_digest);
		lc_hash_zero(hash_ctx);
	}

	if (sk) {
		dilithium_ed448_type = lc_dilithium_ed448_sk_type(sk);

		gen_data->sk.dilithium_ed448_sk = sk;
	}

	switch (dilithium_ed448_type) {
	case LC_DILITHIUM_44:
		gen_data->sig_type = LC_SIG_DILITHIUM_44_ED448;
		break;
	case LC_DILITHIUM_65:
		gen_data->sig_type = LC_SIG_DILITHIUM_65_ED448;
		break;
	case LC_DILITHIUM_87:
		gen_data->sig_type = LC_SIG_DILITHIUM_87_ED448;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium ED448 type\n");
		return -ENOPKG;
	}

out:
	return ret;
}
