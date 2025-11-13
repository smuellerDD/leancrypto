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
#include "ext_headers_internal.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"
#include "x509_mldsa_ed448_privkey_asn1.h"

/*
 * Size of the hash of the message: see
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
 */
#define LC_X509_COMP_ED448_MSG_SIZE 64

int x509_mldsa_ed448_private_key_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
#ifdef LC_X509_GENERATOR
	const struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ml_dsa_sklen, ed448_sklen;
	uint8_t *ml_dsa_ptr, *ed448_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed448_sk_ptr(&ml_dsa_ptr, &ml_dsa_sklen, &ed448_ptr,
					&ed448_sklen,
					keys->sk.dilithium_ed448_sk));

	/* Pointers are not used */
	(void)ml_dsa_ptr;
	(void)ml_dsa_sklen;

	/*
	 * See draft version 5:
	 * Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) -> bytes
	 *
	 * First the ML-DSA seed, then the traditional SK.
	 */
	CKINT(x509_set_bit_string(&data, avail_datalen, keys->sk_seed,
				  LC_X509_PQC_SK_SEED_SIZE));
	CKINT(x509_concatenate_bit_string(&data, avail_datalen, ed448_ptr,
					  ed448_sklen));

	printf_debug("Set composite secret key of size %zu\n",
		     LC_X509_PQC_SK_SEED_SIZE + ed448_sklen);

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

int private_key_encode_dilithium_ed448(uint8_t *data, size_t *avail_datalen,
				       struct x509_generate_privkey_context *ctx)
{
#ifdef LC_X509_GENERATOR
	int ret;

	CKINT(asn1_ber_encoder_small(&x509_mldsa_ed448_privkey_encoder, ctx,
				     data, avail_datalen));

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
}

int x509_mldsa_ed448_private_key(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
	};
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_ed448_sk *dilithium_sk =
		keys->sk.dilithium_ed448_sk;
	const uint8_t *data, *ed448_src_key;
	uint8_t *dilithium_src_key;
	size_t datalen, dilithium_src_key_len, ed448_src_key_len;
	enum lc_dilithium_type dilithium_type = LC_DILITHIUM_UNKNOWN;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;

	datalen = vlen - 1;
	data = value + 1;

	if (datalen != LC_ED448_SECRETKEYBYTES + LC_X509_PQC_SK_SEED_SIZE)
		return -EINVAL;

	/*
	 * See draft version 5:
	 * Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)
	 *
	 * First the ML-DSA seed, then the traditional SK.
	 */

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44_ED448:
		dilithium_type = LC_DILITHIUM_44;
		break;
	case LC_SIG_DILITHIUM_65_ED448:
		dilithium_type = LC_DILITHIUM_65;
		break;
	case LC_SIG_DILITHIUM_87_ED448:
		dilithium_type = LC_DILITHIUM_87;
		break;

	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
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
	memcpy(keys->sk_seed, data, LC_X509_PQC_SK_SEED_SIZE);
	keys->sk_seed_set = 1;

	/*
	 * See draft version 5:
	 * Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)
	 *
	 * First the ML-DSA seed, then the traditional SK.
	 */
	CKINT(lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, keys->sk_seed,
					     LC_X509_PQC_SK_SEED_SIZE,
					     dilithium_type));
	CKINT(lc_dilithium_sk_ptr(&dilithium_src_key, &dilithium_src_key_len,
				  &ws->sk));

	ed448_src_key = data + LC_X509_PQC_SK_SEED_SIZE;
	ed448_src_key_len = LC_ED448_SECRETKEYBYTES;

	CKINT(lc_dilithium_ed448_sk_load(dilithium_sk, dilithium_src_key,
					 dilithium_src_key_len, ed448_src_key,
					 ed448_src_key_len));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int private_key_decode_dilithium_ed448(struct lc_x509_key_data *keys,
				       const uint8_t *data, size_t datalen)
{
	int ret;

	CKINT(asn1_ber_decoder(&x509_mldsa_ed448_privkey_decoder, keys, data,
			       datalen));

out:
	return ret;
}

int public_key_encode_dilithium_ed448(uint8_t *data, size_t *avail_datalen,
				      struct x509_generate_context *ctx)
{
#ifdef LC_X509_GENERATOR
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
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
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

static int
public_key_dilithium_ed448_get_data(const uint8_t **data_ptr, size_t *data_len,
				    const struct lc_public_key_signature *sig)
{
	/*
	 * Select the data to be signed
	 *
	 * We do not support pre-hashed messages! I.e. sig->digest is not
	 * considered.
	 */
	if (sig->authattrs) {
		*data_ptr = sig->authattrs;
		*data_len = sig->authattrs_size;
		return 0;
	} else if (sig->raw_data) {
		*data_ptr = sig->raw_data;
		*data_len = sig->raw_data_len;
		return 0;
	} else {
		return -EOPNOTSUPP;
	}
}

int public_key_verify_signature_dilithium_ed448(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct workspace {
		struct lc_dilithium_ed448_pk dilithium_pk;
		struct lc_dilithium_ed448_sig dilithium_sig;
		uint8_t ph_message[LC_X509_COMP_ED448_MSG_SIZE];
	};
	const struct lc_hash *hash_algo;
	const uint8_t *dilithium_src, *ed448_src, *randomizer, *data_ptr;
	size_t dilithium_src_len, ed448_src_len, data_len;
	int ret;
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(public_key_dilithium_ed448_get_data(&data_ptr, &data_len, sig));

	if (sig->s_size <
	    (LC_ED448_SIGBYTES + LC_X509_SIGNATURE_RANDOMIZER_SIZE))
		return -EINVAL;

	CKINT(public_key_decode_dilithium_ed448(&ws->dilithium_pk, pkey->key,
						pkey->keylen));

	/*
	 * See draft version 5:
	 * Composite-ML-DSA<OID>.DeserializeSignatureValue(bytes)
	 *	-> (r, mldsaSig, tradSig)
	 *
	 * First the ML-DSA PK, then the traditional PK. As we have ED448,
	 * the code takes the ED448 PK size and the remainder is the
	 * ML-DSA PK.
	 */
	randomizer = sig->s;
	dilithium_src = sig->s + LC_X509_SIGNATURE_RANDOMIZER_SIZE;
	dilithium_src_len = sig->s_size - LC_ED448_SIGBYTES -
			    LC_X509_SIGNATURE_RANDOMIZER_SIZE;
	ed448_src = dilithium_src + dilithium_src_len;
	ed448_src_len = LC_ED448_SIGBYTES;

	CKINT(lc_dilithium_ed448_sig_load(&ws->dilithium_sig, dilithium_src,
					  dilithium_src_len, ed448_src,
					  ed448_src_len));

	printf_debug("Loaded composite signature of size %zu\n", sig->s_size);

	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
	/* XOF works as digest size of 64 bytes is same as XOF size */
	CKINT(lc_xof(hash_algo, data_ptr, data_len, ws->ph_message,
		     sizeof(ws->ph_message)));

	/*
	 * TODO currently no ctx is supported. This implies that ctx == NULL.
	 * Yet, the ctx can be added to struct lc_public_key_signature.
	 */
	lc_dilithium_ed448_ctx_userctx(ctx, NULL, 0);
	lc_dilithium_ed448_ctx_randomizer(ctx, randomizer,
					  LC_X509_SIGNATURE_RANDOMIZER_SIZE);

	/*
	 * Verify the signature using Composite-ML-DSA
	 */
	CKINT(lc_dilithium_ed448_verify_ctx(
		&ws->dilithium_sig, ctx, ws->ph_message, sizeof(ws->ph_message),
		&ws->dilithium_pk));

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
#ifdef LC_X509_GENERATOR
	struct workspace {
		uint8_t randomizer[LC_X509_SIGNATURE_RANDOMIZER_SIZE];
		uint8_t ph_message[LC_X509_COMP_ED448_MSG_SIZE];
		struct lc_dilithium_ed448_sig dilithium_ed448_sig;
	};
	const struct lc_hash *hash_algo;
	struct lc_dilithium_ed448_sk *dilithium_ed448_sk =
		keys->sk.dilithium_ed448_sk;
	size_t ml_dsa_siglen, ed448_siglen, data_len;
	const uint8_t *data_ptr;
	uint8_t *ml_dsa_ptr, *ed448_ptr;
	int ret;
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(public_key_dilithium_ed448_get_data(&data_ptr, &data_len, sig));

	/* Generate the randomizer value */
	CKINT(lc_rng_generate(lc_seeded_rng, (uint8_t *)"X509.Comp.Sig.448", 17,
			      ws->randomizer, sizeof(ws->randomizer)));

	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
	/* XOF works as digest size of 64 bytes is same as XOF size */
	CKINT(lc_xof(hash_algo, data_ptr, data_len, ws->ph_message,
		     sizeof(ws->ph_message)));

	/*
	 * TODO currently no ctx is supported. This implies that ctx == NULL.
	 * Yet, the ctx can be added to struct lc_public_key_signature.
	 */
	lc_dilithium_ed448_ctx_userctx(ctx, NULL, 0);
	lc_dilithium_ed448_ctx_randomizer(ctx, ws->randomizer,
					  sizeof(ws->randomizer));

	/* Sign the signature using Composite-ML-DSA */
	CKINT(lc_dilithium_ed448_sign_ctx(
		&ws->dilithium_ed448_sig, ctx, ws->ph_message,
		sizeof(ws->ph_message), dilithium_ed448_sk, lc_seeded_rng));

	CKINT(lc_dilithium_ed448_sig_ptr(&ml_dsa_ptr, &ml_dsa_siglen,
					 &ed448_ptr, &ed448_siglen,
					 &ws->dilithium_ed448_sig));

	/*
	 * Concatenate the signature data into the buffer according to
	 * draft version 5.
	 */
	CKINT(x509_concatenate_bit_string(&sig_data, available_len,
					  ws->randomizer,
					  sizeof(ws->randomizer)));
	CKINT(x509_concatenate_bit_string(&sig_data, available_len, ml_dsa_ptr,
					  ml_dsa_siglen));
	CKINT(x509_concatenate_bit_string(&sig_data, available_len, ed448_ptr,
					  ed448_siglen));

	printf_debug("Set composite signature of size %zu\n",
		     sizeof(ws->randomizer) + ml_dsa_siglen + ed448_siglen);

out:
	lc_dilithium_ed448_ctx_zero(ctx);
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

int public_key_signature_size_dilithium_ed448(
	enum lc_dilithium_type dilithium_type, size_t *size)
{
	/* sig sizes of all components */
	*size = lc_dilithium_sig_size(dilithium_type) + LC_ED448_SIGBYTES +
		LC_X509_SIGNATURE_RANDOMIZER_SIZE;
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
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, dilithium_pk_ptr, dilithium_pk_len);
		lc_hash_update(hash_ctx, ed448_pk_ptr, ed448_pk_len);
		lc_hash_final(hash_ctx, gen_data->pk_digest);
		lc_hash_zero(hash_ctx);
	}

	if (sk) {
		if (dilithium_ed448_type != LC_DILITHIUM_UNKNOWN) {
			enum lc_dilithium_type tmp =
				lc_dilithium_ed448_sk_type(sk);
			if (tmp != dilithium_ed448_type) {
				printf_debug(
					"Public and private key types mismatch\n");
				ret = -EINVAL;
				goto out;
			}
		} else {
			dilithium_ed448_type = lc_dilithium_ed448_sk_type(sk);
		}

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

int asym_keypair_gen_dilithium_ed448(struct lc_x509_certificate *cert,
				     struct lc_x509_key_data *keys,
				     enum lc_dilithium_type dilithium_key_type)
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
		struct lc_ed448_pk pk_ed448;
		struct lc_ed448_sk sk_ed448;
	};
	uint8_t *dilithium_pk_ptr, *dilithium_sk_ptr;
	size_t dilithium_pk_len, dilithium_sk_len;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(asym_keypair_gen_seed(keys, "ML-DSA-ED448", 12));

	CKINT(lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, keys->sk_seed,
					     LC_X509_PQC_SK_SEED_SIZE,
					     dilithium_key_type));
	CKINT(lc_dilithium_pk_ptr(&dilithium_pk_ptr, &dilithium_pk_len,
				  &ws->pk));
	CKINT(lc_dilithium_sk_ptr(&dilithium_sk_ptr, &dilithium_sk_len,
				  &ws->sk));

	CKINT(lc_ed448_keypair(&ws->pk_ed448, &ws->sk_ed448, lc_seeded_rng));

	CKINT(lc_dilithium_ed448_sk_load(
		keys->sk.dilithium_ed448_sk, dilithium_sk_ptr, dilithium_sk_len,
		ws->sk_ed448.sk, LC_ED448_SECRETKEYBYTES));
	CKINT(lc_dilithium_ed448_pk_load(
		keys->pk.dilithium_ed448_pk, dilithium_pk_ptr, dilithium_pk_len,
		ws->pk_ed448.pk, LC_ED448_PUBLICKEYBYTES));

	CKINT(asym_set_dilithium_ed448_keypair(&cert->sig_gen_data,
					       keys->pk.dilithium_ed448_pk,
					       keys->sk.dilithium_ed448_sk));
	CKINT(asym_set_dilithium_ed448_keypair(
		&cert->pub_gen_data, keys->pk.dilithium_ed448_pk, NULL));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
