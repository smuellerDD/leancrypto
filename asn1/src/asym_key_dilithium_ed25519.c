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
#include "asym_key_dilithium_ed25519.h"
#include "dilithium_helper.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"
#include "x509_composite_mldsa_privkey.asn1.h"
#include "x509_composite_mldsa_pubkey.asn1.h"
#include "x509_composite_mldsa_signature.asn1.h"

static int public_key_set_prehash_dilithium_ed25519(
	const struct lc_public_key_signature *sig,
	struct lc_dilithium_ed25519_ctx *ctx)
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

	lc_dilithium_ed25519_ctx_hash(ctx, hash_algo);

out:
	return ret;
}

int x509_ed25519_signature(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct lc_dilithium_ed25519_sig *dilithium_ed25519_sig = context;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_ed25519_sig_load_partial(dilithium_ed25519_sig, NULL,
						    0, value + 1, vlen - 1));

	printf_debug("Loaded ED25519 signature of size %zu\n", vlen - 1);

out:
	return ret;
}

int x509_mldsa_signature(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	struct lc_dilithium_ed25519_sig *dilithium_ed25519_sig = context;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_ed25519_sig_load_partial(
		dilithium_ed25519_sig, value + 1, vlen - 1, NULL, 0));

	printf_debug("Loaded ML-DSA signature of size %zu\n", vlen - 1);

out:
	return ret;
}

int x509_ed25519_signature_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	struct lc_dilithium_ed25519_sig *dilithium_ed25519_sig = context;
	size_t ml_dsa_siglen, ed25519_siglen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_sig_ptr(&ml_dsa_ptr, &ml_dsa_siglen,
					   &ed25519_ptr, &ed25519_siglen,
					   dilithium_ed25519_sig));

	CKINT(x509_set_bit_string(data, avail_datalen, ed25519_ptr,
				  ed25519_siglen));

	printf_debug("Set ED25519 signature of size %zu\n", ed25519_siglen);

out:
	return ret;
}

int x509_mldsa_signature_enc(void *context, uint8_t *data,
			     size_t *avail_datalen, uint8_t *tag)
{
	struct lc_dilithium_ed25519_sig *dilithium_ed25519_sig = context;
	size_t ml_dsa_siglen, ed25519_siglen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_sig_ptr(&ml_dsa_ptr, &ml_dsa_siglen,
					   &ed25519_ptr, &ed25519_siglen,
					   dilithium_ed25519_sig));

	CKINT(x509_set_bit_string(data, avail_datalen, ml_dsa_ptr,
				  ml_dsa_siglen));

	printf_debug("Set ML-DSA signature of size %zu\n", ml_dsa_siglen);

out:
	return ret;
}

int x509_ed25519_public_key(void *context, size_t hdrlen, unsigned char tag,
			    const uint8_t *value, size_t vlen)
{
	struct lc_dilithium_ed25519_pk *dilithium_pk = context;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_ed25519_pk_load_partial(dilithium_pk, NULL, 0,
						   value + 1, vlen - 1));

	printf_debug("Loaded ED25519 public key of size %zu\n", vlen - 1);

out:
	return ret;
}

int x509_mldsa_public_key(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct lc_dilithium_ed25519_pk *dilithium_pk = context;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_ed25519_pk_load_partial(dilithium_pk, value + 1,
						   vlen - 1, NULL, 0));

	printf_debug("Loaded ML-DSA public key of size %zu\n", vlen - 1);

out:
	return ret;
}

int x509_ed25519_public_key_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_key_data *gen_data = &cert->pub_gen_data;
	size_t ml_dsa_pklen, ed25519_pklen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_pk_ptr(&ml_dsa_ptr, &ml_dsa_pklen,
					  &ed25519_ptr, &ed25519_pklen,
					  gen_data->pk.dilithium_ed25519_pk));

	CKINT(x509_set_bit_string(data, avail_datalen, ed25519_ptr,
				  ed25519_pklen));

	printf_debug("Set ED25519 public key of size %zu\n", ed25519_pklen);

out:
	return ret;
}

int x509_mldsa_public_key_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_key_data *gen_data = &cert->pub_gen_data;
	size_t ml_dsa_pklen, ed25519_pklen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_pk_ptr(&ml_dsa_ptr, &ml_dsa_pklen,
					  &ed25519_ptr, &ed25519_pklen,
					  gen_data->pk.dilithium_ed25519_pk));

	CKINT(x509_set_bit_string(data, avail_datalen, ml_dsa_ptr,
				  ml_dsa_pklen));

	printf_debug("Set ML-DSA public key of size %zu\n", ml_dsa_pklen);

out:
	return ret;
}

int public_key_encode_dilithium_ed25519(uint8_t *data, size_t *avail_datalen,
					struct x509_generate_context *ctx)
{
	int ret;

	CKINT(asn1_ber_encoder(&x509_composite_mldsa_pubkey_encoder, ctx, data,
			       avail_datalen));

out:
	return ret;
}

int x509_mldsa_composite_private_key_enc(void *context, uint8_t *data,
					 size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ml_dsa_pklen, ed25519_pklen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_sk_ptr(&ml_dsa_ptr, &ml_dsa_pklen,
					  &ed25519_ptr, &ed25519_pklen,
					  keys->sk.dilithium_ed25519_sk));

	CKINT(x509_set_bit_string(data, avail_datalen, ml_dsa_ptr,
				  ml_dsa_pklen));

	printf_debug("Set ML-DSA private key of size %zu\n", ml_dsa_pklen);

out:
	return ret;
}

int x509_ed25519_private_key_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ml_dsa_pklen, ed25519_pklen;
	uint8_t *ml_dsa_ptr, *ed25519_ptr;
	int ret;

	(void)tag;

	CKINT(lc_dilithium_ed25519_sk_ptr(&ml_dsa_ptr, &ml_dsa_pklen,
					  &ed25519_ptr, &ed25519_pklen,
					  keys->sk.dilithium_ed25519_sk));

	CKINT(x509_set_bit_string(data, avail_datalen, ed25519_ptr,
				  ed25519_pklen));

	printf_debug("Set ED25519 public key of size %zu\n", ed25519_pklen);

out:
	return ret;
}

int private_key_encode_dilithium_ed25519(
	uint8_t *data, size_t *avail_datalen,
	struct x509_generate_privkey_context *ctx)
{
	int ret;

	CKINT(asn1_ber_encoder(&x509_composite_mldsa_privkey_encoder, ctx, data,
			       avail_datalen));

out:
	return ret;
}

int x509_mldsa_composite_private_key(void *context, size_t hdrlen,
				     unsigned char tag, const uint8_t *value,
				     size_t vlen)
{
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_ed25519_sk *dilithium_sk =
		keys->sk.dilithium_ed25519_sk;
	int ret;

	(void)hdrlen;
	(void)tag;

	/*
	 * Account for the BIT STRING
	 */
	if (vlen < 1)
		return -EBADMSG;
	CKINT(lc_dilithium_ed25519_sk_load_partial(dilithium_sk, value + 1,
						   vlen - 1, NULL, 0));

	printf_debug("Loaded ML-DSA secret key of size %zu\n", vlen - 1);

out:
	return ret;
}

int x509_ed25519_private_key(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct lc_x509_key_data *keys = context;
	struct lc_dilithium_ed25519_sk *dilithium_sk =
		keys->sk.dilithium_ed25519_sk;
	int ret;

	(void)hdrlen;
	(void)tag;

	CKINT(lc_dilithium_ed25519_sk_load_partial(dilithium_sk, NULL, 0,
						   value + 1, vlen - 1));

	printf_debug("Loaded ED25519 secret key of size %zu\n", vlen - 1);

out:
	return ret;
}

int private_key_decode_dilithium_ed25519(struct lc_x509_key_data *keys,
					 const uint8_t *data, size_t datalen)
{
	int ret;

	CKINT(asn1_ber_decoder(&x509_composite_mldsa_privkey_decoder, keys,
			       data, datalen));

out:
	return ret;
}

int public_key_verify_signature_dilithium_ed25519(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct workspace {
		struct lc_dilithium_ed25519_pk dilithium_pk;
		struct lc_dilithium_ed25519_sig dilithium_sig;
	};
	int ret;
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	if (sig->s_size < LC_ED25519_PUBLICKEYBYTES)
		return -EINVAL;

	CKINT(asn1_ber_decoder(&x509_composite_mldsa_pubkey_decoder,
			       &ws->dilithium_pk, pkey->key, pkey->keylen));
	CKINT(asn1_ber_decoder(&x509_composite_mldsa_signature_decoder,
			       &ws->dilithium_sig, sig->s, sig->s_size));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium_ed25519(sig, ctx));

		if (sig->request_prehash) {
			/*
			 * Verify the signature using HashComposite-ML-DSA
			 */
			CKINT(lc_dilithium_ed25519_verify_init(
				ctx, &ws->dilithium_pk));
			CKINT(lc_dilithium_ed25519_verify_update(
				ctx, sig->digest, sig->digest_size));
			CKINT(lc_dilithium_ed25519_verify_final(
				&ws->dilithium_sig, ctx, &ws->dilithium_pk));
		} else {
			/*
			 * Verify the signature using Composite-ML-DSA
			 */
			CKINT(lc_dilithium_ed25519_verify_ctx(
				&ws->dilithium_sig, ctx, sig->digest,
				sig->digest_size, &ws->dilithium_pk));
		}
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature using Composite-ML-DSA
		 */
		CKINT(lc_dilithium_ed25519_verify_ctx(
			&ws->dilithium_sig, ctx, sig->raw_data,
			sig->raw_data_len, &ws->dilithium_pk));
	}

out:
	lc_dilithium_ed25519_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_dilithium_ed25519(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
	//TODO reduce buffer size
#define LC_ASYM_DILITHIUM_ED25519_SIGBUF_SIZE 8192
	struct workspace {
		uint8_t sigbuf[LC_ASYM_DILITHIUM_ED25519_SIGBUF_SIZE];
		struct lc_dilithium_ed25519_sig dilithium_ed25519_sig;
	};
	struct lc_dilithium_ed25519_sk *dilithium_ed25519_sk =
		keys->sk.dilithium_ed25519_sk;
	size_t siglen = LC_ASYM_DILITHIUM_ED25519_SIGBUF_SIZE;
	int ret;
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * Select the data to be signed
	 */
	if (sig->digest_size) {
		CKINT(public_key_set_prehash_dilithium_ed25519(sig, ctx));

		if (sig->request_prehash) {
			/*
			 * Sign the hash using HashComposite-ML-DSA
			 */
			CKINT(lc_dilithium_ed25519_sign_init(
				ctx, dilithium_ed25519_sk));
			CKINT(lc_dilithium_ed25519_sign_update(
				ctx, sig->digest, sig->digest_size));
			CKINT(lc_dilithium_ed25519_sign_final(
				&ws->dilithium_ed25519_sig, ctx,
				dilithium_ed25519_sk, lc_seeded_rng));
		} else {
			/*
			 * Sign the signature using Composite-ML-DSA
			 */
			CKINT(lc_dilithium_ed25519_sign_ctx(
				&ws->dilithium_ed25519_sig, ctx, sig->digest,
				sig->digest_size, dilithium_ed25519_sk,
				lc_seeded_rng));
		}
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Sign the signature using Composite-ML-DSA
		 */
		CKINT(lc_dilithium_ed25519_sign_ctx(
			&ws->dilithium_ed25519_sig, ctx, sig->raw_data,
			sig->raw_data_len, dilithium_ed25519_sk,
			lc_seeded_rng));
	}

	/*
	 * Encode the signature
	 */
	CKINT(asn1_ber_encoder(&x509_composite_mldsa_signature_encoder,
			       &ws->dilithium_ed25519_sig, ws->sigbuf,
			       &siglen));
	siglen = LC_ASYM_DILITHIUM_ED25519_SIGBUF_SIZE - siglen;

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
	memcpy(sig_data, ws->sigbuf, siglen);
	*available_len -= siglen;

out:
	lc_dilithium_ed25519_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_signature_size_dilithium_ed25519(
	enum lc_dilithium_type dilithium_type, size_t *size)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
		*size = 4703;
		break;
	case LC_DILITHIUM_65:
		*size = 3385;
		break;
	case LC_DILITHIUM_44:
		*size = 2496;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -ENOPKG;
	}

	return 0;

	/* The values above are generated with the following code */
#if 0
	size_t siglen, enc_len = 0;
	int ret;

	/* Encoding of the first sequence part plus the BIT STRING prefix */
	siglen = lc_dilithium_sig_size(dilithium_type);
	siglen += 1;
	CKINT(asn1_encode_length_size(siglen, &enc_len));
	siglen += enc_len;
	/* Tag */
	siglen += 1;

	/* Encoding of the first sequence part plus the BIT STRING prefix */
	siglen += LC_ED25519_SIGBYTES;
	siglen += 1;
	CKINT(asn1_encode_length_size(LC_ED25519_SIGBYTES, &enc_len));
	siglen += enc_len;
	/* Tag */
	siglen += 1;

	/* Encoding of the sequence */
	CKINT(asn1_encode_length_size(siglen, &enc_len));
	siglen += enc_len;
	/* Tag */
	siglen += 1;

	*size = siglen;

out:
	return ret;
#endif
}

int asym_set_dilithium_ed25519_keypair(struct lc_x509_key_data *gen_data,
				       struct lc_dilithium_ed25519_pk *pk,
				       struct lc_dilithium_ed25519_sk *sk)
{
	uint8_t *dilithium_pk_ptr, *ed25519_pk_ptr;
	size_t dilithium_pk_len, ed25519_pk_len;
	enum lc_dilithium_type dilithium_ed25519_type = LC_DILITHIUM_UNKNOWN;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_X509_SKID_DEFAULT_HASH);

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		dilithium_ed25519_type = lc_dilithium_ed25519_pk_type(pk);

		gen_data->pk.dilithium_ed25519_pk = pk;

		CKINT(lc_dilithium_ed25519_pk_ptr(&dilithium_pk_ptr,
						  &dilithium_pk_len,
						  &ed25519_pk_ptr,
						  &ed25519_pk_len,
						  pk));
		lc_hash_init(hash_ctx);
		lc_hash_update(hash_ctx, dilithium_pk_ptr, dilithium_pk_len);
		lc_hash_update(hash_ctx, ed25519_pk_ptr, ed25519_pk_len);
		lc_hash_final(hash_ctx, gen_data->pk_digest);
		lc_hash_zero(hash_ctx);
	}

	if (sk) {
		dilithium_ed25519_type = lc_dilithium_ed25519_sk_type(sk);

		gen_data->sk.dilithium_ed25519_sk = sk;
	}

	switch (dilithium_ed25519_type) {
	case LC_DILITHIUM_44:
		gen_data->sig_type = LC_SIG_DILITHIUM_44_ED25519;
		break;
	case LC_DILITHIUM_65:
		gen_data->sig_type = LC_SIG_DILITHIUM_65_ED25519;
		break;
	case LC_DILITHIUM_87:
		gen_data->sig_type = LC_SIG_DILITHIUM_87_ED25519;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium ED25519 type\n");
		return -ENOPKG;
	}

out:
	return ret;
}
