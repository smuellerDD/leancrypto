/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include "asym_key_ed448.h"
#include "ed448_ctx.h"
#include "ext_headers_internal.h"
#include "lc_ed448.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "pkcs7_internal.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"

int private_key_encode_ed448(uint8_t *data, size_t *avail_datalen,
			     struct x509_generate_privkey_context *ctx)
{
#ifdef LC_X509_GENERATOR
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ed448_sklen;
	uint8_t *ed448_ptr;
	int ret;

	CKINT(lc_ed448_sk_ptr(&ed448_ptr, &ed448_sklen,
				keys->sk.ed448_sk));

	/* Only export the secret part of the ED448 secret key */
	CKINT(lc_x509_concatenate_bit_string(&data, avail_datalen, ed448_ptr,
					     ed448_sklen));

	printf_debug("Set composite secret key of size %u\n", ed448_sklen);

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
}

int private_key_decode_ed448(struct lc_x509_key_data *keys,
			     const uint8_t *data, size_t datalen)
{
	struct lc_ed448_sk *sk = keys->sk.ed448_sk;
	int ret;

	CKINT(lc_ed448_sk_load(sk, data, datalen));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

int public_key_decode_ed448(struct lc_ed448_pk *ed448_pk,
			    const uint8_t *data, size_t datalen)
{
	int ret;

	if (datalen != LC_ED448_PUBLICKEYBYTES)
		return -EINVAL;

	CKINT(lc_ed448_pk_load(ed448_pk, data, LC_ED448_PUBLICKEYBYTES));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

static int
public_key_ed448_get_data(const uint8_t **data_ptr,
			  size_t *data_len, int *authattrs_tag,
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
		if (authattrs_tag)
			*authattrs_tag = 1;
		return 0;
	} else if (sig->raw_data) {
		*data_ptr = sig->raw_data;
		*data_len = sig->raw_data_len;
		if (authattrs_tag)
			*authattrs_tag = 0;
		return 0;
	} else {
		return -EOPNOTSUPP;
	}
}

int public_key_verify_signature_ed448(const struct lc_public_key *pkey,
				      const struct lc_public_key_signature *sig)
{
	struct workspace {
		struct lc_ed448_pk pk;
		struct lc_ed448_sig sig;
		struct lc_dilithium_ed448_ctx sign_ctx;
	};
	const uint8_t *data_ptr;
	size_t data_len;
	int ret, authattrs_tag;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(public_key_ed448_get_data(&data_ptr, &data_len,
					&authattrs_tag, sig));

	if (sig->s_size != LC_ED448_SIGBYTES)
		return -EBADMSG;

	CKINT(public_key_decode_ed448(&ws->pk, pkey->key, pkey->keylen));

	CKINT(lc_ed448_sig_load(&ws->sig, sig->s, sig->s_size));

	printf_debug("Loaded Ed448 signature of size %zu\n", sig->s_size);

	if (authattrs_tag) {
		/* Add the authattr tag */
		ws->sign_ctx.msg_prefix = &lc_pkcs7_authattr_tag;
		ws->sign_ctx.msg_prefix_len = sizeof(lc_pkcs7_authattr_tag);
	}

	CKINT(lc_ed448_verify_ctx(&ws->sig, data_ptr, data_len, &ws->pk,
				  &ws->sign_ctx));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_ed448(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
#ifdef LC_X509_GENERATOR
	struct workspace {
		struct lc_ed448_sig ed448_sig;
	};
	struct lc_ed448_sk *ed448_sk = keys->sk.ed448_sk;
	size_t ed448_siglen, data_len;
	const uint8_t *data_ptr;
	uint8_t *ed448_ptr;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(public_key_ed448_get_data(&data_ptr, &data_len, NULL, sig));

	/* Sign the signature using Composite-ML-DSA */
	CKINT(lc_ed448_sign(&ws->ed448_sig, data_ptr, data_len, ed448_sk,
			      lc_seeded_rng));

	CKINT(lc_ed448_sig_ptr(&ed448_ptr, &ed448_siglen, &ws->ed448_sig));

	CKINT(lc_x509_concatenate_bit_string(&sig_data, available_len,
					     ed448_ptr, ed448_siglen));

	printf_debug("Set Ed448 signature of size %zu\n", ed448_siglen);

out:
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

int asym_set_ed448_keypair(struct lc_x509_key_data *gen_data,
			   struct lc_ed448_pk *pk, struct lc_ed448_sk *sk)
{
	uint8_t *ed448_pk_ptr;
	size_t ed448_pk_len;
	int ret = 0;

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		gen_data->pk.ed448_pk = pk;

		CKINT(lc_ed448_pk_ptr(&ed448_pk_ptr, &ed448_pk_len, pk));
		CKINT(lc_hash(LC_X509_SKID_DEFAULT_HASH, ed448_pk_ptr,
			      ed448_pk_len, gen_data->pk_digest));
	}

	if (sk)
		gen_data->sk.ed448_sk = sk;

	gen_data->sig_type = LC_SIG_ED448;

out:
	return ret;
}

int asym_keypair_gen_ed448(struct lc_x509_certificate *cert,
			   struct lc_x509_key_data *keys)
{
	struct workspace {
		struct lc_ed448_pk pk_ed448;
		struct lc_ed448_sk sk_ed448;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_ed448_keypair(&ws->pk_ed448, &ws->sk_ed448,
				 lc_seeded_rng));

	CKINT(lc_ed448_sk_load(keys->sk.ed448_sk, ws->sk_ed448.sk,
				 LC_ED448_SECRETKEYBYTES));
	CKINT(lc_ed448_pk_load(keys->pk.ed448_pk, ws->pk_ed448.pk,
				 LC_ED448_PUBLICKEYBYTES));

	CKINT(asym_set_ed448_keypair(&cert->sig_gen_data, keys->pk.ed448_pk,
				     keys->sk.ed448_sk));
	CKINT(asym_set_ed448_keypair(&cert->pub_gen_data, keys->pk.ed448_pk,
				     NULL));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
