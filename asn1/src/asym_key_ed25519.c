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

#include "asym_key_ed25519.h"
#include "ed25519_ctx.h"
#include "ext_headers_internal.h"
#include "lc_ed25519.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "pkcs7_internal.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"

int private_key_encode_ed25519(uint8_t *data, size_t *avail_datalen,
			       struct x509_generate_privkey_context *ctx)
{
#ifdef LC_X509_GENERATOR
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t ed25519_sklen;
	uint8_t *ed25519_ptr;
	int ret;

	CKINT(lc_ed25519_sk_ptr(&ed25519_ptr, &ed25519_sklen,
				keys->sk.ed25519_sk));

	/* Only export the secret part of the ED25519 secret key */
	CKINT(lc_x509_concatenate_bit_string(&data, avail_datalen, ed25519_ptr,
					     ed25519_sklen));

	printf_debug("Set composite secret key of size %u\n", ed25519_sklen);

out:
	return ret;
#else
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -EOPNOTSUPP;
#endif
}

int private_key_decode_ed25519(struct lc_x509_key_data *keys,
			       const uint8_t *data, size_t datalen)
{
	struct lc_ed25519_sk *sk = keys->sk.ed25519_sk;
	int ret;

	CKINT(lc_ed25519_sk_load(sk, data, datalen));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

int public_key_decode_ed25519(struct lc_ed25519_pk *ed25519_pk,
			      const uint8_t *data, size_t datalen)
{
	int ret;

	if (datalen != LC_ED25519_PUBLICKEYBYTES)
		return -EINVAL;

	CKINT(lc_ed25519_pk_load(ed25519_pk, data, LC_ED25519_PUBLICKEYBYTES));

	printf_debug("Loaded composite public key of size %zu\n", datalen);

out:
	return ret;
}

static int
public_key_ed25519_get_data(const uint8_t **data_ptr,
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

int public_key_verify_signature_ed25519(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct workspace {
		struct lc_ed25519_pk pk;
		struct lc_ed25519_sig sig;
		struct lc_dilithium_ed25519_ctx sign_ctx;
	};
	const uint8_t *data_ptr;
	size_t data_len;
	int ret, authattrs_tag;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	CKINT(public_key_ed25519_get_data(&data_ptr, &data_len,
					  &authattrs_tag, sig));

	if (sig->s_size != LC_ED25519_SIGBYTES)
		return -EBADMSG;

	CKINT(public_key_decode_ed25519(&ws->pk, pkey->key, pkey->keylen));

	CKINT(lc_ed25519_sig_load(&ws->sig, sig->s, sig->s_size));

	printf_debug("Loaded Ed25519 signature of size %zu\n", sig->s_size);

	if (authattrs_tag) {
		/* Add the authattr tag */
		ws->sign_ctx.msg_prefix = &lc_pkcs7_authattr_tag;
		ws->sign_ctx.msg_prefix_len = sizeof(lc_pkcs7_authattr_tag);
	}

	CKINT(lc_ed25519_verify_ctx(&ws->sig, data_ptr, data_len, &ws->pk,
				    &ws->sign_ctx));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int public_key_generate_signature_ed25519(
	const struct lc_x509_key_data *keys,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
#ifdef LC_X509_GENERATOR
	struct workspace {
		struct lc_ed25519_sig ed25519_sig;
	};
	struct lc_ed25519_sk *ed25519_sk = keys->sk.ed25519_sk;
	size_t ed25519_siglen, data_len;
	const uint8_t *data_ptr;
	uint8_t *ed25519_ptr;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(public_key_ed25519_get_data(&data_ptr, &data_len, NULL, sig));

	/* Sign the signature using Composite-ML-DSA */
	CKINT(lc_ed25519_sign(&ws->ed25519_sig, data_ptr, data_len, ed25519_sk,
			      lc_seeded_rng));

	CKINT(lc_ed25519_sig_ptr(&ed25519_ptr, &ed25519_siglen,
				 &ws->ed25519_sig));

	CKINT(lc_x509_concatenate_bit_string(&sig_data, available_len,
					     ed25519_ptr, ed25519_siglen));

	printf_debug("Set Ed25519 signature of size %zu\n", ed25519_siglen);

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

int asym_set_ed25519_keypair(struct lc_x509_key_data *gen_data,
			     struct lc_ed25519_pk *pk, struct lc_ed25519_sk *sk)
{
	uint8_t *ed25519_pk_ptr;
	size_t ed25519_pk_len;
	int ret = 0;

	CKNULL(gen_data, -EINVAL);

	if (!pk && !sk)
		return -EINVAL;

	if (pk) {
		gen_data->pk.ed25519_pk = pk;

		CKINT(lc_ed25519_pk_ptr(&ed25519_pk_ptr, &ed25519_pk_len, pk));
		CKINT(lc_hash(LC_X509_SKID_DEFAULT_HASH, ed25519_pk_ptr,
			      ed25519_pk_len, gen_data->pk_digest));
	}

	if (sk)
		gen_data->sk.ed25519_sk = sk;

	gen_data->sig_type = LC_SIG_ED25519;

out:
	return ret;
}

int asym_keypair_gen_ed25519(struct lc_x509_certificate *cert,
			     struct lc_x509_key_data *keys)
{
	struct workspace {
		struct lc_ed25519_pk pk_ed25519;
		struct lc_ed25519_sk sk_ed25519;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_ed25519_keypair(&ws->pk_ed25519, &ws->sk_ed25519,
				 lc_seeded_rng));

	CKINT(lc_ed25519_sk_load(keys->sk.ed25519_sk, ws->sk_ed25519.sk,
				 LC_ED25519_SECRETKEYBYTES));
	CKINT(lc_ed25519_pk_load(keys->pk.ed25519_pk, ws->pk_ed25519.pk,
				 LC_ED25519_PUBLICKEYBYTES));

	CKINT(asym_set_ed25519_keypair(&cert->sig_gen_data, keys->pk.ed25519_pk,
				       keys->sk.ed25519_sk));
	CKINT(asym_set_ed25519_keypair(&cert->pub_gen_data, keys->pk.ed25519_pk,
				       NULL));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
