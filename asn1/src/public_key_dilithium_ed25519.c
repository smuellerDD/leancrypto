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
#include "public_key_dilithium_ed25519.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"

int public_key_verify_signature_dilithium_ed25519(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	struct lc_dilithium_ed25519_pk dilithium_pk;
	struct lc_dilithium_ed25519_sig dilithium_sig;
	const struct lc_hash *hash_algo;
	int ret;
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);

	/* A signature verification does not work with a private key */
	if (pkey->key_is_private)
		return -EKEYREJECTED;

	if (sig->s_size < LC_ED25519_PUBLICKEYBYTES)
		return -EINVAL;

	/* PK is defined as Dilithium PK || ED25519 PK */
	CKINT(lc_dilithium_ed25519_pk_load(
		&dilithium_pk, pkey->key,
		pkey->keylen - LC_ED25519_PUBLICKEYBYTES,
		pkey->key + LC_ED25519_PUBLICKEYBYTES,
		LC_ED25519_PUBLICKEYBYTES));
	CKINT(lc_dilithium_ed25519_sig_load(
		&dilithium_sig, sig->s, sig->s_size - LC_ED25519_SIGBYTES,
		sig->s + LC_ED25519_SIGBYTES, LC_ED25519_SIGBYTES));

	/*
	 * Select hash-based signature if there was a hash
	 */
	if (sig->digest_size) {
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));
		CKNULL(hash_algo, -EOPNOTSUPP);
		lc_dilithium_ed25519_ctx_hash(ctx, hash_algo);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_ed25519_verify_ctx(
			&dilithium_sig, ctx, sig->digest, sig->digest_size,
			&dilithium_pk));
	} else {
		CKNULL(sig->raw_data, -EOPNOTSUPP);

		/*
		 * Verify the signature
		 */
		CKINT(lc_dilithium_ed25519_verify_ctx(
			&dilithium_sig, ctx, sig->raw_data, sig->raw_data_len,
			&dilithium_pk));
	}

out:
	lc_dilithium_ed25519_ctx_zero(ctx);
	lc_memset_secure(&dilithium_pk, 0, sizeof(dilithium_pk));
	lc_memset_secure(&dilithium_sig, 0, sizeof(dilithium_sig));
	return ret;
}
