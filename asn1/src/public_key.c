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
#include "public_key_dilithium.h"
#include "public_key_dilithium_ed25519.h"
#include "public_key_sphincs.h"
#include "ret_checkers.h"
#include "x509_algorithm_mapper.h"

/*
 * Zeroize a public key signature.
 */
void public_key_signature_clear(struct lc_public_key_signature *sig)
{
	if (!sig)
		return;

	lc_memset_secure(sig, 0, sizeof(struct lc_public_key_signature));
}

/*
 * Zeroize a public key algorithm key.
 */
void public_key_clear(struct lc_public_key *key)
{
	if (!key)
		return;

	lc_memset_secure(key, 0, sizeof(struct lc_public_key));
}

/*
 * Verify a signature using a public key.
 */
int public_key_verify_signature(const struct lc_public_key *pkey,
				const struct lc_public_key_signature *sig)
{
	int ret;

	printf_debug("==>%s()\n", __func__);

	CKNULL(pkey, -EFAULT);
	CKNULL(sig, -EFAULT);
	if (!sig->s)
		return -EFAULT;

	/*
	 * If the signature specifies a public key algorithm, it *must* match
	 * the key's actual public key algorithm.
	 */
	if (sig->pkey_algo > LC_SIG_UNKNOWN &&
	    (pkey->pkey_algo != sig->pkey_algo))
		return -EKEYREJECTED;

	/*
	 * Check that the used hashing algorithm is of sufficient size.
	 * But that check is only needed if we received a hash algorithm.
	 */
	if (sig->hash_algo)
		CKINT(lc_x509_sig_check_hash(pkey->pkey_algo, sig->hash_algo));

	switch (pkey->pkey_algo) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(public_key_verify_signature_dilithium(pkey, sig));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_verify_signature_dilithium_ed25519(pkey, sig));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT(public_key_verify_signature_sphincs(pkey, sig, 1));
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(public_key_verify_signature_sphincs(pkey, sig, 0));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
		printf_debug("Unimplemented asymmetric algorithm %u\n",
			     pkey->pkey_algo);
		fallthrough;
	default:
		/* Unknown public key algorithm */
		ret = -ENOPKG;
	}

out:
	printf_debug("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * Generate a signature using a secret key.
 */
int public_key_generate_signature(const struct lc_x509_generate_data *gen_data,
				  const struct lc_public_key_signature *sig,
				  uint8_t *sig_data, size_t *available_len)
{
	int ret;

	printf_debug("==>%s()\n", __func__);

	CKNULL(gen_data, -EFAULT);
	CKNULL(sig, -EFAULT);
	CKNULL(sig_data, -EFAULT);
	CKNULL(available_len, -EFAULT);

	switch (gen_data->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(public_key_generate_signature_dilithium(
			gen_data, sig, sig_data, available_len));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_generate_signature_dilithium_ed25519(
			gen_data, sig, sig_data, available_len));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT(public_key_generate_signature_sphincs(
			gen_data, sig, sig_data, available_len, 1));
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(public_key_generate_signature_sphincs(
			gen_data, sig, sig_data, available_len, 0));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
		printf_debug("Unimplemented asymmetric algorithm %u\n",
			     gen_data->sig_type);
		fallthrough;
	default:
		/* Unknown public key algorithm */
		ret = -ENOPKG;
	}

out:
	printf_debug("<==%s() = %d\n", __func__, ret);
	return ret;
}
