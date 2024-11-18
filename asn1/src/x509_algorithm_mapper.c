/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "asn1_debug.h"
#include "helper.h"
#include "ret_checkers.h"
#include "lc_sha256.h"
#include "lc_x509_generator.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"

struct lc_x509_algorithms {
	enum OID oid;
	const char *name_algo;
	size_t namelen;
	enum lc_sig_types pkey_algo;
};

static struct lc_x509_algorithms x509_algo_table[] = {
	{ .oid = OID_id_MLDSA44,
	  .name_algo = "ML-DSA44",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_44 },
	{ .oid = OID_id_MLDSA65,
	  .name_algo = "ML-DSA65",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_65 },
	{ .oid = OID_id_MLDSA87,
	  .name_algo = "ML-DSA87",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_87 },
	{ .oid = OID_id_SLHDSA_SHAKE_128F,
	  .name_algo = "SLH-DSA-SHAKE-128F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_128F },
	{ .oid = OID_id_SLHDSA_SHAKE_128S,
	  .name_algo = "SLH-DSA-SHAKE-128S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_128S },
	{ .oid = OID_id_SLHDSA_SHAKE_192F,
	  .name_algo = "SLH-DSA-SHAKE-192F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_192F },
	{ .oid = OID_id_SLHDSA_SHAKE_192S,
	  .name_algo = "SLH-DSA-SHAKE-192S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_192S },
	{ .oid = OID_id_SLHDSA_SHAKE_256F,
	  .name_algo = "SLH-DSA-SHAKE-256F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_256F },
	{ .oid = OID_id_SLHDSA_SHAKE_256S,
	  .name_algo = "SLH-DSA-SHAKE-256S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_256S },

	{ .oid = OID_id_rsassa_pkcs1_v1_5_with_sha3_256,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA3-256",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },
	{ .oid = OID_id_rsassa_pkcs1_v1_5_with_sha3_384,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA3-384",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },
	{ .oid = OID_id_rsassa_pkcs1_v1_5_with_sha3_512,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA3-512",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },

	{ .oid = OID_id_ecdsa_with_sha3_256,
	  .name_algo = "ECDSA-X963-SHA3-256",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },
	{ .oid = OID_id_ecdsa_with_sha3_384,
	  .name_algo = "ECDSA-X963-SHA3-384",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },
	{ .oid = OID_id_ecdsa_with_sha3_512,
	  .name_algo = "ECDSA-X963-SHA3-512",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },

	{ .oid = OID_sha256WithRSAEncryption,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA2-256",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },
	{ .oid = OID_id_ecdsa_with_sha256,
	  .name_algo = "ECDSA-X963-SHA2-256",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },

	/*
	 * See https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-02.html
	 * section 7 (table, column pre-hash).
	 */
	{ .oid = OID_id_MLDSA44_Ed25519,
	  .name_algo = "ML-DSA44-ED25519",
	  .namelen = 16,
	  .pkey_algo = LC_SIG_DILITHIUM_44_ED25519 },
	{ .oid = OID_id_MLDSA65_Ed25519,
	  .name_algo = "ML-DSA65-ED25519",
	  .namelen = 16,
	  .pkey_algo = LC_SIG_DILITHIUM_65_ED25519 },
	{ .oid = OID_id_MLDSA87_Ed448,
	  .name_algo = "ML-DSA44-ED448",
	  .namelen = 14,
	  .pkey_algo = LC_SIG_DILITHIUM_87_ED448 },
	{ .oid = OID_sha384WithRSAEncryption,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA2-384",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },
	{ .oid = OID_sha512WithRSAEncryption,
	  .name_algo = "RSASSA-PKCS1-v1.5-SHA2-512",
	  .namelen = 26,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },

	{ .oid = OID_id_ecdsa_with_sha384,
	  .name_algo = "ECDSA-X963-SHA2-384",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },
	{ .oid = OID_id_ecdsa_with_sha512,
	  .name_algo = "ECDSA-X963-SHA2-512",
	  .namelen = 19,
	  .pkey_algo = LC_SIG_ECDSA_X963 },

	{ .oid = OID_rsaEncryption,
	  .name_algo = "RSASSA-PKCS1-v1.5",
	  .namelen = 17,
	  .pkey_algo = LC_SIG_RSA_PKCS1 },
};

LC_INTERFACE_FUNCTION(int, lc_x509_pkey_name_to_algorithm, const char *name,
		      enum lc_sig_types *pkey_algo)
{
	size_t namelen;
	unsigned int i;
	int ret = 0;

	CKNULL(name, -EINVAL);
	CKNULL(pkey_algo, -EINVAL);

	namelen = strlen(name);

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (namelen == x509_algo_table[i].namelen &&
		    !strncmp(name, x509_algo_table[i].name_algo, namelen)) {
			*pkey_algo = x509_algo_table[i].pkey_algo;
			goto out;
		}
	}

	printf("Allowed Public Key Algorithms:\n");
	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++)
		printf(" %s\n", x509_algo_table[i].name_algo);

	return -ENOPKG;

out:
	return ret;
}

int lc_x509_sig_type_to_oid(enum lc_sig_types pkey_algo, enum OID *oid)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (pkey_algo == x509_algo_table[i].pkey_algo) {
			*oid = x509_algo_table[i].oid;
			return 0;
		}
	}
	printf_debug("Public Key algo %u not found\n", pkey_algo);

	return -ENOPKG;
}

LC_INTERFACE_FUNCTION(int, lc_x509_sig_type_to_hash,
		      enum lc_sig_types pkey_algo,
		      const struct lc_hash **hash_algo)
{
	switch (pkey_algo) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		/* They are using the builtin hash type */
		*hash_algo = NULL;
		return 0;
#ifdef LC_SHA3
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_256S:
		/* They are using the builtin hash type */
		*hash_algo = NULL;
		return 0;
#else
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_256S:
		return -ENOPKG;
#endif
#ifdef LC_SHA2_512
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
	case LC_SIG_DILITHIUM_87_ED448:
		/* They are using the builtin hash type */
		*hash_algo = NULL;
		return 0;
#else
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
	case LC_SIG_DILITHIUM_87_ED448:
		return -ENOPKG;
#endif
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
	default:
#ifdef LC_PKCS7_DEBUG
#warning                                                                       \
	"LC_PKCS7_DEBUG enabled - code MUST ONLY BE USED FOR TESTING - NEVER IN PRODUCTION!"
		*hash_algo = lc_sha512;
		return 0;
#else
		return -ENOPKG;
#endif
	}
}

int lc_x509_hash_to_oid(const struct lc_hash *hash_algo, enum OID *oid)
{
	if (hash_algo == lc_sha256)
		*oid = OID_sha256;
	else if (hash_algo == lc_sha384)
		*oid = OID_sha384;
	else if (hash_algo == lc_sha512)
		*oid = OID_sha512;
	else if (hash_algo == lc_sha3_256)
		*oid = OID_sha3_256;
	else if (hash_algo == lc_sha3_384)
		*oid = OID_sha3_384;
	else if (hash_algo == lc_sha3_512)
		*oid = OID_sha3_512;
	else
		*oid = OID__NR;

	return 0;
}

int lc_x509_oid_to_sig_type(enum OID oid, enum lc_sig_types *pkey_algo)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (oid == x509_algo_table[i].oid) {
			*pkey_algo = x509_algo_table[i].pkey_algo;
			return 0;
		}
	}

	printf_debug("OID %u not found\n", oid);

	return -ENOPKG;
}

LC_INTERFACE_FUNCTION(const char, *lc_x509_sig_type_to_name,
		      enum lc_sig_types pkey_algo)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (pkey_algo == x509_algo_table[i].pkey_algo) {
			return x509_algo_table[i].name_algo;
		}
	}

	return "<not found>";
}

const char *lc_x509_oid_to_name(enum OID oid)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (oid == x509_algo_table[i].oid) {
			return x509_algo_table[i].name_algo;
		}
	}

	return "<not found>";
}
