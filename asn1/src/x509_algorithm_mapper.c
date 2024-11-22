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
	enum OID std_hash;
};

static struct lc_x509_algorithms x509_algo_table[] = {
	{ .oid = OID_id_MLDSA44,
	  .name_algo = "ML-DSA44",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_44,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_MLDSA65,
	  .name_algo = "ML-DSA65",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_65,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_MLDSA87,
	  .name_algo = "ML-DSA87",
	  .namelen = 8,
	  .pkey_algo = LC_SIG_DILITHIUM_87,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_128F,
	  .name_algo = "SLH-DSA-SHAKE-128F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_128F,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_128S,
	  .name_algo = "SLH-DSA-SHAKE-128S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_128S,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_192F,
	  .name_algo = "SLH-DSA-SHAKE-192F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_192F,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_192S,
	  .name_algo = "SLH-DSA-SHAKE-192S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_192S,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_256F,
	  .name_algo = "SLH-DSA-SHAKE-256F",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_256F,
	  .std_hash = OID_shake256 },
	{ .oid = OID_id_SLHDSA_SHAKE_256S,
	  .name_algo = "SLH-DSA-SHAKE-256S",
	  .namelen = 18,
	  .pkey_algo = LC_SIG_SPINCS_SHAKE_256S,
	  .std_hash = OID_shake256 },

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
	  .pkey_algo = LC_SIG_DILITHIUM_44_ED25519,
	  .std_hash = OID_sha3_512 },
	{ .oid = OID_id_MLDSA65_Ed25519,
	  .name_algo = "ML-DSA65-ED25519",
	  .namelen = 16,
	  .pkey_algo = LC_SIG_DILITHIUM_65_ED25519,
	  .std_hash = OID_sha3_512 },
	{ .oid = OID_id_MLDSA87_Ed448,
	  .name_algo = "ML-DSA44-ED448",
	  .namelen = 14,
	  .pkey_algo = LC_SIG_DILITHIUM_87_ED448,
	  .std_hash = OID_sha3_512 },

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
	unsigned int i;
	enum OID hash_oid = OID__NR;

	for (i = 0; i < ARRAY_SIZE(x509_algo_table); i++) {
		if (pkey_algo == x509_algo_table[i].pkey_algo) {
			hash_oid = x509_algo_table[i].std_hash;
			break;
		}
	}

	if (hash_oid == OID__NR) {
		printf_debug("Public Key algo %u not found\n", pkey_algo);

		return -ENOPKG;
	}

	return lc_x509_oid_to_hash(hash_oid, hash_algo);
}

int lc_x509_sig_check_hash(enum lc_sig_types pkey_algo,
			   const struct lc_hash *hash_algo)
{
	unsigned int found = 0;

	if (!hash_algo)
		return -ENOPKG;

	switch (pkey_algo) {
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_DILITHIUM_44:
#ifdef LC_SHA2_256
		if (hash_algo == lc_sha256) {
			found = 1;
			break;
		} else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_256) {
			found = 1;
			break;
		} else if (hash_algo == lc_shake128) {
			found = 1;
			break;
		}
#endif
		fallthrough;
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_DILITHIUM_65:
#ifdef LC_SHA2_512
		if (hash_algo == lc_sha384) {
			found = 1;
			break;
		} else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_384) {
			found = 1;
			break;
		}
#endif
		fallthrough;
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_DILITHIUM_87:
#ifdef LC_SHA2_512
		if (hash_algo == lc_sha512) {
			found = 1;
			break;
		} else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_512) {
			found = 1;
			break;
		} else if (hash_algo == lc_shake256) {
			found = 1;
			break;
		}
#endif
		break;

	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
#ifdef LC_SHA2_512
		if (hash_algo == lc_sha512) {
			found = 1;
			break;
		} else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_512) {
			found = 1;
			break;
		} else if (hash_algo == lc_shake256) {
			found = 1;
			break;
		}
#endif
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
		printf_debug("Unimplemented asymmetric algorithm %u\n",
			     pkey_algo);
		fallthrough;
	default:
		/* Unknown public key algorithm */
		return -ENOPKG;
	}

	if (found)
		return 0;

	printf_debug("Message digest for signature algorithm too weak\n");
	return -ENOPKG;
}


LC_INTERFACE_FUNCTION(int, lc_x509_name_to_hash, const char *hash_name,
		      const struct lc_hash **hash_algo)
{
	size_t namelen;

	if (!hash_name)
		return -EINVAL;

	namelen = strlen(hash_name);

#ifdef LC_SHA2_256
	if (namelen == 8 && !strncmp(hash_name, "SHA2-256", namelen))
		*hash_algo = lc_sha256;
	else
#endif
#ifdef LC_SHA2_512
		if (namelen == 8 && !strncmp(hash_name, "SHA2-384", namelen))
		*hash_algo = lc_sha384;
	else if (namelen == 8 && !strncmp(hash_name, "SHA2-512", namelen))
		*hash_algo = lc_sha512;
	else
#endif
#ifdef LC_SHA3
		if (namelen == 8 && !strncmp(hash_name, "SHA3-256", namelen))
		*hash_algo = lc_sha3_256;
	else if (namelen == 8 && !strncmp(hash_name, "SHA3-384", namelen))
		*hash_algo = lc_sha3_384;
	else if (namelen == 8 && !strncmp(hash_name, "SHA3-512", namelen))
		*hash_algo = lc_sha3_512;
	else if (namelen == 8 && !strncmp(hash_name, "SHAKE128", namelen))
		*hash_algo = lc_shake128;
	else if (namelen == 8 && !strncmp(hash_name, "SHAKE256", namelen))
		*hash_algo = lc_shake256;
	else
#endif
	{
		printf("Allowed message digest algorithms: ");
#ifdef LC_SHA2_256
		printf("SHA2-256 ");
#endif
#ifdef LC_SHA2_512
		printf("SHA2-384 SHA2-512 ");
#endif
#ifdef LC_SHA3
		printf("SHA3-256 SHA3-384 SHA3-512 SHAKE128 SHAKE256");
#endif
		printf("\n");
		return -EINVAL;
	}

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_x509_hash_to_name,
		      const struct lc_hash *hash_algo, const char **hash_name)
{
#ifdef LC_SHA2_256
	if (hash_algo == lc_sha256)
		*hash_name = "SHA2-256";
	else
#endif
#ifdef LC_SHA2_512
		if (hash_algo == lc_sha384)
		*hash_name = "SHA2-384";
	else if (hash_algo == lc_sha512)
		*hash_name = "SHA2-512";
	else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_256)
		*hash_name = "SHA3-256";
	else if (hash_algo == lc_sha3_384)
		*hash_name = "SHA3-384";
	else if (hash_algo == lc_sha3_512)
		*hash_name = "SHA3-512";
	else if (hash_algo == lc_shake128)
		*hash_name = "SHAKE128";
	else if (hash_algo == lc_shake256)
		*hash_name = "SHAKE256";
	else
#endif
		*hash_name = "<unknown>";

	return 0;
}

int lc_x509_hash_to_oid(const struct lc_hash *hash_algo, enum OID *oid)
{
#ifdef LC_SHA2_256
	if (hash_algo == lc_sha256)
		*oid = OID_sha256;
	else
#endif
#ifdef LC_SHA2_512
		if (hash_algo == lc_sha384)
		*oid = OID_sha384;
	else if (hash_algo == lc_sha512)
		*oid = OID_sha512;
	else
#endif
#ifdef LC_SHA3
		if (hash_algo == lc_sha3_256)
		*oid = OID_sha3_256;
	else if (hash_algo == lc_sha3_384)
		*oid = OID_sha3_384;
	else if (hash_algo == lc_sha3_512)
		*oid = OID_sha3_512;
	else if (hash_algo == lc_shake128)
		*oid = OID_shake128;
	else if (hash_algo == lc_shake256)
		*oid = OID_shake256;
	else
#endif
		*oid = OID__NR;

	return 0;
}

int lc_x509_oid_to_hash(enum OID oid, const struct lc_hash **hash_algo)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (oid) {
#ifdef LC_SHA2_256
	case OID_sha256:
		*hash_algo = lc_sha256;
		break;
#endif
#ifdef LC_SHA2_512
	case OID_sha384:
		*hash_algo = lc_sha384;
		break;
	case OID_sha512:
		*hash_algo = lc_sha512;
		break;
#endif
#ifdef LC_SHA3
	case OID_sha3_256:
		*hash_algo = lc_sha3_256;
		break;
	case OID_sha3_384:
		*hash_algo = lc_sha3_384;
		break;
	case OID_sha3_512:
		*hash_algo = lc_sha3_512;
		break;
	case OID_shake128:
		*hash_algo = lc_shake128;
		break;
	case OID_shake256:
		*hash_algo = lc_shake256;
		break;
#endif
	default:
		printf_debug("Unsupported digest algo: %u\n", oid);
		return -ENOPKG;
	}
#pragma GCC diagnostic pop

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

struct lc_keyusage_names {
	uint16_t keyusage;
	const char *name;
	size_t namelen;
};

static const struct lc_keyusage_names keyusage_names[] = {
	{ .keyusage = LC_KEY_USAGE_CRITICAL, .name = "critical", .namelen = 8 },
	{ .keyusage = LC_KEY_USAGE_DIGITALSIG, .name = "digitalSignature", .namelen = 16 },
	{ .keyusage = LC_KEY_USAGE_CONTENT_COMMITMENT, .name = "contentCommitment", .namelen = 17 },
	{ .keyusage = LC_KEY_USAGE_KEY_ENCIPHERMENT, .name = "keyEncipherment", .namelen = 15 },
	{ .keyusage = LC_KEY_USAGE_DATA_ENCIPHERMENT, .name = "dataEncipherment", .namelen = 16 },
	{ .keyusage = LC_KEY_USAGE_KEYCERTSIGN, .name = "keyCertSign", .namelen = 11 },
	{ .keyusage = LC_KEY_USAGE_CRLSIGN, .name = "cRLSign", .namelen = 7 },
	{ .keyusage = LC_KEY_USAGE_ENCIPHER_ONLY, .name = "encipherOnly", .namelen = 12 },
	{ .keyusage = LC_KEY_USAGE_DECIPHER_ONLY, .name = "decipherOnly", .namelen = 12 }
};

LC_INTERFACE_FUNCTION(int, lc_x509_name_to_keyusage, const char *name,
		      uint16_t *keyusage)
{
	size_t namelen;
	unsigned int i, found = 0;
	int ret = 0;

	CKNULL(name, -EINVAL);
	CKNULL(keyusage, -EINVAL);

	namelen = strlen(name);

	for (i = 0; i < ARRAY_SIZE(keyusage_names); i++) {
		if (namelen == keyusage_names[i].namelen &&
		    !strncmp(name, keyusage_names[i].name, namelen)) {
			*keyusage |= keyusage_names[i].keyusage;
			found = 1;
		}
	}

	if (found)
		goto out;

	printf("Allowed Key Usage flags:\n");
	for (i = 0; i < ARRAY_SIZE(keyusage_names); i++)
		printf(" %s\n", keyusage_names[i].name);

	return -ENOPKG;

out:
	return ret;
}

static const struct lc_keyusage_names eku_names[] = {
	{ .keyusage = LC_KEY_EKU_CRITICAL, .name = "critical", .namelen = 8 },
	{ .keyusage = LC_KEY_EKU_ANY, .name = "anyExtendedKeyUsage", .namelen = 19 },
	{ .keyusage = LC_KEY_EKU_SERVER_AUTH, .name = "ServerAuthentication", .namelen = 20 },
	{ .keyusage = LC_KEY_EKU_CLIENT_AUTH, .name = "ClientAuthentication", .namelen = 20 },
	{ .keyusage = LC_KEY_EKU_CODE_SIGNING, .name = "CodeSigning", .namelen = 11 },
	{ .keyusage = LC_KEY_EKU_EMAIL_PROTECTION, .name = "EmailProtection", .namelen = 15 },
	{ .keyusage = LC_KEY_EKU_TIME_STAMPING, .name = "TImeStamping", .namelen = 12 },
	{ .keyusage = LC_KEY_EKU_OCSP_SIGNING, .name = "OCSPSignign", .namelen = 11 }
};

LC_INTERFACE_FUNCTION(int, lc_x509_name_to_eku, const char *name,
		      uint16_t *eku)
{
	size_t namelen;
	unsigned int i, found = 0;
	int ret = 0;

	CKNULL(name, -EINVAL);
	CKNULL(eku, -EINVAL);

	namelen = strlen(name);

	for (i = 0; i < ARRAY_SIZE(eku_names); i++) {
		if (namelen == eku_names[i].namelen &&
		    !strncmp(name, eku_names[i].name, namelen)) {
			*eku |= eku_names[i].keyusage;
			found = 1;
		}
	}

	if (found)
		goto out;

	printf("Allowed Extended Key Usage flags:\n");
	for (i = 0; i < ARRAY_SIZE(eku_names); i++)
		printf(" %s\n", eku_names[i].name);

	return -ENOPKG;

out:
	return ret;
}
