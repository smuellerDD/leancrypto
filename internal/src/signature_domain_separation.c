/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "signature_domain_separation.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

/* RFC4055 2.16.840.1.101.3.4.2.1 */
LC_FIPS_RODATA_SECTION
static const uint8_t sha256_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x01 };
/* RFC4055 2.16.840.1.101.3.4.2.2 */
LC_FIPS_RODATA_SECTION
static const uint8_t sha384_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x02 };
/* RFC4055 2.16.840.1.101.3.4.2.3 */
LC_FIPS_RODATA_SECTION
static const uint8_t sha512_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x03 };

/*
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
 */
LC_FIPS_RODATA_SECTION
static const uint8_t sha3_256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
};
LC_FIPS_RODATA_SECTION
static const uint8_t sha3_384_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
};
LC_FIPS_RODATA_SECTION
static const uint8_t sha3_512_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
LC_FIPS_RODATA_SECTION
static const uint8_t shake128_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
LC_FIPS_RODATA_SECTION
static const uint8_t shake256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C
};

/*
 * OIDs
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
 */
LC_FIPS_RODATA_SECTION
const uint8_t lc_x509_composite_sig_prefix[] = {
	0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
	0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35
};

/* COMPSIG-MLDSA65-ECDSA-P256-SHA512 */
LC_FIPS_RODATA_SECTION
static const uint8_t lc_x509_test_label[] = {
	0x43, 0x4F, 0x4D, 0x50, 0x53, 0x49, 0x47, 0x2D, 0x4D, 0x4C, 0x44,
	0x53, 0x41, 0x36, 0x35, 0x2D, 0x45, 0x43, 0x44, 0x53, 0x41, 0x2D,
	0x50, 0x32, 0x35, 0x36, 0x2D, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32
};

/* COMPSIG-MLDSA44-Ed25519-SHA512 */
LC_FIPS_RODATA_SECTION
static const uint8_t lc_x509_mldsa44_ed25519_sha512_label[] = {
	0x43, 0x4F, 0x4D, 0x50, 0x53, 0x49, 0x47, 0x2D, 0x4D, 0x4C,
	0x44, 0x53, 0x41, 0x34, 0x34, 0x2D, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x2D, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32
};

/* COMPSIG-MLDSA65-Ed25519-SHA512 */
LC_FIPS_RODATA_SECTION
static const uint8_t lc_x509_mldsa65_ed25519_sha512_label[] = {
	0x43, 0x4F, 0x4D, 0x50, 0x53, 0x49, 0x47, 0x2D, 0x4D, 0x4C,
	0x44, 0x53, 0x41, 0x36, 0x35, 0x2D, 0x45, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x2D, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32
};

/* COMPSIG-MLDSA87-Ed448-SHAKE256 */
LC_FIPS_RODATA_SECTION
static const uint8_t lc_x509_mldsa87_ed448_sha512_label[] = {
	0x43, 0x4F, 0x4D, 0x50, 0x53, 0x49, 0x47, 0x2D, 0x4D, 0x4C,
	0x44, 0x53, 0x41, 0x38, 0x37, 0x2D, 0x45, 0x64, 0x34, 0x34,
	0x38, 0x2D, 0x53, 0x48, 0x41, 0x4B, 0x45, 0x32, 0x35, 0x36
};

int signature_ph_oids(struct lc_hash_ctx *hash_ctx,
		      const struct lc_hash *signature_prehash_type, size_t mlen,
		      uint8_t nist_category)
{
	/* If no hash is supplied, we have no HashML-DSA */
	if (!signature_prehash_type)
		return 0;

	/*
	 * The signature init/update/final operation will not work with the
	 * check of mlen, as only when _final is invoked, the message length
	 * is known.
	 *
	 * As defined in FIPS 204, section 5.4 requires
	 * "... the digest that is signed needs to be generated using an
	 * approved hash function or XOF (e.g., from FIPS 180 or FIPS 202) that
	 * provides at least λ bits of classical security strength against both
	 * collision and second preimage attacks ... Obtaining at least λ bits
	 * of classical security strength against collision attacks requires
	 * that the digest to be signed be at least 2λ bits in length."
	 * This requirement implies in the following definitions.
	 */
	(void)mlen;

	switch (nist_category) {
	case 1:
#ifdef LC_SHA2_256
		if (signature_prehash_type == lc_sha256) {
			// if (mlen != LC_SHA256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha256_oid_der,
				       sizeof(sha256_oid_der));
			return 0;
		}
#endif
#ifdef LC_SHA3
		if (signature_prehash_type == lc_sha3_256) {
			// if (mlen != LC_SHA3_256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_256_oid_der,
				       sizeof(sha3_256_oid_der));
			return 0;
		}
		if (signature_prehash_type == lc_shake128) {
			/* FIPS 204 section 5.4.1 */
			// if (mlen != 32)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, shake128_oid_der,
				       sizeof(shake128_oid_der));
			return 0;
		}
#endif
		/* FALLTHROUGH - Dilithium44 allows the following, too */
		fallthrough;
	case 3:
#ifdef LC_SHA3
		if (signature_prehash_type == lc_sha3_384) {
			// if (mlen != LC_SHA3_384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_384_oid_der,
				       sizeof(sha3_384_oid_der));
			return 0;
		}
#endif
#ifdef LC_SHA2_512
		if (signature_prehash_type == lc_sha384) {
			// if (mlen != LC_SHA384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha384_oid_der,
				       sizeof(sha384_oid_der));
			return 0;
		}
#endif
		/* FALLTHROUGH - Dilithium[44|65] allows the following, too  */
		fallthrough;
	case 5:
#ifdef LC_SHA2_512
		if (signature_prehash_type == lc_sha512) {
			// if (mlen != LC_SHA512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha512_oid_der,
				       sizeof(sha512_oid_der));
			return 0;
		}
#endif
#ifdef LC_SHA3
		if (signature_prehash_type == lc_sha3_512) {
			// if (mlen != LC_SHA3_512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_512_oid_der,
				       sizeof(sha3_512_oid_der));
			return 0;
		} else if (signature_prehash_type == lc_shake256) {
			/* FIPS 204 section 5.4.1 */
			/*
			 * TODO: mlen must be >= 64 to comply with the
			 * aforementioned requirement - unfortunately we can
			 * only check mlen at the end of the signature
			 * operation - shall this be implemented?
			 */
			// if (mlen != 64)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, shake256_oid_der,
				       sizeof(shake256_oid_der));
			return 0;
		}
#endif
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int composite_signature_set_label(const uint8_t **domain,
					 size_t *domainlen,
					 uint8_t nist_category)
{
	/* Set Domain */
	switch (nist_category) {
	case 0:
		*domain = lc_x509_test_label;
		*domainlen = sizeof(lc_x509_test_label);
		break;
	case 1:
		*domain = lc_x509_mldsa44_ed25519_sha512_label;
		*domainlen = sizeof(lc_x509_mldsa44_ed25519_sha512_label);
		break;
	case 3:
		*domain = lc_x509_mldsa65_ed25519_sha512_label;
		*domainlen = sizeof(lc_x509_mldsa65_ed25519_sha512_label);
		break;
	case 5:
		*domain = lc_x509_mldsa87_ed448_sha512_label;
		*domainlen = sizeof(lc_x509_mldsa87_ed448_sha512_label);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int composite_signature_domain_separation(struct lc_hash_ctx *hash_ctx,
					  const uint8_t *userctx,
					  size_t userctxlen,
					  uint8_t nist_category)
{
	const uint8_t *label;
	size_t labellen;
	uint8_t userctxlen_small = (uint8_t)userctxlen;
	int ret;

	CKINT(composite_signature_set_label(&label, &labellen, nist_category));

	/*
	 * M' = Prefix || Label || len(ctx) || ctx || PH (M)
	 *
	 * where PH(M) is to be set by caller
	 *
	 * See for details: https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
	 */
	lc_hash_update(hash_ctx, lc_x509_composite_sig_prefix,
		       sizeof(lc_x509_composite_sig_prefix));
	lc_hash_update(hash_ctx, label, labellen);
	lc_hash_update(hash_ctx, &userctxlen_small, sizeof(userctxlen_small));
	lc_hash_update(hash_ctx, userctx, userctxlen);

out:
	return ret;
}

/* FIPS 204 pre-hash ML-DSA domain separation, but without original message */
static int standalone_signature_domain_separation(
	struct lc_hash_ctx *hash_ctx,
	const struct lc_hash *signature_prehash_type, const uint8_t *userctx,
	size_t userctxlen, size_t mlen, uint8_t nist_category)
{
	int ret;
	uint8_t domainseparation[2];

	domainseparation[0] = signature_prehash_type ? 1 : 0;
	domainseparation[1] = (uint8_t)userctxlen;

	lc_hash_update(hash_ctx, domainseparation, sizeof(domainseparation));
	lc_hash_update(hash_ctx, userctx, userctxlen);

	CKINT(signature_ph_oids(hash_ctx, signature_prehash_type, mlen,
				nist_category));

out:
	return ret;
}

/*
 * Domain separation as required by:
 *
 * FIPS 204 pre-hash ML-DSA: composite is 0
 * Composite ML-DSA draft 5: composite is set
 */
int signature_domain_separation(struct lc_hash_ctx *hash_ctx,
				unsigned int ml_dsa_internal,
				const struct lc_hash *signature_prehash_type,
				const uint8_t *userctx, size_t userctxlen,
				const uint8_t *m, size_t mlen,
				uint8_t composite, uint8_t nist_category)
{
	int ret = 0;

	/* The internal operation skips the domain separation code */
	if (ml_dsa_internal)
		goto out;

	if (userctxlen > 255)
		return -EINVAL;

	/* If Composite ML-DSA is requested, use domain as userctx */
	if (composite) {
		const uint8_t *label;
		size_t labellen;

		CKINT(composite_signature_set_label(&label, &labellen,
						    nist_category));

		/* Add the composite signature label as context */
		CKINT(composite_signature_domain_separation(
			hash_ctx, userctx, userctxlen, nist_category));
	} else {
		CKINT(standalone_signature_domain_separation(
			hash_ctx, signature_prehash_type, userctx, userctxlen,
			mlen, nist_category));
	}

out:
	lc_hash_update(hash_ctx, m, mlen);
	return ret;
}
