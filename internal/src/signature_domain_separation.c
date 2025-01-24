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

#include "signature_domain_separation.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

/* RFC4055 2.16.840.1.101.3.4.2.1 */
static const uint8_t sha256_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x01 };
/* RFC4055 2.16.840.1.101.3.4.2.2 */
static const uint8_t sha384_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x02 };
/* RFC4055 2.16.840.1.101.3.4.2.3 */
static const uint8_t sha512_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x03 };

/*
 *https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
 */
static const uint8_t sha3_256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
};
static const uint8_t sha3_384_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
};
static const uint8_t sha3_512_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake128_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C
};

/* OIDs from https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html */
/* id-HashMLDSA44-Ed25519-SHA512 */
static const uint8_t mldsa44_ed25519_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x17
};

/* id-HashMLDSA65-Ed25519-SHA512 */
static const uint8_t mldsa65_ed25519_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1E
};

/* id-HashMLDSA87-Ed448-SHA512 */
static const uint8_t mldsa87_ed448_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x21
};

int signature_ph_oids(struct lc_hash_ctx *hash_ctx,
		      const struct lc_hash *signature_prehash_type, size_t mlen,
		      unsigned int nist_category)
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

static int composite_signature_set_domain(struct lc_hash_ctx *hash_ctx,
					  unsigned int nist_category)
{
	/* Set Domain */
	switch (nist_category) {
	case 1:
		lc_hash_update(hash_ctx, mldsa44_ed25519_sha512_oid_der,
			       sizeof(mldsa44_ed25519_sha512_oid_der));
		break;
	case 3:
		lc_hash_update(hash_ctx, mldsa65_ed25519_sha512_oid_der,
			       sizeof(mldsa65_ed25519_sha512_oid_der));
		break;
	case 5:
		/* See above for the rationale */
		lc_hash_update(hash_ctx, mldsa87_ed448_sha512_oid_der,
			       sizeof(mldsa87_ed448_sha512_oid_der));
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int composite_signature_domain_separation(struct lc_hash_ctx *hash_ctx,
					  const uint8_t *userctx,
					  size_t userctxlen,
					  unsigned int nist_category)
{
	int ret;

	if (userctxlen > 255)
		return -EINVAL;

	/*
	 * Create M'
	 */
	CKINT(composite_signature_set_domain(hash_ctx, nist_category));

	/* Set len(ctx) */
	lc_hash_update(hash_ctx, (uint8_t *)&userctxlen, 1);

	/* Set ctx */
	lc_hash_update(hash_ctx, userctx, userctxlen);

out:
	return ret;
}

int signature_domain_separation(struct lc_hash_ctx *hash_ctx,
				unsigned int ml_dsa_internal,
				const struct lc_hash *signature_prehash_type,
				const uint8_t *userctx, size_t userctxlen,
				const uint8_t *m, size_t mlen,
				unsigned int nist_category,
				unsigned int composte_signature)
{
	uint8_t domainseparation[2];
	int ret = 0;

	/* The internal operation skips the domain separation code */
	if (ml_dsa_internal)
		goto out;

	if (userctxlen > 255)
		return -EINVAL;

	domainseparation[0] = signature_prehash_type ? 1 : 0;

	/* If Composite ML-DSA is requested, use domain as userctx */
	if (composte_signature) {
		/* All domains have the same length */
		domainseparation[1] =
			(uint8_t)sizeof(mldsa44_ed25519_sha512_oid_der);

		lc_hash_update(hash_ctx, domainseparation,
			       sizeof(domainseparation));
		CKINT(composite_signature_set_domain(hash_ctx, nist_category));

	} else {
		domainseparation[1] = (uint8_t)userctxlen;

		lc_hash_update(hash_ctx, domainseparation,
			       sizeof(domainseparation));
		lc_hash_update(hash_ctx, userctx, userctxlen);
	}

	CKINT(signature_ph_oids(hash_ctx, signature_prehash_type, mlen,
				nist_category));

	/* If Composite ML-DSA is requested, apply domain separation */
	if (composte_signature) {
		ret = composite_signature_domain_separation(
			hash_ctx, userctx, userctxlen, nist_category);
	}

out:
	lc_hash_update(hash_ctx, m, mlen);
	return ret;
}
