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

#include "dilithium_domain_separation.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

/* RFC4055 2.16.840.1.101.3.4.2.1 */
static const uint8_t sha256_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					  0x65, 0x03, 0x04, 0x02, 0x01 };
/* RFC4055 2.16.840.1.101.3.4.2.2 */
static const uint8_t sha384_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					  0x65, 0x03, 0x04, 0x02, 0x02 };
/* RFC4055 2.16.840.1.101.3.4.2.3 */
static const uint8_t sha512_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					  0x65, 0x03, 0x04, 0x02, 0x03 };

/*
 *https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
 */
static const uint8_t sha3_256_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					    0x65, 0x03, 0x04, 0x02, 0x08 };
static const uint8_t sha3_384_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					    0x65, 0x03, 0x04, 0x02, 0x09 };
static const uint8_t sha3_512_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					    0x65, 0x03, 0x04, 0x02, 0x0a };

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake128_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					    0x65, 0x03, 0x04, 0x02, 0x0B };

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake256_oid_der[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
					    0x65, 0x03, 0x04, 0x02, 0x0C };

static int dilithium_ph_oids(struct lc_dilithium_ctx *ctx, size_t mlen,
			     unsigned int dilithium_mode)
{
	struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;

	/* If no hash is supplied, we have no HashML-DSA */
	if (!ctx->dilithium_prehash_type)
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

	switch (dilithium_mode) {
	case 2:
		if (ctx->dilithium_prehash_type == lc_sha256) {
			// if (mlen != LC_SHA256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha256_oid_der,
				       sizeof(sha256_oid_der));
			return 0;
		} else if (ctx->dilithium_prehash_type == lc_sha3_256) {
			// if (mlen != LC_SHA3_256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_256_oid_der,
				       sizeof(sha3_256_oid_der));
			return 0;
		} else if (ctx->dilithium_prehash_type == lc_shake128) {
			/* FIPS 204 section 5.4.1 */
			// if (mlen != 32)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, shake128_oid_der,
				       sizeof(shake128_oid_der));
			return 0;
		}
		/* FALLTHROUGH - Dilithium44 allows the following, too */
		fallthrough;
	case 3:
		if (ctx->dilithium_prehash_type == lc_sha3_384) {
			// if (mlen != LC_SHA3_384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_384_oid_der,
				       sizeof(sha3_384_oid_der));
			return 0;
		}
		if (ctx->dilithium_prehash_type == lc_sha384) {
			// if (mlen != LC_SHA384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha384_oid_der,
				       sizeof(sha384_oid_der));
			return 0;
		}
		/* FALLTHROUGH - Dilithium[44|65] allows the following, too  */
		fallthrough;
	case 5:
		if (ctx->dilithium_prehash_type == lc_sha512) {
			// if (mlen != LC_SHA512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha512_oid_der,
				       sizeof(sha512_oid_der));
			return 0;
		} else if (ctx->dilithium_prehash_type == lc_sha3_512) {
			// if (mlen != LC_SHA3_512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			lc_hash_update(hash_ctx, sha3_512_oid_der,
				       sizeof(sha3_512_oid_der));
			return 0;
		} else if (ctx->dilithium_prehash_type == lc_shake256) {
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
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

int dilithium_domain_separation(struct lc_dilithium_ctx *ctx, const uint8_t *m,
				size_t mlen, unsigned int dilithium_mode)
{
	uint8_t domainseparation[2];
	struct lc_hash_ctx *hash_ctx;
	int ret = 0;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* The internal operation skips the domain separation code */
	if (ctx->ml_dsa_internal)
		goto out;

	if (ctx->userctxlen > 255)
		return -EINVAL;

	domainseparation[0] = ctx->dilithium_prehash_type ? 1 : 0;
	domainseparation[1] = (uint8_t)ctx->userctxlen;

	lc_hash_update(hash_ctx, domainseparation, sizeof(domainseparation));
	lc_hash_update(hash_ctx, ctx->userctx, ctx->userctxlen);

	CKINT(dilithium_ph_oids(ctx, mlen, dilithium_mode));

out:
	lc_hash_update(hash_ctx, m, mlen);
	return ret;
}
