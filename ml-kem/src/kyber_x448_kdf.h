/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_X448_KDF_H
#define KYBER_X448_KDF_H

#include "kyber_type.h"
#include "lc_hash.h"
#include "lc_kmac.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief kyber_double_ss_kdf - KDF to derive arbitrary sized SS from Kyber SS
 *
 *	SS <- KMAC256(K = Kyber-SS || X448-SS,
 *		      X = Kyber-CT || X448-ephemeral-PK,
 *		      L = requested SS length, S = "Kyber X448 KEM SS")
 *
 * This KDF is is consistent with SP800-108 rev 1.
 *
 * This KDF is consistent with SP800-227 section 4.6.2 - albeit this section
 * refers only to SP800-56C, in turn SP800-56C refers to and allows SP800-108.
 *
 * NOTE: SP800-227 section 4.6.2 documents that H(x,y) should not considered
 * immediately apply the concatenation H(x||y) without further considerations.
 * This is due to the concern that lengths of x and y may vary where a simple
 * concatenation with simple paddings may hide differences here. As this is
 * not applicable to this schema since all input data have well-defined and
 * enforced lengths without any padding, this concern is not applicable and
 * thus a concatenation can be applied without additional considerations.
 *
 * According to SP800-227 section 4.6.3, the KDF will uphold the IND-CCA
 * property by integrating the ciphertexts in addition to the shared secrets
 * to the KDF. Section 4.6.3 *recommends* the addition of the encapsulation
 * keys into the KDF as well, but that is not marked as necessary to uphold
 * the IND-CCA property.
 */
static inline void kyber_x448_ss_kdf(uint8_t *ss, size_t ss_len,
				     const struct lc_kyber_x448_ct *ct,
				     const struct lc_kyber_x448_ss *calc_ss)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t kyber_ss_label[] = "Kyber X448 KEM SS";

	/*
	 * NOTE: this only works because struct lc_kyber_x448_ss contains
	 * Kyber SS || X448 SS in memory. Also, lc_kyber_x448_ct contains
	 * Kyber CT || X448 ephemeral PK in memory. If either structure
	 * changes, change this KDF invocation.
	 */
	lc_kmac(lc_cshake256, (uint8_t *)calc_ss, sizeof(struct lc_kyber_ss),
		kyber_ss_label, sizeof(kyber_ss_label) - 1, (uint8_t *)ct,
		sizeof(struct lc_kyber_x448_ct), ss, ss_len);
}

/**
 * @brief Kyber-X448 KDF with 3 input values
 *
 * SS <- KMAC256(K = Kyber-SS || X448-SS from ephemeral key 1,
 *		 X = Kyber-SS || X448-SS from static key || Nonce,
 *		 L = requested SS length,
 *		 S = "Kyber X448 KEM 3-way SS")
 *
 * @param [in] ss0 SS0
 * @param [in] ss1 SS1
 * @param [in] in3 input buffer 3
 * @param [in] inlen3 length of input buffer 3
 * @param [out] out output buffer of size
 * @param [in] outlen output buffer length
 *
 * NOTE: This is not considered a key combiner in the sense of SP800-227, but
 * to support the KEX operation.
 */
static inline void kyber_x448_kdf3(const struct lc_kyber_x448_ss *ss0,
				   const struct lc_kyber_x448_ss *ss1,
				   const uint8_t *in3, size_t inlen3,
				   uint8_t *out, size_t outlen)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t kyber_x448_ss_label[] = "Kyber X448 KEM 3-way SS";
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	/*
	 * NOTE: this only works because struct lc_kyber_x448_ss contains
	 * Kyber SS || X448 SS in memory. If this structure changes,
	 * change this KDF invocation.
	 */
	if (lc_kmac_init(kmac_ctx, (uint8_t *)ss0,
			 sizeof(struct lc_kyber_x448_ss), kyber_x448_ss_label,
			 sizeof(kyber_x448_ss_label) - 1))
		return;
	lc_kmac_update(kmac_ctx, (uint8_t *)ss1,
		       sizeof(struct lc_kyber_x448_ss));
	lc_kmac_update(kmac_ctx, in3, inlen3);
	lc_kmac_final(kmac_ctx, out, outlen);

	lc_kmac_zero(kmac_ctx);
}

/**
 * @brief Kyber-X448 KDF with 4 input values
 *
 * SS <- KMAC256(K = Kyber-SS || X448-SS from ephemeral key 1,
 *		 X = Kyber-SS || X448-SS from ephemeral key 2 ||
 *		     Kyber-SS || X448-SS from static key || Nonce,
 *		 L = requested SS length,
 *		 S = "Kyber X448 KEM 4-way SS")
 *
 * @param [in] ss0 SS0
 * @param [in] ss1 SS1
 * @param [in] ss2 SS2
 * @param [in] in4 input buffer 4
 * @param [in] inlen4 length of input buffer 4
 * @param [out] out output buffer of size
 * @param [in] outlen output buffer length
 *
 * NOTE: This is not considered a key combiner in the sense of SP800-227, but
 * to support the KEX operation.
 */
static inline void kyber_x448_kdf4(const struct lc_kyber_x448_ss *ss0,
				   const struct lc_kyber_x448_ss *ss1,
				   const struct lc_kyber_x448_ss *ss2,
				   const uint8_t *in4, size_t inlen4,
				   uint8_t *out, size_t outlen)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t kyber_x448_ss_label[] = "Kyber X448 KEM 4-way SS";
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	/*
	 * NOTE: this only works because struct lc_kyber_x448_ss contqains
	 * Kyber SS || X448 SS in memory. If this structure changes,
	 * change this KDF invocation.
	 */
	if (lc_kmac_init(kmac_ctx, (uint8_t *)ss0,
			 sizeof(struct lc_kyber_x448_ss), kyber_x448_ss_label,
			 sizeof(kyber_x448_ss_label) - 1))
		return;
	lc_kmac_update(kmac_ctx, (uint8_t *)ss1,
		       sizeof(struct lc_kyber_x448_ss));
	lc_kmac_update(kmac_ctx, (uint8_t *)ss2,
		       sizeof(struct lc_kyber_x448_ss));
	lc_kmac_update(kmac_ctx, in4, inlen4);
	lc_kmac_final(kmac_ctx, out, outlen);

	lc_kmac_zero(kmac_ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_X448_KDF_H */
