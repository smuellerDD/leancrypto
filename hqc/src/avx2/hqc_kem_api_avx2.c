/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "cpufeatures.h"
#include "hqc_internal_avx2.h"
#include "hqc_kem_avx2.h"
#include "../hqc_selftest.h"
#include "../hqc_kem_c.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	if (lc_cpu_feature_available() &
	    ((LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL))) {
		hqc_kem_keygen_selftest(lc_hqc_keypair_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_KEYGEN);

		return lc_hqc_keypair_avx2(pk, sk, rng_ctx);
	}

	hqc_kem_keygen_selftest(lc_hqc_keypair_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_KEYGEN);
	return lc_hqc_keypair_c(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair_from_seed, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, const uint8_t *seed, size_t seedlen)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_keygen_selftest(lc_hqc_keypair_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_KEYGEN);

		return lc_hqc_keypair_from_seed_avx2(pk, sk, seed, seedlen);
	}

	hqc_kem_keygen_selftest(lc_hqc_keypair_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_KEYGEN);
	return lc_hqc_keypair_from_seed_c(pk, sk, seed, seedlen);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_internal, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_enc_selftest(lc_hqc_enc_internal_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);

		return lc_hqc_enc_internal_avx2(ct, ss, pk, rng_ctx);
	}

	hqc_kem_enc_selftest(lc_hqc_enc_internal_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);
	return lc_hqc_enc_internal_c(ct, ss, pk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_enc_selftest(lc_hqc_enc_internal_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);

		return lc_hqc_enc_avx2(ct, ss, pk);
	}

	hqc_kem_enc_selftest(lc_hqc_enc_internal_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);
	return lc_hqc_enc_c(ct, ss, pk);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_kdf, struct lc_hqc_ct *ct, uint8_t *ss,
		      size_t ss_len, const struct lc_hqc_pk *pk)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_enc_selftest(lc_hqc_enc_internal_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);

		return lc_hqc_enc_kdf_avx2(ct, ss, ss_len, pk);
	}

	hqc_kem_enc_selftest(lc_hqc_enc_internal_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_ENC);
	return lc_hqc_enc_kdf_c(ct, ss, ss_len, pk);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec, struct lc_hqc_ss *ss,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_dec_selftest(lc_hqc_dec_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_DEC);

		return lc_hqc_dec_avx2(ss, ct, sk);
	}

	hqc_kem_dec_selftest(lc_hqc_dec_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_DEC);
	return lc_hqc_dec_c(ss, ct, sk);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	if (lc_cpu_feature_available() &
	    (LC_CPU_FEATURE_INTEL_AVX2 | LC_CPU_FEATURE_INTEL_PCLMUL)) {
		hqc_kem_dec_selftest(lc_hqc_dec_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_DEC);

		return lc_hqc_dec_kdf_avx2(ss, ss_len, ct, sk);
	}

	hqc_kem_dec_selftest(lc_hqc_dec_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HQC_DEC);
	return lc_hqc_dec_kdf_c(ss, ss_len, ct, sk);
}
