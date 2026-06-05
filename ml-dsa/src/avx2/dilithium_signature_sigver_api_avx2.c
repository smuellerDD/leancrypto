/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_type.h"
#include "dilithium_selftest.h"
#include "dilithium_signature_sigver_avx2.h"
#include "../dilithium_signature_sigver_c.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) {
		dilithium_sigver_tester(lc_dilithium_verify_ctx_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

		return lc_dilithium_verify_avx2(sig, m, mlen, pk);
	}

	dilithium_sigver_tester(lc_dilithium_verify_ctx_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_c(sig, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) {
		dilithium_sigver_tester(lc_dilithium_verify_ctx_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

		return lc_dilithium_verify_ctx_avx2(sig, ctx, m, mlen, pk);
	}

	dilithium_sigver_tester(lc_dilithium_verify_ctx_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_ctx_c(sig, ctx, m, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) {
		dilithium_sigver_tester(lc_dilithium_verify_ctx_avx2);
		LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

		return lc_dilithium_verify_init_avx2(ctx, pk);
	}

	dilithium_sigver_tester(lc_dilithium_verify_ctx_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_MLDSA_SIGVER);

	return lc_dilithium_verify_init_c(ctx, pk);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return lc_dilithium_verify_update_avx2(ctx, m, mlen);
	return lc_dilithium_verify_update_c(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return lc_dilithium_verify_final_avx2(sig, ctx, pk);
	return lc_dilithium_verify_final_c(sig, ctx, pk);
}
