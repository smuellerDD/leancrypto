/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "cpufeatures.h"
#include "dilithium_signature_avx2.h"
#include "../dilithium_signature_c.h"
#include "lc_dilithium.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
int, lc_dilithium_keypair, struct lc_dilithium_pk *pk,
			   struct lc_dilithium_sk *sk,
			   struct lc_rng_ctx *rng_ctx)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return lc_dilithium_keypair_avx2(pk, sk, rng_ctx);
	return lc_dilithium_keypair_c(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_sign, struct lc_dilithium_sig *sig,
			const uint8_t *m,
			size_t mlen,
			const struct lc_dilithium_sk *sk,
			struct lc_rng_ctx *rng_ctx)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return lc_dilithium_sign_avx2(sig, m, mlen, sk, rng_ctx);
	return lc_dilithium_sign_c(sig, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_verify, const struct lc_dilithium_sig *sig,
			  const uint8_t *m,
			  size_t mlen,
			  const struct lc_dilithium_pk *pk)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return lc_dilithium_verify_avx2(sig, m, mlen, pk);
	return lc_dilithium_verify_c(sig, m, mlen, pk);
}
