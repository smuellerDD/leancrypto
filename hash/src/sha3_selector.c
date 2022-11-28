/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
#include "ext_headers.h"
#include "lc_sha3.h"
#include "sha3_c.h"
#include "sha3_arm8_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_common.h"
#include "visibility.h"

LC_CONSTRUCTOR(sha3_fastest_impl)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

	/* Check if NULL pointers are present */
	if (!lc_sha3_224_arm8_neon) {
		lc_sha3_224_arm8_neon = lc_sha3_224_c;
		lc_sha3_256_arm8_neon = lc_sha3_256_c;
		lc_sha3_384_arm8_neon = lc_sha3_384_c;
		lc_sha3_512_arm8_neon = lc_sha3_512_c;
		lc_shake128_arm8_neon = lc_shake128_c;
		lc_shake256_arm8_neon = lc_shake256_c;
		lc_cshake128_arm8_neon = lc_cshake128_c;
		lc_cshake256_arm8_neon = lc_cshake256_c;
	}

	if (!lc_sha3_224_avx512) {
		lc_sha3_224_avx512 = lc_sha3_224_c;
		lc_sha3_256_avx512 = lc_sha3_256_c;
		lc_sha3_384_avx512 = lc_sha3_384_c;
		lc_sha3_512_avx512 = lc_sha3_512_c;
		lc_shake128_avx512 = lc_shake128_c;
		lc_shake256_avx512 = lc_shake256_c;
		lc_cshake128_avx512 = lc_cshake128_c;
		lc_cshake256_avx512 = lc_cshake256_c;
	}

	if (!lc_sha3_224_avx2) {
		lc_sha3_224_avx2 = lc_sha3_224_c;
		lc_sha3_256_avx2 = lc_sha3_256_c;
		lc_sha3_384_avx2 = lc_sha3_384_c;
		lc_sha3_512_avx2 = lc_sha3_512_c;
		lc_shake128_avx2 = lc_shake128_c;
		lc_shake256_avx2 = lc_shake256_c;
		lc_cshake128_avx2 = lc_cshake128_c;
		lc_cshake256_avx2 = lc_cshake256_c;
	}

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		lc_sha3_224 = lc_sha3_224_avx512;
		lc_sha3_256 = lc_sha3_256_avx512;
		lc_sha3_384 = lc_sha3_384_avx512;
		lc_sha3_512 = lc_sha3_512_avx512;
		lc_shake128 = lc_shake128_avx512;
		lc_shake256 = lc_shake256_avx512;
		lc_cshake128 = lc_cshake128_avx512;
		lc_cshake256 = lc_cshake256_avx512;
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		lc_sha3_224 = lc_sha3_224_avx2;
		lc_sha3_256 = lc_sha3_256_avx2;
		lc_sha3_384 = lc_sha3_384_avx2;
		lc_sha3_512 = lc_sha3_512_avx2;
		lc_shake128 = lc_shake128_avx2;
		lc_shake256 = lc_shake256_avx2;
		lc_cshake128 = lc_cshake128_avx2;
		lc_cshake256 = lc_cshake256_avx2;
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX512)) {
		lc_sha3_224_avx512 = lc_sha3_224_c;
		lc_sha3_256_avx512 = lc_sha3_256_c;
		lc_sha3_384_avx512 = lc_sha3_384_c;
		lc_sha3_512_avx512 = lc_sha3_512_c;
		lc_shake128_avx512 = lc_shake128_c;
		lc_shake256_avx512 = lc_shake256_c;
		lc_cshake128_avx512 = lc_cshake128_c;
		lc_cshake256_avx512 = lc_cshake256_c;
	}
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX2)) {
		lc_sha3_224_avx2 = lc_sha3_224_c;
		lc_sha3_256_avx2 = lc_sha3_256_c;
		lc_sha3_384_avx2 = lc_sha3_384_c;
		lc_sha3_512_avx2 = lc_sha3_512_c;
		lc_shake128_avx2 = lc_shake128_c;
		lc_shake256_avx2 = lc_shake256_c;
		lc_cshake128_avx2 = lc_cshake128_c;
		lc_cshake256_avx2 = lc_cshake256_c;
	}
}
