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
#include "ext_headers.h"
#include "lc_sha3.h"
#include "sha3_c.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_common.h"
#include "visibility.h"

LC_CONSTRUCTOR(sha3_fastest_impl)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_C(accel)					       \
	lc_sha3_224_ ##accel = lc_sha3_224_c;				       \
	lc_sha3_256_ ##accel = lc_sha3_256_c;				       \
	lc_sha3_384_ ##accel = lc_sha3_384_c;				       \
	lc_sha3_512_ ##accel = lc_sha3_512_c;				       \
	lc_shake128_ ##accel = lc_shake128_c;				       \
	lc_shake256_ ##accel = lc_shake256_c;				       \
	lc_cshake128_ ##accel = lc_cshake128_c;				       \
	lc_cshake256_ ##accel = lc_cshake256_c;

#define LC_FILL_ACCEL_NULL(accel)					       \
	if (!lc_sha3_224_ ##accel) {					       \
		LC_FILL_ACCEL_WITH_C(accel)				       \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(arm_neon)
	LC_FILL_ACCEL_NULL(avx512)
	LC_FILL_ACCEL_NULL(avx2)

#define LC_FILL_DFLT_IMPL(accel)					       \
	lc_sha3_224 = lc_sha3_224_ ##accel;				       \
	lc_sha3_256 = lc_sha3_256_ ##accel;				       \
	lc_sha3_384 = lc_sha3_384_ ##accel;				       \
	lc_sha3_512 = lc_sha3_512_ ##accel;				       \
	lc_shake128 = lc_shake128_ ##accel;				       \
	lc_shake256 = lc_shake256_ ##accel;				       \
	lc_cshake128 = lc_cshake128_ ##accel;				       \
	lc_cshake256 = lc_cshake256_ ##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		LC_FILL_DFLT_IMPL(avx512)
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		LC_FILL_DFLT_IMPL(avx2)
	} else if (feat & LC_CPU_FEATURE_ARM_NEON) {
		LC_FILL_DFLT_IMPL(arm_neon)
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX512)) {
		LC_FILL_ACCEL_WITH_C(avx512)
	}
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX2)) {
		LC_FILL_ACCEL_WITH_C(avx2)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_NEON)) {
		LC_FILL_ACCEL_WITH_C(arm_neon)
	}
}
