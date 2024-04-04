/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_ascon_hash.h"
#include "ascon_arm_neon.h"
#include "ascon_avx512.h"
#include "ascon_c.h"
#include "visibility.h"

LC_CONSTRUCTOR(ascon_fastest_impl)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_DEFAULT(accel, dflt)                                \
	lc_ascon_128_##accel = lc_ascon_128_##dflt;                            \
	lc_ascon_128a_##accel = lc_ascon_128a_##dflt;                          \
	lc_ascon_xof_##accel = lc_ascon_xof_##dflt;                            \
	lc_ascon_xofa_##accel = lc_ascon_xofa_##dflt;

#define LC_FILL_ACCEL_WITH_C(accel) LC_FILL_ACCEL_WITH_DEFAULT(accel, c)

#define LC_FILL_ACCEL_NULL(accel)                                              \
	if (!lc_ascon_128_##accel) {                                           \
		LC_FILL_ACCEL_WITH_C(accel)                                    \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(avx512)

#define LC_FILL_DFLT_IMPL(accel)                                               \
	lc_ascon_128 = lc_ascon_128_##accel;                                   \
	lc_ascon_128a = lc_ascon_128a_##accel;                                 \
	lc_ascon_xof = lc_ascon_xof_##accel;                                   \
	lc_ascon_xofa = lc_ascon_xofa_##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		LC_FILL_DFLT_IMPL(avx512)
	//} else if (feat & LC_CPU_FEATURE_ARM_NEON) {
	//	LC_FILL_DFLT_IMPL(arm_neon)
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX512)) {
		LC_FILL_ACCEL_WITH_C(avx512)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_NEON)) {
		LC_FILL_ACCEL_WITH_C(arm_neon)
	}
}
