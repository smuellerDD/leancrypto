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

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "initialization.h"
#include "lc_sha256.h"
#include "sha256_arm_ce.h"
#include "sha256_arm_neon.h"
#include "sha256_avx2.h"
#include "sha256_c.h"
#include "sha256_riscv.h"
#include "sha256_riscv_zbb.h"
#include "sha256_shani.h"
#include "visibility.h"

LC_CONSTRUCTOR(sha256_fastest_impl, LC_INIT_PRIO_ALGO)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_DEFAULT(accel, dflt)                                \
	lc_sha256_##accel = lc_sha256_##dflt;

#define LC_FILL_ACCEL_WITH_C(accel) LC_FILL_ACCEL_WITH_DEFAULT(accel, c)

#define LC_FILL_ACCEL_NULL(accel)                                              \
	if (!lc_sha256_##accel) {                                              \
		LC_FILL_ACCEL_WITH_C(accel)                                    \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(shani)
	LC_FILL_ACCEL_NULL(avx2)
	LC_FILL_ACCEL_NULL(arm_ce)
	LC_FILL_ACCEL_NULL(arm_neon)
	LC_FILL_ACCEL_NULL(riscv)
	LC_FILL_ACCEL_NULL(riscv_zbb)

#define LC_FILL_DFLT_IMPL(accel) lc_sha256 = lc_sha256_##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_SHANI) {
		LC_FILL_DFLT_IMPL(shani)
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		LC_FILL_DFLT_IMPL(avx2)
	} else if (feat & LC_CPU_FEATURE_ARM_SHA2) {
		LC_FILL_DFLT_IMPL(arm_ce)
	} else if (feat & LC_CPU_FEATURE_ARM_NEON) {
		LC_FILL_DFLT_IMPL(arm_neon)
	} else if (feat & LC_CPU_FEATURE_RISCV_ASM_ZBB) {
		LC_FILL_DFLT_IMPL(riscv_zbb)
	} else if (feat & LC_CPU_FEATURE_RISCV) {
		LC_FILL_DFLT_IMPL(riscv)
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX2)) {
		LC_FILL_ACCEL_WITH_C(avx2)
	}
	if (!(feat & LC_CPU_FEATURE_INTEL_SHANI)) {
		LC_FILL_ACCEL_WITH_C(shani)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_SHA2)) {
		LC_FILL_ACCEL_WITH_C(arm_ce)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_NEON)) {
		LC_FILL_ACCEL_WITH_C(arm_neon)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV_ASM_ZBB)) {
		LC_FILL_ACCEL_WITH_C(riscv_zbb)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV)) {
		LC_FILL_ACCEL_WITH_C(riscv)
	}
}
