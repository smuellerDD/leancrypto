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

#include "chacha20_c.h"
#include "chacha20_neon.h"
#include "chacha20_riscv64_v_zbb.h"
#include "chacha20_ssse3.h"
#include "cpufeatures.h"
#include "initialization.h"
#include "lc_chacha20.h"
#include "visibility.h"

LC_CONSTRUCTOR(chacha20_fastest_impl)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_DEFAULT(accel, dflt)                                \
	lc_chacha20_##accel = lc_chacha20_##dflt;

#define LC_FILL_ACCEL_WITH_C(accel) LC_FILL_ACCEL_WITH_DEFAULT(accel, c)

#define LC_FILL_ACCEL_NULL(accel)                                              \
	if (!lc_chacha20_##accel) {                                            \
		LC_FILL_ACCEL_WITH_C(accel)                                    \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(neon)

#define LC_FILL_DFLT_IMPL(accel) lc_chacha20 = lc_chacha20_##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_ARM_NEON) {
		LC_FILL_DFLT_IMPL(neon)
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX) {
		LC_FILL_DFLT_IMPL(ssse3)
	} else if (feat & LC_CPU_FEATURE_RISCV_ASM_RVV) {
		LC_FILL_DFLT_IMPL(riscv64_v_zbb)
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_ARM_NEON)) {
		LC_FILL_ACCEL_WITH_C(neon)
	}
	if (!(feat & LC_CPU_FEATURE_INTEL_AVX)) {
		LC_FILL_ACCEL_WITH_C(ssse3)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV_ASM_RVV)) {
		LC_FILL_ACCEL_WITH_C(riscv64_v_zbb)
	}
}
