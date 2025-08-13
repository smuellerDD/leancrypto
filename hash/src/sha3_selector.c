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

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "initialization.h"
#include "lc_sha3.h"
#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_common.h"
#include "sha3_riscv_asm.h"
#include "visibility.h"

LC_CONSTRUCTOR(sha3_fastest_impl)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_DEFAULT(accel, dflt)                                \
	lc_sha3_224_##accel = lc_sha3_224_##dflt;                              \
	lc_sha3_256_##accel = lc_sha3_256_##dflt;                              \
	lc_sha3_384_##accel = lc_sha3_384_##dflt;                              \
	lc_sha3_512_##accel = lc_sha3_512_##dflt;                              \
	lc_shake128_##accel = lc_shake128_##dflt;                              \
	lc_shake256_##accel = lc_shake256_##dflt;                              \
	lc_cshake128_##accel = lc_cshake128_##dflt;                            \
	lc_cshake256_##accel = lc_cshake256_##dflt;

#define LC_FILL_ACCEL_WITH_C(accel) LC_FILL_ACCEL_WITH_DEFAULT(accel, c)

#define LC_FILL_ACCEL_NULL(accel)                                              \
	if (!lc_sha3_224_##accel) {                                            \
		LC_FILL_ACCEL_WITH_C(accel)                                    \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(arm_asm)
	LC_FILL_ACCEL_NULL(arm_ce)
	LC_FILL_ACCEL_NULL(arm_neon)
	LC_FILL_ACCEL_NULL(avx512)
	LC_FILL_ACCEL_NULL(avx2)
	LC_FILL_ACCEL_NULL(riscv_asm)
	LC_FILL_ACCEL_NULL(riscv_asm_zbb)

#define LC_FILL_DFLT_IMPL(accel)                                               \
	lc_sha3_224 = lc_sha3_224_##accel;                                     \
	lc_sha3_256 = lc_sha3_256_##accel;                                     \
	lc_sha3_384 = lc_sha3_384_##accel;                                     \
	lc_sha3_512 = lc_sha3_512_##accel;                                     \
	lc_shake128 = lc_shake128_##accel;                                     \
	lc_shake256 = lc_shake256_##accel;                                     \
	lc_cshake128 = lc_cshake128_##accel;                                   \
	lc_cshake256 = lc_cshake256_##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		LC_FILL_DFLT_IMPL(avx512)
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		LC_FILL_DFLT_IMPL(avx2)
	} else if (feat & LC_CPU_FEATURE_ARM_SHA3) {
		LC_FILL_DFLT_IMPL(arm_ce)
	} else if (feat & LC_CPU_FEATURE_ARM_NEON) {
		/*
		 * NEON is only defined for ARMv7, but ARMv8 also has NEON,
		 * for which we can only define the assembler.
		 */
		if (lc_sha3_224_arm_neon == lc_sha3_224_c) {
			LC_FILL_DFLT_IMPL(arm_asm)
		} else {
			LC_FILL_DFLT_IMPL(arm_neon)
		}
	} else if (feat & LC_CPU_FEATURE_ARM) {
		LC_FILL_DFLT_IMPL(arm_asm)
	} else if (feat & LC_CPU_FEATURE_RISCV_ASM_ZBB) {
		LC_FILL_DFLT_IMPL(riscv_asm_zbb)
	} else if (feat & LC_CPU_FEATURE_RISCV) {
		LC_FILL_DFLT_IMPL(riscv_asm)
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
	if (!(feat & LC_CPU_FEATURE_ARM_SHA3)) {
		LC_FILL_ACCEL_WITH_C(arm_ce)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_NEON)) {
		LC_FILL_ACCEL_WITH_C(arm_neon)
	}
	if (!(feat & LC_CPU_FEATURE_ARM)) {
		LC_FILL_ACCEL_WITH_C(arm_asm)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV_ASM_ZBB)) {
		LC_FILL_ACCEL_WITH_C(riscv_asm_zbb)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV)) {
		LC_FILL_ACCEL_WITH_C(riscv_asm)
	}
}
