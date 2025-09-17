/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"
#include "cpufeatures.h"
#include "initialization.h"
#include "lc_aes.h"
#include "visibility.h"

#ifdef LC_AES_XTS
#define LC_FILL_ACCEL_NULL_XTS(accel, dflt)                                    \
	lc_aes_xts_##accel = lc_aes_xts_##dflt;
#define LC_FILL_DFLT_IMPL_XTS(accel)                                           \
	lc_aes_xts = lc_aes_xts_##accel;
#else
#define LC_FILL_ACCEL_NULL_XTS(accel, dflt)
#define LC_FILL_DFLT_IMPL_XTS(accel)
#endif

#ifdef LC_AES_CBC
#define LC_FILL_ACCEL_NULL_CBC(accel, dflt)                                    \
	lc_aes_cbc_##accel = lc_aes_cbc_##dflt;
#define LC_FILL_DFLT_IMPL_CBC(accel)                                           \
	lc_aes_cbc = lc_aes_cbc_##accel;
#else
#define LC_FILL_ACCEL_NULL_CBC(accel, dflt)
#define LC_FILL_DFLT_IMPL_CBC(accel)
#endif

#ifdef LC_AES_CTR
#define LC_FILL_ACCEL_NULL_CTR(accel, dflt)                                    \
	lc_aes_ctr_##accel = lc_aes_ctr_##dflt;
#define LC_FILL_DFLT_IMPL_CTR(accel)                                           \
	lc_aes_ctr = lc_aes_ctr_##accel;
#else
#define LC_FILL_ACCEL_NULL_CTR(accel, dflt)
#define LC_FILL_DFLT_IMPL_CTR(accel)
#endif

#ifdef LC_AES_KW
#define LC_FILL_ACCEL_NULL_KW(accel, dflt)                                     \
	lc_aes_kw_##accel = lc_aes_kw_##dflt;
#define LC_FILL_DFLT_IMPL_KW(accel)                                            \
	lc_aes_kw = lc_aes_kw_##accel;
#else
#define LC_FILL_ACCEL_NULL_KW(accel, dflt)
#define LC_FILL_DFLT_IMPL_KW(accel)
#endif

LC_CONSTRUCTOR(aes_fastest_impl, LC_INIT_PRIO_ALGO)
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

#define LC_FILL_ACCEL_WITH_DEFAULT(accel, dflt)                                \
	LC_FILL_ACCEL_NULL_XTS(accel, dflt)                                    \
	LC_FILL_ACCEL_NULL_CBC(accel, dflt)                                    \
	LC_FILL_ACCEL_NULL_CTR(accel, dflt)                                    \
	LC_FILL_ACCEL_NULL_KW(accel, dflt)                                     \
	lc_aes_##accel = lc_aes_##dflt;

#define LC_FILL_ACCEL_WITH_C(accel) LC_FILL_ACCEL_WITH_DEFAULT(accel, c)

#define LC_FILL_ACCEL_NULL(accel)                                              \
	if (!lc_aes_##accel) {                                                 \
		LC_FILL_ACCEL_WITH_C(accel)                                    \
	}

	/* Check if NULL pointers are present */
	LC_FILL_ACCEL_NULL(aesni)
	LC_FILL_ACCEL_NULL(armce)
	LC_FILL_ACCEL_NULL(riscv64)

#define LC_FILL_DFLT_IMPL(accel)                                               \
	LC_FILL_DFLT_IMPL_XTS(accel)                                           \
	LC_FILL_DFLT_IMPL_CBC(accel)                                           \
	LC_FILL_DFLT_IMPL_CTR(accel)                                           \
	LC_FILL_DFLT_IMPL_KW(accel)                                            \
	lc_aes = lc_aes_##accel;

	/*
	 * Set accelerated modes: The fastest implementations are at the top
	 */
	if (feat & LC_CPU_FEATURE_INTEL_AESNI) {
		LC_FILL_DFLT_IMPL(aesni)
	} else if (feat & LC_CPU_FEATURE_ARM_AES) {
		LC_FILL_DFLT_IMPL(armce)
	} else if (feat & LC_CPU_FEATURE_RISCV) {
		LC_FILL_DFLT_IMPL(riscv64)
	} else {
		/* do nothing as the C definitions are used automatically */
	}

	/* Unset accelerated modes to C if CPU does not provide support */
	if (!(feat & LC_CPU_FEATURE_INTEL_AESNI)) {
		LC_FILL_ACCEL_WITH_C(aesni)
	}
	if (!(feat & LC_CPU_FEATURE_ARM_AES)) {
		LC_FILL_ACCEL_WITH_C(armce)
	}
	if (!(feat & LC_CPU_FEATURE_RISCV)) {
		LC_FILL_ACCEL_WITH_C(riscv64)
	}
}
