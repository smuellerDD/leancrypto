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

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"
#include "cpufeatures.h"
#include "ext_headers.h"
#include "lc_status.h"
#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_status, char *outbuf, size_t outlen)
{
	static const char armv8[] =
#if defined(LC_HOST_AARCH64) || defined(CONFIG_ARM64)
		"ARMv8 ";
#else
		"";
#endif
	static const char armv7[] =
#if defined(LC_HOST_ARM32_NEON) || defined(CONFIG_ARM)
		"ARMv7 ";
#else
		"";
#endif
	static const char avx[] =
#if defined(LC_HOST_X86_64) || defined(CONFIG_X86_64)
		"AVX ";
#else
		"";
#endif
	static const char riscv64[] =
#if defined(LC_HOST_RISCV64) || defined(CONFIG_RISCV)
		"RISCV64 ";
#else
		"";
#endif
	static const char fips140[] =
#ifdef LC_FIPS140
		"yes";
#else
		"no";
#endif

	size_t len;

	snprintf(outbuf, outlen, "leancrypto %u.%u.%u\n", MAJVERSION,
		 MINVERSION, PATCHLEVEL);

	len = strlen(outbuf);
	snprintf(outbuf + len, outlen - len,
		 "FIPS 140 Mode: %s\n"
		 "AES Acceleration support: %s%s%s\n"
		 "SHA Acceleration support: %s%s%s%s%s%s%s\n"
		 "Kyber Acceleration support: %s%s%s%s\n"
		 "Dilithium Acceleration support: %s%s%s%s\n"
		 "Curve25519 Acceleration support: %s\n",

		 fips140,

		 /* AES */
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AESNI) ?
			 "AESNI " :
			 "",
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_ARM_AES) ?
			 "ARMv8 CE " :
			 "",
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV_ASM) ?
			 "RISC-V 64 " :
			 "",

		 /* SHA3 */
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX512) ?
			 "AVX512 " :
			 "",
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			 "AVX2 " :
			 "",
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_ARM_NEON) ?
			 "ARMv7 Neon " :
			 "",
		 armv8,
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_ARM_SHA3) ?
			 "ARMv8 CE " :
			 "",
		 riscv64,
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_ARM_SHA3) ?
			 "RISCV64 ZBB " :
			 "",

		 /* Kyber */
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			 "AVX2" :
			 "",
		 armv7, armv8, riscv64,

		 /* Dilithium */
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			 "AVX2" :
			 "",
		 armv7, armv8, riscv64,

		 /* Curve25519 */
		 avx);
}
