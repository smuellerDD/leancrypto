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

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"
#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "helper.h"
#include "lc_status.h"
#include "sha256_arm_ce.h"
#include "sha256_arm_neon.h"
#include "sha256_avx2.h"
#include "sha256_c.h"
#include "sha256_riscv.h"
#include "sha256_riscv_zbb.h"
#include "sha256_shani.h"
#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_riscv_asm.h"
#include "sha512_arm_ce.h"
#include "sha512_arm_neon.h"
#include "sha512_avx2.h"
#include "sha512_c.h"
#include "sha512_riscv.h"
#include "sha512_riscv_zbb.h"
#include "sha512_shani.h"
#include "small_stack_support.h"
#include "status_algorithms.h"
#include "visibility.h"

#include "../src/riscv64/kyber_rvv_vlen_selector.h"

LC_INTERFACE_FUNCTION(int, lc_status, char *outbuf, size_t outlen)
{
	LC_FIPS_RODATA_SECTION
	static const char __maybe_unused armv8[] =
#if defined(LC_HOST_AARCH64) || defined(CONFIG_ARM64)
		"ARMv8 ";
#else
		"";
#endif
	LC_FIPS_RODATA_SECTION
	static const char __maybe_unused armv7[] =
#if defined(LC_HOST_ARM32_NEON) || defined(CONFIG_ARM)
		"ARMv7 ";
#else
		"";
#endif
	LC_FIPS_RODATA_SECTION
	static const char __maybe_unused riscv64[] =
#if defined(LC_HOST_RISCV64) || defined(CONFIG_RISCV)
		"RISCV64 ";
#else
		"";
#endif

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wembedded-directive"
#endif

#define LC_STATUS_ALG_SIZE 1000
	struct workspace {
		char status_pass[LC_STATUS_ALG_SIZE];
		char status_error[LC_STATUS_ALG_SIZE];
		char status_untested[LC_STATUS_ALG_SIZE];
	};
	size_t len, status_pass_len = LC_STATUS_ALG_SIZE,
		    status_error_len = LC_STATUS_ALG_SIZE,
		    status_untested_len = LC_STATUS_ALG_SIZE;
	LC_DECLARE_MEM(ws, struct workspace, 8);

	snprintf(outbuf, outlen, "leancrypto %u.%u.%u\n", MAJVERSION,
		 MINVERSION, PATCHLEVEL);

	alg_status_print((uint64_t)-1, ws->status_pass, status_pass_len,
			 ws->status_untested, status_untested_len,
			 ws->status_error, status_error_len);

	len = strlen(outbuf);
	snprintf(outbuf + len, outlen - len,
		 "Self-Test Passed: %s\n"
		 "Self-Test Not Executed: %s\n"
		 "Self-Test Failed: %s\n",
		 ws->status_pass, ws->status_untested, ws->status_error);

	len = strlen(outbuf);
	snprintf(
		outbuf + len, outlen - len,
		"FIPS 140 Mode: %s\n"
		"Acceleration support:\n"
#ifdef LC_AES
		" AES: %s%s%s\n"
#endif
#ifdef LC_SHA2_256
		" SHA2-256: %s%s%s%s%s%s\n"
#endif
#ifdef LC_SHA2_512
		" SHA2-512: %s%s%s%s%s%s\n"
#endif
#ifdef LC_SHA3
		" SHA3 family: %s%s%s%s%s%s%s\n"
#endif
#ifdef LC_KYBER
		" ML-KEM: %s%s%s%s%s\n"
#endif
#ifdef LC_DILITHIUM
		" ML-DSA: %s%s%s%s%s\n"
#endif
#ifdef LC_SPHINCS
		" SLH-DSA: %s%s\n"
#endif
#ifdef LC_BIKE
		" BIKE: %s%s\n"
#endif
#ifdef LC_HQC
		" HQC: %s\n"
#endif
#ifdef LC_CURVE25519
		" Curve25519: %s%s%s\n"
#endif
#ifdef LC_CURVE448
		" Curve448: %s\n"
#endif
		" GF: %s%s%s\n",
		fips140_mode_enabled() ? "yes" : "no"

	/* AES */
#ifdef LC_AES
		,
		(lc_aes_aesni && lc_aes_aesni != lc_aes_c) ? "AESNI " : "",
		(lc_aes_armce && lc_aes_armce != lc_aes_c) ? "ARMv8-CE " : "",
		(lc_aes_riscv64 && lc_aes_riscv64 != lc_aes_c) ? "RISCV64 " : ""
#endif

	/* SHA2-256 */
#ifdef LC_SHA2_256
		,
		(lc_sha256_shani && lc_sha256_shani != lc_sha256_c) ? "SHANI " :
								      "",
		(lc_sha256_avx2 && lc_sha256_avx2 != lc_sha256_c) ? "AVX2 " :
								    "",
		(lc_sha256_arm_ce && lc_sha256_arm_ce != lc_sha256_c) ?
			"ARM-CE " :
			"",
		(lc_sha256_arm_neon && lc_sha256_arm_neon != lc_sha256_c) ?
			"ARM-Neon " :
			"",
		(lc_sha256_riscv && lc_sha256_riscv != lc_sha256_c) ?
			"RISCV64 " :
			"",
		(lc_sha256_riscv_zbb && lc_sha256_riscv_zbb != lc_sha256_c) ?
			"RISCV64-Zbb " :
			""
#endif

	/* SHA2-512 */
#ifdef LC_SHA2_512
		,
		(lc_sha512_shani && lc_sha512_shani != lc_sha512_c) ?
			"SHANI-512 " :
			"",
		(lc_sha512_avx2 && lc_sha512_avx2 != lc_sha512_c) ? "AVX2 " :
								    "",
		(lc_sha512_arm_ce && lc_sha512_arm_ce != lc_sha512_c) ?
			"ARM-CE " :
			"",
		(lc_sha512_arm_neon && lc_sha512_arm_neon != lc_sha512_c) ?
			"ARM-Neon " :
			"",
		(lc_sha512_riscv && lc_sha512_riscv != lc_sha512_c) ?
			"RISCV64 " :
			"",
		(lc_sha512_riscv_zbb && lc_sha512_riscv_zbb != lc_sha512_c) ?
			"RISCV64-Zbb " :
			""
#endif

	/* SHA3 */
#ifdef LC_SHA3
		,
		(lc_sha3_256_avx512 && lc_sha3_256_avx512 != lc_sha3_256_c) ?
			"AVX512 " :
			"",
		(lc_sha3_256_avx2 && lc_sha3_256_avx2 != lc_sha3_256_c) ?
			"AVX2 AVX2-4x " :
			"",
		(lc_sha3_256_arm_neon &&
		 lc_sha3_256_arm_neon != lc_sha3_256_c) ?
			"ARM-Neon " :
			"",
		(lc_sha3_256_arm_ce && lc_sha3_256_arm_ce != lc_sha3_256_c) ?
			"ARMv8-CE " :
			"",
		(lc_sha3_256_arm_asm && lc_sha3_256_arm_asm != lc_sha3_256_c) ?
			"ARMv8 ARMv8-2x " :
			"",
		(lc_sha3_256_riscv_asm_zbb &&
		 lc_sha3_256_riscv_asm_zbb != lc_sha3_256_c) ?
			"RISCV64-Zbb " :
			"",
		(lc_sha3_256_riscv_asm &&
		 lc_sha3_256_riscv_asm != lc_sha3_256_c) ?
			"RISCV64 " :
			""
#endif

	/* Kyber */
#ifdef LC_KYBER
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			"",
		armv7, armv8, riscv64,
#if defined(LC_HOST_RISCV64) || defined(CONFIG_RISCV)
		lc_riscv_rvv_is_vlen128() ? "RISV64-RVV128 " :
		lc_riscv_rvv_is_vlen256() ? "RISV64-RVV256 " :
					    ""
#else
		""
#endif

#endif /* LC_KYBER */

	/* Dilithium */
#ifdef LC_DILITHIUM
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			"",
		armv7, armv8, riscv64,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV_ASM_RVV) ?
			"RISCV64-RVV " :
			""
#endif /* LC_DILITHIUM */

	/* Sphincs+ */
#ifdef LC_SPHINCS
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			"",
		armv8
#endif /* LC_DILITHIUM */

	/* Bike */
#ifdef LC_BIKE
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			"",
		((lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX512) &&
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_VPCLMUL)) ?
			"AVX512 " :
			""
#endif /* LC_BIKE */
	/* HQC */
#ifdef LC_HQC
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			""
#endif /* LC_HQC */

	/* Curve25519 */
#ifdef LC_CURVE25519
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			"",
		armv7, armv8
#endif /* LC_CURVE25519 */

	/* Curve448 */
#ifdef LC_CURVE448
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			"AVX2 " :
			""
#endif /* LC_CURVE448 */

		/* GF */
		,
		(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_PCLMUL) ?
			"PCLMULQDQ " :
			"",
		(lc_cpu_feature_available() & LC_CPU_FEATURE_ARM_PMULL) ?
			"PMULL " :
			"",
		(lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV) ?
			(lc_cpu_feature_available() &
			 LC_CPU_FEATURE_RISCV_ASM_ZBB) ?
			"RISCV64-Zbb " :
			"RISCV64 " :
			"");

#ifdef __clang__
#pragma GCC diagnostic pop
#endif

	return 0;
}
