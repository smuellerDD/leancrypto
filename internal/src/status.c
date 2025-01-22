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
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_status, char *outbuf, size_t outlen)
{
	static const char __maybe_unused armv8[] =
#if defined(LC_HOST_AARCH64) || defined(CONFIG_ARM64)
		"ARMv8 ";
#else
		"";
#endif
	static const char __maybe_unused armv7[] =
#if defined(LC_HOST_ARM32_NEON) || defined(CONFIG_ARM)
		"ARMv7 ";
#else
		"";
#endif
	static const char __maybe_unused avx[] =
#if defined(LC_HOST_X86_64) || defined(CONFIG_X86_64)
		"AVX ";
#else
		"";
#endif
	static const char __maybe_unused riscv64[] =
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
#ifdef LC_AES
		 "AES Acceleration support: %s%s%s\n"
#endif
#ifdef LC_SHA2_256
		 "SHA2-256 Acceleration support: %s%s%s%s%s%s\n"
#endif
#ifdef LC_SHA2_512
		 "SHA2-512 Acceleration support: %s%s%s%s%s%s\n"
#endif
#ifdef LC_SHA3
		 "SHA3 Acceleration support: %s%s%s%s%s%s%s\n"
#endif
#ifdef LC_KYBER
		 "Kyber Acceleration support: %s%s%s%s\n"
#endif
#ifdef LC_DILITHIUM
		 "Dilithium Acceleration support: %s%s%s%s%s\n"
#endif
#ifdef LC_CURVE25519
		 "Curve25519 Acceleration support: %s%s%s\n"
#endif
		 , fips140

		 /* AES */
#ifdef LC_AES
		 ,
		 (lc_aes_cbc_aesni && lc_aes_cbc_aesni != lc_aes_cbc_c) ?
			 "AESNI " :
			 "",
		 (lc_aes_cbc_armce && lc_aes_cbc_armce != lc_aes_cbc_c) ?
			 "ARMv8-CE " :
			 "",
		 (lc_aes_cbc_riscv64 && lc_aes_cbc_riscv64 != lc_aes_cbc_c) ?
			 "RISCV64 " :
			 ""
#endif

		 /* SHA2-256 */
#ifdef LC_SHA2_256
		 ,
		 (lc_sha256_shani && lc_sha256_shani != lc_sha256_c) ?
			 "SHANI " :
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
			 "AVX2 " :
			 "",
		 (lc_sha3_256_arm_neon &&
		  lc_sha3_256_arm_neon != lc_sha3_256_c) ?
			 "ARMv7-Neon " :
			 "",
		 (lc_sha3_256_arm_asm && lc_sha3_256_arm_asm != lc_sha3_256_c) ?
			 "ARMv8 " :
			 "",
		 (lc_sha3_256_arm_ce && lc_sha3_256_arm_ce != lc_sha3_256_c) ?
			 "ARMv8-CE " :
			 "",
		 (lc_sha3_256_riscv_asm &&
		  lc_sha3_256_riscv_asm != lc_sha3_256_c) ?
			 "RISCV64 " :
			 "",
		 (lc_sha3_256_riscv_asm_zbb &&
		  lc_sha3_256_riscv_asm_zbb != lc_sha3_256_c) ?
			 "RISCV64-Zbb " :
			 ""
#endif

		 /* Kyber */
#ifdef LC_KYBER
		 ,
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			 "AVX2" :
			 "",
		 armv7, armv8, riscv64
#endif

		 /* Dilithium */
#ifdef LC_DILITHIUM
		 ,
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) ?
			 "AVX2" :
			 "",
		 armv7, armv8, riscv64,
		 (lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV_ASM_RVV) ?
			 "RISCV64-RVV " :
			 ""
#endif

		 /* Curve25519 */
#ifdef LC_CURVE25519
		 ,
		 avx, armv7, armv8
#endif
		 );
}
