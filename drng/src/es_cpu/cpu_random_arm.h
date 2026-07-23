/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef _CPU_RANDOM_ARM
#define _CPU_RANDOM_ARM

#if defined(__aarch64__)

#include <arm_acle.h>
#include <stdint.h>

#include <stdbool.h>

#define LC_CPU_ES_IMPLEMENTED

/*
 * Read the feature register ID_AA64ISAR0_EL1
 *
 * Purpose: Provides information about the instructions implemented in
 * AArch64 state. For general information about the interpretation of the ID
 * registers, see 'Principles of the ID scheme for fields in ID registers'.
 *
 * Documentation: https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0?lang=en
 *
 * No standard intrinsic exists for reading system ID registers, so the
 * inline asm is retained.
 */
#define ARM8_RNDR_FEATURE (UINT64_C(0xf) << 60)
#define ARM8_SM4_FEATURE (UINT64_C(0xf) << 40)
#define ARM8_SM3_FEATURE (UINT64_C(0xf) << 36)
#define ARM8_SHA3_FEATURE (UINT64_C(0xf) << 32)
#define ARM8_SHA2_FEATURE (UINT64_C(0xf) << 32)
#define ARM8_SHA256_FEATURE (UINT64_C(0x1) << 32) /* SHA256 */
#define ARM8_SHA256512_FEATURE (UINT64_C(0x1) << 33) /* SHA256 and SHA512 */
#define ARM8_SHA1_FEATURE (UINT64_C(0xf) << 8)
#define ARM8_PMULL_FEATURE (UINT64_C(0x1) << 5)
#define ARM8_AES_FEATURE (UINT64_C(0x1) << 4)
static inline bool arm_id_aa64isar0_el1_feature(unsigned long feature)
{
	static unsigned long id_aa64isar0_el1_val = 0xffffffffffffffff;

	if (id_aa64isar0_el1_val == 0xffffffffffffffff) {
		__asm__ __volatile__("mrs %0, id_aa64isar0_el1"
				     : "=r"(id_aa64isar0_el1_val));

		if (id_aa64isar0_el1_val == 0xffffffffffffffff)
			return false;
	}

	return (id_aa64isar0_el1_val & feature) ? true : false;
}

/*
 * RNDRRS, Reseeded Random Number. Returns a 64-bit random number which is
 * reseeded from the True Random Number source immediately before the read
 * of the random number.
 *
 * The ACLE intrinsic __rndrrs returns 0 on success (a genuine random number
 * was produced) and non-zero on failure.
 */
/*
 * RNDRRS may transiently fail while the immediate reseed from the TRNG cannot
 * complete (e.g. under load from other consumers) - the same failure class
 * RDSEED exhibits on x86. Retry a bounded number of times with a yield hint
 * before giving up, mirroring RDSEED_RETRY_LOOPS in cpu_random_x86.h.
 */
#define RNDRRS_RETRY_LOOPS 1024

__attribute__((target("+rng"))) static inline bool arm_seed(unsigned long *data)
{
	unsigned int retry = 0;
	uint64_t val;

	while (__rndrrs(&val) != 0) {
		if (retry++ >= RNDRRS_RETRY_LOOPS)
			return false;
		__asm__ __volatile__("yield");
	}

	*data = (unsigned long)val;
	return true;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	if (!arm_id_aa64isar0_el1_feature(ARM8_RNDR_FEATURE))
		return false;

	/*
	 * RNDRRS yields one 64-bit value, which is exactly one unsigned long on
	 * aarch64, so fill the caller's single slot directly. The previous
	 * for-loop only ever ran once but advanced buf by sizeof(unsigned long)
	 * *elements* - a latent out-of-bounds footgun had the loop bound changed.
	 */
	return arm_seed(buf);
}

static inline unsigned int cpu_es_multiplier(void)
{
	return 1;
}

#endif

#endif /* _CPU_RANDOM_ARM */
