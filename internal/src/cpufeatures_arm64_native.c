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
#include "visibility.h"

/*
 * Read the feature register ID_AA64ISAR0_EL1
 *
 * Purpose: Provides information about the instructions implemented in
 * AArch64 state. For general information about the interpretation of the ID
 * registers, see 'Principles of the ID scheme for fields in ID registers'.
 *
 * Documentation: https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0?lang=en
 */
#define ARM8_RNDR_FEATURE	(UINT64_C(0xf)<<60)
#define ARM8_SM4_FEATURE	(UINT64_C(0xf)<<40)
#define ARM8_SM3_FEATURE	(UINT64_C(0xf)<<36)
#define ARM8_SHA3_FEATURE	(UINT64_C(0xf)<<32)
#define ARM8_SHA2_FEATURE	(UINT64_C(0xf)<<32)
#define ARM8_SHA256_FEATURE	(UINT64_C(0x1)<<32)	/* SHA256 */
#define ARM8_SHA256512_FEATURE	(UINT64_C(0x1)<<33)	/* SHA256 and SHA512 */
#define ARM8_SHA1_FEATURE	(UINT64_C(0xf)<<8)
#define ARM8_PMULL_FEATURE	(UINT64_C(0x1)<<5)
#define ARM8_AES_FEATURE	(UINT64_C(0x1)<<4)

/* Apple M1/M2 returns an illegal instruction */
#if (!defined(__APPLE__))
static inline int arm_id_aa64isar0_el1_feature(unsigned long feature)
{
	static unsigned long id_aa64isar0_el1_val = 0xffffffffffffffff;

	if (id_aa64isar0_el1_val == 0xffffffffffffffff) {
		__asm__ __volatile__(
			"mrs %0, id_aa64isar0_el1 \n"
			: "=r" (id_aa64isar0_el1_val)
		);

		if (id_aa64isar0_el1_val == 0xffffffffffffffff)
			return 0;
	}

        return (id_aa64isar0_el1_val & feature) ? 1 : 0;
}
#else
static inline int arm_id_aa64isar0_el1_feature(unsigned long feature)
{
	(void)feature;
	return 0;
}
#endif

LC_INTERFACE_FUNCTION(
enum lc_cpu_features, lc_cpu_feature_available, void)
{
	enum lc_cpu_features features = LC_CPU_FEATURE_ARM;

	if (arm_id_aa64isar0_el1_feature(ARM8_AES_FEATURE))
		features |= LC_CPU_FEATURE_ARM_AES;

	if (arm_id_aa64isar0_el1_feature(ARM8_SHA256512_FEATURE))
		features |= LC_CPU_FEATURE_ARM_SHA2;

	if (arm_id_aa64isar0_el1_feature(ARM8_SHA3_FEATURE))
		features |= LC_CPU_FEATURE_ARM_SHA3;

	return features;
}
