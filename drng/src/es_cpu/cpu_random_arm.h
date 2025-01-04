/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <stdint.h>

#include "bool.h"

#define ESDM_CPU_ES_IMPLEMENTED

/*
 * https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/RNDR--Random-Number
 *
 * RNDR, Random Number
 *
 * The RNDR characteristics are:
 *
 * Purpose: Random Number. Returns a 64-bit random number which is reseeded
 * from the True Random Number source at an IMPLEMENTATION DEFINED rate.
 *
 * MRS <Xt>, RNDR
 * op0: 0b11
 * op1: 0b011
 * CRn: 0b0010
 * CRm: 0b0100
 * op2: 0b000
 *
 *
 * RNDRRS, Reseeded Random Number
 *
 * The RNDRRS characteristics are:
 *
 * Purpose: Reseeded Random Number. Returns a 64-bit random number which is
 * reseeded from the True Random Number source immediately before the read
 * of the random number.
 *
 * MRS <Xt>, RNDRRS
 * op0: 0b11
 * op1: 0b011
 * CRn: 0b0010
 * CRm: 0b0100
 * op2: 0b001
 */
#define RNDR_INSTR "s3_3_c2_c4_0"
#define RNDRRS_INSTR "s3_3_c2_c4_1"

/*
 * Read the feature register ID_AA64ISAR0_EL1
 *
 * Purpose: Provides information about the instructions implemented in
 * AArch64 state. For general information about the interpretation of the ID
 * registers, see 'Principles of the ID scheme for fields in ID registers'.
 * 
 * Documentation: https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0?lang=en
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

static inline bool arm_seed(unsigned long *data)
{
	bool success;

	/*
	 * If the hardware returns a genuine random number, PSTATE.NZCV is
	 * set to 0b0000.
	 * If the instruction cannot return a genuine random number in a
	 * reasonable period of time, PSTATE.NZCV is set to 0b0100 and the
	 * data value returned is 0.
	 */
	__asm__ __volatile__("mrs %0, " RNDRRS_INSTR "\n"
			     "cset %w1, ne\n"
			     : "=r"(*data), "=r"(success)
			     :
			     : "cc");

	return success;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	unsigned int i = 0;

	if (!arm_id_aa64isar0_el1_feature(ARM8_RNDR_FEATURE))
		return false;

	for (i = 0; i < sizeof(unsigned long);
	     i += sizeof(unsigned long), buf += sizeof(unsigned long)) {
		if (!arm_seed(buf))
			return false;
	}

	return true;
}

static inline unsigned int cpu_es_multiplier(void)
{
	return 1;
}

#endif

#endif /* _CPU_RANDOM_ARM */
