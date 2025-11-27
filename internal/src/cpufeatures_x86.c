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
#include "ext_headers_x86.h"
#include "visibility.h"

#define cpuid_eax(level, a, b, c, d)                                           \
	__asm__ __volatile__("cpuid\n\t"                                       \
			     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)              \
			     : "0"(level)                                      \
			     : "memory")

#define cpuid_eax_ecx(level, count, a, b, c, d)                                \
	__asm__ __volatile__("cpuid\n\t"                                       \
			     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)              \
			     : "0"(level), "2"(count)                          \
			     : "memory")

/* Leaf 1 */
#define LC_INTEL_AESNI_ECX (1 << 25)
#define LC_INTEL_PCLMUL_ECX (1 << 1)
#define LC_INTEL_AVX_ECX (1 << 28)
#define LC_INTEL_FMA_ECX (1 << 12)
#define LC_INTEL_MOVBE_ECX (1 << 22)
#define LC_INTEL_OSXSAVE (1 << 27)
#define LC_INTEL_AVX_PREREQ1                                                   \
	(LC_INTEL_FMA_ECX | LC_INTEL_MOVBE_ECX | LC_INTEL_OSXSAVE)
/* Leaf 7, subleaf 0 of CPUID */
#define LC_INTEL_AVX2_EBX (1 << 5)
#define LC_INTEL_BMI1_EBX (1 << 3)
#define LC_INTEL_BMI2_EBX (1 << 8)
#define LC_INTEL_AVX2_PREREQ2                                                  \
	(LC_INTEL_AVX2_EBX | LC_INTEL_BMI1_EBX | LC_INTEL_BMI2_EBX)
#define LC_INTEL_AVX512F_EBX (1 << 16)
#define LC_INTEL_VPCLMUL_ECX (1 << 10)
#define LC_INTEL_SHANI_EBX (1 << 29)
#define LC_INTEL_SHANI_EBX (1 << 29)
#define LC_INTEL_SHANI512_EAX (1 << 0)

/* This is required by aes_aesni_x86_64.S */
static unsigned int x86_64_cpuid[4] __attribute__((used));

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_get_cpuid, unsigned int cpuid[4])
{
	cpuid[0] = x86_64_cpuid[0];
	cpuid[1] = x86_64_cpuid[1];
	cpuid[2] = x86_64_cpuid[2];
	cpuid[3] = x86_64_cpuid[3];
}

static enum lc_cpu_features feat = LC_CPU_FEATURE_UNSET;

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_disable, void)
{
	feat = LC_CPU_FEATURE_INTEL;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_enable, void)
{
	feat = LC_CPU_FEATURE_UNSET;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_set, enum lc_cpu_features feature)
{
	feat = feature;
}

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	unsigned int eax, ebx, ecx, edx;

	if (!(feat & LC_CPU_FEATURE_UNSET))
		return feat;

	feat = LC_CPU_FEATURE_INTEL;

	cpuid_eax(1, x86_64_cpuid[0], x86_64_cpuid[1], x86_64_cpuid[2],
		  x86_64_cpuid[3]);

	if (x86_64_cpuid[2] & LC_INTEL_AESNI_ECX)
		feat |= LC_CPU_FEATURE_INTEL_AESNI;

	/* Read the maximum leaf */
	cpuid_eax(0, eax, ebx, ecx, edx);
	if (eax >= 1)
		cpuid_eax_ecx(1, 0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax < 7)
		return feat;

	/* read advanced features eax = 7, ecx = 1 */
	cpuid_eax_ecx(7, 1, eax, ebx, ecx, edx);
	if (eax & LC_INTEL_SHANI512_EAX)
		feat |= LC_CPU_FEATURE_INTEL_SHANI512;

	/* read advanced features eax = 7, ecx = 0 */
	cpuid_eax_ecx(7, 0, eax, ebx, ecx, edx);

	/*
	 * Check AVX2 support according to Intel document "How to detect New
	 * Instruction support in the 4th generation Intel® Core™ processor
	 * family"
	 */
	if ((x86_64_cpuid[2] & LC_INTEL_AVX_PREREQ1) == LC_INTEL_AVX_PREREQ1) {
		uint32_t xcr0 = 0;

		/* XCR0 may only be queried if the OSXSAVE bit is set. */
		if (x86_64_cpuid[2] & LC_INTEL_OSXSAVE) {
#if defined(_MSC_VER) && !defined(__clang__)
			xcr0 = _xgetbv(0);
#else
			__asm__ ("xgetbv" : "=a" (xcr0) : "c" (0) : "%edx");
#endif
		}

		/* Check if xmm and ymm state are enabled in XCR0. */
		if ((xcr0 & 6) == 6) {
			/* XMM registers are accessible */
			if (x86_64_cpuid[2] & LC_INTEL_PCLMUL_ECX)
				feat |= LC_CPU_FEATURE_INTEL_PCLMUL;
			if (x86_64_cpuid[2] & LC_INTEL_AVX_ECX)
				feat |= LC_CPU_FEATURE_INTEL_AVX;

			/* YMM registers are accessible */
			if ((ebx & LC_INTEL_AVX2_PREREQ2) ==
			     LC_INTEL_AVX2_PREREQ2)
				feat |= LC_CPU_FEATURE_INTEL_AVX2;
			if (x86_64_cpuid[2] & LC_INTEL_PCLMUL_ECX &&
			    ecx & LC_INTEL_VPCLMUL_ECX)
				feat |= LC_CPU_FEATURE_INTEL_VPCLMUL;
		}

		/* See Intel manual, volume 1, section 15.2. */
		if ((xcr0 & 0xe6) == 0xe6) {
			/*
			 * Allow AVX512F. Other AVX512 operations are supported
			 * as they do not use YMM.
			 */
			if (ebx & LC_INTEL_AVX512F_EBX)
				feat |= LC_CPU_FEATURE_INTEL_AVX512;
		}
	}

	if (ebx & LC_INTEL_SHANI_EBX)
		feat |= LC_CPU_FEATURE_INTEL_SHANI;

	return feat;
}
