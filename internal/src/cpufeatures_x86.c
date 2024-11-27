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

#include "cpufeatures.h"
#include "ext_headers.h"
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
#define LC_INTEL_AVX_ECX (1 << 28)
/* Leaf 7, subleaf 0 of CPUID */
#define LC_INTEL_AVX2_EBX (1 << 5)
#define LC_INTEL_AVX512F_EBX (1 << 16)
#define LC_INTEL_VPCLMUL_ECX (1 << 10)
#define LC_INTEL_PCLMUL_ECX (1 << 1)

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
	feat = LC_CPU_FEATURE_NONE;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_enable, void)
{
	feat = LC_CPU_FEATURE_UNSET;
}

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	unsigned int eax, ebx, ecx, edx;

	if (!(feat & LC_CPU_FEATURE_UNSET))
		return feat;

	feat = LC_CPU_FEATURE_NONE;

	cpuid_eax(1, x86_64_cpuid[0], x86_64_cpuid[1], x86_64_cpuid[2],
		  x86_64_cpuid[3]);

	if (x86_64_cpuid[2] & LC_INTEL_AESNI_ECX)
		feat |= LC_CPU_FEATURE_INTEL_AESNI;
	if (x86_64_cpuid[2] & LC_INTEL_AVX_ECX)
		feat |= LC_CPU_FEATURE_INTEL_AVX;

	/* Read the maximum leaf */
	cpuid_eax(0, eax, ebx, ecx, edx);

	if (eax >= 1) {
		cpuid_eax_ecx(1, 0, eax, ebx, ecx, edx);

		if (ecx & LC_INTEL_PCLMUL_ECX)
			feat |= LC_CPU_FEATURE_INTEL_PCLMUL;
	}

	/* Only make call if the leaf is present */
	if (eax < 7)
		return feat;

	/* read advanced features eax = 7, ecx = 0 */
	cpuid_eax_ecx(7, 0, eax, ebx, ecx, edx);
	if (ebx & LC_INTEL_AVX2_EBX)
		feat |= LC_CPU_FEATURE_INTEL_AVX2;

	if (ebx & LC_INTEL_AVX512F_EBX)
		feat |= LC_CPU_FEATURE_INTEL_AVX512;

	if (ecx & LC_INTEL_VPCLMUL_ECX)
		feat |= LC_CPU_FEATURE_INTEL_VPCLMUL;

	return feat;
}
