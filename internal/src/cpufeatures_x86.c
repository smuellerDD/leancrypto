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

/* This is required by aes_aesni_x86_64.S */
unsigned int lc_x86_64_cpuid[4] __attribute__((used));

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	unsigned int eax, ebx, ecx, edx;
	static enum lc_cpu_features feat = LC_CPU_FEATURE_UNSET;

	if (!(feat & LC_CPU_FEATURE_UNSET))
		return feat;

	feat = LC_CPU_FEATURE_NONE;

	cpuid_eax(1, lc_x86_64_cpuid[0], lc_x86_64_cpuid[1], lc_x86_64_cpuid[2],
		  lc_x86_64_cpuid[3]);

	if (lc_x86_64_cpuid[2] & LC_INTEL_AESNI_ECX)
		feat |= LC_CPU_FEATURE_INTEL_AESNI;
	if (lc_x86_64_cpuid[2] & LC_INTEL_AVX_ECX)
		feat |= LC_CPU_FEATURE_INTEL_AVX;

	/* Read the maximum leaf */
	cpuid_eax(0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax < 7)
		return feat;

	/* read advanced features eax = 7, ecx = 0 */
	cpuid_eax_ecx(7, 0, eax, ebx, ecx, edx);
	if (ebx & LC_INTEL_AVX2_EBX)
		feat |= LC_CPU_FEATURE_INTEL_AVX2;

	if (ebx & LC_INTEL_AVX512F_EBX)
		feat |= LC_CPU_FEATURE_INTEL_AVX512;

	return feat;
}
