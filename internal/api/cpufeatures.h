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

#ifndef CPUFEATURES_H
#define CPUFEATURES_H

#ifdef __cplusplus
extern "C" {
#endif

enum lc_cpu_features {
	LC_CPU_FEATURE_NONE = 0,

	/* Intel-specific */
	LC_CPU_FEATURE_INTEL_AVX = 1 << 0,
	LC_CPU_FEATURE_INTEL_AVX2 = 1 << 1,
	LC_CPU_FEATURE_INTEL_AVX512 = 1 << 2,
	LC_CPU_FEATURE_INTEL_AESNI = 1 << 3,

	/* ARM-specific */
	LC_CPU_FEATURE_ARM = 1 << 8,
	LC_CPU_FEATURE_ARM_AES = 1 << 9,
	LC_CPU_FEATURE_ARM_NEON = 1 << 10,
	LC_CPU_FEATURE_ARM_SHA2 = 1 << 11,
	LC_CPU_FEATURE_ARM_SHA3 = 1 << 12,

	/* RISC-V-specific */
	LC_CPU_FEATURE_RISCV_ASM = 1 << 16,

	LC_CPU_FEATURE_UNSET = (1U) << 30
};

enum lc_cpu_features lc_cpu_feature_available(void);

#ifdef __cplusplus
}
#endif

#endif /* CPUFEATURES_H */
