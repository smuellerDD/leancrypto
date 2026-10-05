/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef CPUFEATURES_RISCV_H
#define CPUFEATURES_RISCV_H

#include "cpufeatures.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LINUX_KERNEL
#include <asm/cpufeature.h>
#include <linux/of.h>

static inline enum lc_cpu_features lc_cpu_features_iriscv(void)
{
	struct device_node *np;
	enum lc_cpu_features tmp = LC_CPU_FEATURE_NONE;

	np = of_get_cpu_node(smp_processor_id(), NULL);
	if (!np)
		return LC_CPU_FEATURE_NONE;

	if (of_property_read_bool(np, "chronox,es-drbg-seed-enabled"))
		tmp |= LC_CPU_FEATURE_RISCV_VESDRBGSEED;
	if (of_property_read_bool(np, "chronox,es-drbg-rand-enabled"))
		tmp |= LC_CPU_FEATURE_RISCV_VESDRBG;

	of_node_put(np);

	if (riscv_isa_extension_available(NULL, RISCV_ISA_EXT_ZKR))
		tmp |= LC_CPU_FEATURE_RISCV_ZKR;

	return tmp;
}

#else /* LINUX_KERNEL */

//TODO: I currently have no idea how implement that on BSDs / Windows, etc.
#ifdef __linux__

#include <signal.h>
#include <setjmp.h>

static sigjmp_buf lc_cpu_features_riscv_env;

static void lc_cpu_features_riscv_sigill_handler(int sig)
{
	(void)sig;
	siglongjmp(lc_cpu_features_riscv_env, 1);
}

/*
 * This function reliably detects the CSR 0x015 presence: It installs a
 * temporary signal handler for SIGILL and invokes the CSR. If a SIGILL is
 * seen, it performs a longjump to jump over the faulting CSR instruction
 * and returns that the feature is not implemented. Otherwise, when the CSR
 * suceeds, it returns that the ZKR extension is present.
 */
static inline enum lc_cpu_features lc_cpu_features_riscv_csrseed(void)
{
	struct sigaction old,
		sa = { .sa_handler = lc_cpu_features_riscv_sigill_handler };

	sigemptyset(&sa.sa_mask);
	sigaction(SIGILL, &sa, &old);

	if (sigsetjmp(lc_cpu_features_riscv_env, 1) == 0) {
		unsigned long value;

		asm volatile("csrr %0, 0x015" : "=r"(value));
		sigaction(SIGILL, &old, NULL);
		return LC_CPU_FEATURE_RISCV_ZKR;
	}

	sigaction(SIGILL, &old, NULL);
	return LC_CPU_FEATURE_NONE;
}

#else /* __linux__ */
static inline enum lc_cpu_features lc_cpu_features_riscv_csrseed(void)
{
	/*
	 * We just assume that ZKR is present - as otherwise the selection
	 * of enabling the CPU entropy source makes no sense.
	 */
	return LC_CPU_FEATURE_RISCV_ZKR;
}
#endif /* __linux__ */

static inline enum lc_cpu_features lc_cpu_features_riscv_common(void)
{
	enum lc_cpu_features tmp = LC_CPU_FEATURE_NONE;

	/*
	 * i-RISCV exports the presence of vesdrbg.v and vesdrbgseed.v via
	 * the DTS.
	 *
	 * TODO: I would not know how to check for that on other OSes.
	 */
	if (access("/proc/device-tree/cpus/cpu@0/chronox,es-drbg-seed-enabled",
		   F_OK) == 0)
		tmp |= LC_CPU_FEATURE_RISCV_VESDRBGSEED;
	if (access("/proc/device-tree/cpus/cpu@0/chronox,es-drbg-rand-enabled",
		   F_OK) == 0)
		tmp |= LC_CPU_FEATURE_RISCV_VESDRBG;

	tmp |= lc_cpu_features_riscv_csrseed();

	return tmp;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* CPUFEATURES_RISCV_H */
