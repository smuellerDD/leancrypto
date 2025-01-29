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
#include "ext_headers.h"
#include "ext_headers_riscv.h"
#include "visibility.h"

static enum lc_cpu_features features = LC_CPU_FEATURE_UNSET;

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_disable, void)
{
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_enable, void)
{
}

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	if (features == LC_CPU_FEATURE_UNSET) {
		features = LC_CPU_FEATURE_RISCV;

#ifdef LINUX_KERNEL
		if (riscv_isa_extension_available(NULL, ZBB))
			features |= LC_CPU_FEATURE_RISCV_ASM_ZBB;
		if (riscv_isa_extension_available(NULL, ZVE64D) &&
		    may_use_simd())
			features |= LC_CPU_FEATURE_RISCV_ASM_RVV;
#endif
	}

	return features;
}
