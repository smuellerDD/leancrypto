/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
#include "ext_headers_riscv.h"
#include "initialization.h"
#include "kyber_rvv_vlen_selector.h"
#include "visibility.h"

int kyber_rvv_selector(void);

static int lc_riscv_rvv_vlen = 0;

LC_CONSTRUCTOR(kyber_riscv_rvv_selector, LC_INIT_PRIO_ALGO)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV_ASM_RVV) {
		LC_VECTOR_ENABLE;
		lc_riscv_rvv_vlen = kyber_rvv_selector();
		LC_VECTOR_DISABLE;
	}
}

int lc_riscv_rvv_is_vlen128(void)
{
#ifdef LC_KYBER_RISCV_RVV_VLEN128
	return (lc_riscv_rvv_vlen == 8);
#else
	return 0;
#endif
}

int lc_riscv_rvv_is_vlen256(void)
{
#ifdef LC_KYBER_RISCV_RVV_VLEN256
	return (lc_riscv_rvv_vlen == 16);
#else
	return 0;
#endif
}
