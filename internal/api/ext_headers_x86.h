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

#ifndef EXT_HEADERS_X86_H
#define EXT_HEADERS_X86_H

void lc_cpu_feature_get_cpuid(unsigned int cpuid[4]);

/*
 * When this define is enabled, the locally-provided x86intrin code is
 * used instead of the code from the compiler.
 */
//#undef LC_FORCE_LOCAL_X86_INTRINSICS

#if (defined(LINUX_KERNEL) || defined(LC_FORCE_LOCAL_X86_INTRINSICS))

#ifdef LINUX_KERNEL

/* Disable the restrict keyword */
#if __GNUC__ < 13
#define restrict
#endif

#include <linux/types.h>
#include <asm/fpu/api.h>

#define LC_FPU_ENABLE kernel_fpu_begin()
#define LC_FPU_DISABLE kernel_fpu_end()
#else
#define LC_FPU_ENABLE
#define LC_FPU_DISABLE
#endif /* LINUX_KERNEL */

#include "ext_x86_immintrin.h"

#else /* LINUX_KERNEL */

#include <immintrin.h>

#define LC_FPU_ENABLE
#define LC_FPU_DISABLE

#endif /* LINUX_KERNEL */

#endif /* EXT_HEADERS_X86_H */
