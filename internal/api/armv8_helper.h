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

#ifndef ARMV8_HELPER_H
#define ARMV8_HELPER_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The ARMv8 Kyber implementation uses the SIMD registers v8 through v15 which
 * must be preserved by the callee.
 *
 * Store only the lower 64 bits of the FP registers v8 through v15 according to
 * https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#612simd-and-floating-point-registers
 */
static inline void store_fp_regs(uint64_t tmp[8])
{
	__asm__ volatile("mov %0, v8.d[0]" : "=r"(tmp[0]) : : "memory" );
	__asm__ volatile("mov %0, v9.d[0]" : "=r"(tmp[1]) : : "memory" );
	__asm__ volatile("mov %0, v10.d[0]" : "=r"(tmp[2]) : : "memory" );
	__asm__ volatile("mov %0, v11.d[0]" : "=r"(tmp[3]) : : "memory" );
	__asm__ volatile("mov %0, v12.d[0]" : "=r"(tmp[4]) : : "memory" );
	__asm__ volatile("mov %0, v13.d[0]" : "=r"(tmp[5]) : : "memory" );
	__asm__ volatile("mov %0, v14.d[0]" : "=r"(tmp[6]) : : "memory" );
	__asm__ volatile("mov %0, v15.d[0]" : "=r"(tmp[7]) : : "memory" );
}

/*
 * Reload the stored register content into the SIMD registers
 */
static inline void reload_fp_regs(uint64_t tmp[8])
{
	__asm__ volatile("mov v8.d[0], %0" : : "r"(tmp[0]) : "memory" );
	__asm__ volatile("mov v9.d[0], %0" : : "r"(tmp[1]) : "memory" );
	__asm__ volatile("mov v10.d[0], %0" : : "r"(tmp[2]) : "memory" );
	__asm__ volatile("mov v11.d[0], %0" : : "r"(tmp[3]) : "memory" );
	__asm__ volatile("mov v12.d[0], %0" : : "r"(tmp[4]) : "memory" );
	__asm__ volatile("mov v13.d[0], %0" : : "r"(tmp[5]) : "memory" );
	__asm__ volatile("mov v14.d[0], %0" : : "r"(tmp[6]) : "memory" );
	__asm__ volatile("mov v15.d[0], %0" : : "r"(tmp[7]) : "memory" );
}

#ifdef __cplusplus
}
#endif

#endif /* ARMV8_HELPER_H */
