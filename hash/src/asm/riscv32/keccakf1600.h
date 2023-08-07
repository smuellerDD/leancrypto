/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/AsmOptC-RiscV/Assembly-Optimized-C-RiscV
 *
 * That code is released under MIT license.
 */

#ifndef KECCAKF1600_H
#define KECCAKF1600_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reg {
	uint32_t a2;
	uint32_t a3;
	uint32_t a4;
	uint32_t a5;
	uint32_t a6;
	uint32_t a7;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;
	uint32_t t4;
	uint32_t t5;
	uint32_t t6;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t s4;
} reg;

extern void lc_keccakf1600_riscv(uint32_t *lanes);

#ifdef __cplusplus
}
#endif

#endif /* KECCAKF1600_H */
