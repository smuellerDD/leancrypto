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

#include "assembler_support.h"

/*
 * The vesdrbgseed.v is defined in the i-RISCV core (see https://i-riscv.org)
 *
 * 0xC6002077 is the instruction
 * vd occupies bits[11:7]: v0 -> 0x0; v1 -> 0x80; ...
 *
 * vesdrbgseed.v v0 -> 0xC6002077 | 0x0
 * vesdrbgseed.v v1 -> 0xC6002077 | 0x80
 * ...
 *
 * PTG.3 / RBG3(RS)
 */
/* void lc_riscv_vesdrbgseed(uint8_t *buffer) */
SYM_FUNC_START(lc_riscv_vesdrbgseed)
.align 2

	li t0, 4 /* Set this to any number <= 4 to return only the requested
		  * number of 64 bit chunks. */
	vsetvli t1, t0, e64, m1, ta, ma
	.word 0xC6002077   /* vesdrbgseed.v v0 */
	vse64.v v0, (a0)

	/* Zeroize the v0 - vsetvli unconditionally applies vl=VMAX */
	vsetvli t0, zero, e64, m1, ta, ma
	vmv.v.i v0, 0
SYM_FUNC_END(lc_riscv_vesdrbgseed)

/*
 * The vesdrbg.v is defined in the i-RISCV core (see https://i-riscv.org)
 *
 * 0xC2002077 is the instruction
 * vd occupies bits[11:7]: v0 -> 0x0; v1 -> 0x80; ...
 *
 * vesdrbg.v v0 -> 0xC2002077 | 0x0
 * vesdrbg.v v1 -> 0xC6002077 | 0x80
 * ...
 *
 * DRG.4/PTG.2 / RBG2(P)
 */
/* void lc_riscv_vesdrbg(uint8_t *buffer) */
SYM_FUNC_START(lc_riscv_vesdrbg)
.align 2
	li t0, 4 /* Only request 4 * 64 bits output - the rest of v0 is wasted,
		  * i.e. any subsequent call triggers a new 512 bit XDRBG
		  * generate */
	vsetvli t1, t0, e64, m1, ta, ma
	.word 0xC2002077   /* vesdrbg.v v0 */
	vse64.v v0, (a0)

	/* Zeroize the v0 - vsetvli unconditionally applies vl=VMAX */
	vsetvli t0, zero, e64, m1, ta, ma
	vmv.v.i v0, 0
SYM_FUNC_END(lc_riscv_vesdrbg)

LC_ASM_END
