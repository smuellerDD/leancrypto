/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/dilithium-coretexm/dilithium-cortexm.git
 *
 * author: Markus Krausz
 * date: 18.03.18
 *
 * Creative Commons Legal Code
 *
 * CC0 1.0 Universal
 *
 *   CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
 *   LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
 *   ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
 *   INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
 *   REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
 *   PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
 *   THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
 *   HEREUNDER.
 */

 #include "assembler_support.h"
#include "dilithium_type.h"

.syntax unified
.thumb

.macro montgomery_multiplication res, pa, pb, q, qinv
    smull \pa, \res, \pa, \pb
    mul \pb, \pa, \qinv
    smlal \pa, \res, \pb, \q
.endm

SYM_FUNC_START(armv7_poly_pointwise_invmontgomery_asm_smull)
SYM_FUNC_ENTER(armv7_poly_pointwise_invmontgomery_asm_smull)
.align 2
    push.w {r4-r11, r14}
    c_ptr .req r0
    a_ptr .req r1
    b_ptr .req r2
    qinv  .req r3
    q     .req r4
    pa0   .req r5
    pa1   .req r6
    pa2   .req r7
    pb0   .req r8
    pb1   .req r9
    pb2   .req r10
    tmp0  .req r11
    ctr   .req r12
    res   .req r14

    movw qinv, #:lower16:0xfc7fdfff
    movt qinv, #:upper16:0xfc7fdfff
    movw q, #0xE001
    movt q, #0x7F


    // 85x3 = 255 coefficients
    movw ctr, #85
    1:
        ldr.w pa1, [a_ptr, #4]
        ldr.w pa2, [a_ptr, #8]
        ldr pa0, [a_ptr], #12
        ldr.w pb1, [b_ptr, #4]
        ldr.w pb2, [b_ptr, #8]
        ldr pb0, [b_ptr], #12

        montgomery_multiplication res, pa0, pb0, q, qinv
        str res, [c_ptr], #4
        montgomery_multiplication res, pa1, pb1, q, qinv
        str res, [c_ptr], #4
        montgomery_multiplication res, pa2, pb2, q, qinv
        str res, [c_ptr], #4
    subs ctr, #1
    bne.w 1b

    // final coefficient
    ldr.w pa0, [a_ptr]
    ldr.w pb0, [b_ptr]
    montgomery_multiplication res, pa0, pb0, q, qinv
    str.w res, [c_ptr]

    pop.w {r4-r11, pc}

SYM_FUNC_END(armv7_poly_pointwise_invmontgomery_asm_smull)

SYM_FUNC_START(armv7_poly_pointwise_acc_invmontgomery_asm_smull)
SYM_FUNC_ENTER(armv7_poly_pointwise_acc_invmontgomery_asm_smull)
.align 2
    push.w {r4-r11, r14}
    c_ptr .req r0
    a_ptr .req r1
    b_ptr .req r2
    qinv  .req r3
    q     .req r4
    pa0   .req r5
    pa1   .req r6
    pa2   .req r7
    pb0   .req r8
    pb1   .req r9
    pb2   .req r10
    tmp0  .req r11
    ctr   .req r12
    res   .req r14

    movw qinv, #:lower16:0xfc7fdfff
    movt qinv, #:upper16:0xfc7fdfff
    movw q, #0xE001
    movt q, #0x7F


    // 85x3 = 255 coefficients
    movw ctr, #85
    1:
        ldr.w pa1, [a_ptr, #4]
        ldr.w pa2, [a_ptr, #8]
        ldr pa0, [a_ptr], #12
        ldr.w pb1, [b_ptr, #4]
        ldr.w pb2, [b_ptr, #8]
        ldr pb0, [b_ptr], #12

        montgomery_multiplication res, pa0, pb0, q, qinv
        montgomery_multiplication pa0, pa1, pb1, q, qinv
        montgomery_multiplication pa1, pa2, pb2, q, qinv

        ldr.w pb0, [c_ptr]
        ldr.w pb1, [c_ptr, #4]
        ldr.w pb2, [c_ptr, #8]
        add.w res, res, pb0
        str res, [c_ptr], #12
        add.w pa0, pa0, pb1
        str pa0, [c_ptr, #-8]
        add.w pa1, pa1, pb2
        str pa1, [c_ptr, #-4]
    subs ctr, #1
    bne.w 1b

    // final coefficient
    ldr.w pa0, [a_ptr]
    ldr.w pb0, [b_ptr]
    ldr.w pa1, [c_ptr]
    montgomery_multiplication res, pa0, pb0, q, qinv
    add.w res, res, pa1
    str.w res, [c_ptr]

    pop.w {r4-r11, pc}

SYM_FUNC_END(armv7_poly_pointwise_acc_invmontgomery_asm_smull)

ASM_END
