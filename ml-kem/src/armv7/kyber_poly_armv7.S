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
#include "kyber_type.h"

.syntax unified
.thumb

.macro barrettm3 a, tmp, q, barrettconst
    mul.w \tmp, \a, \barrettconst
    asr.w \tmp, \tmp, #26
    mul.w \tmp, \tmp, \q
    sub.w \a, \a, \tmp
.endm

.macro montgomerym3 q, qinv, a, tmp
  mul.w \tmp, \a, \qinv
  sxth.w \tmp, \tmp
  mla.w \a, \tmp, \q, \a
  asr.w \a, \a, #16
.endm

SYM_FUNC_START(kyber_poly_sub_armv7)
SYM_FUNC_ENTER(kyber_poly_sub_armv7)
.align 2
  push.w {r4-r11, lr}

  movw r14, #51
  1:
    ldrsh.w r4, [r1, #2]
    ldrsh.w r5, [r1, #4]
    ldrsh.w r6, [r1, #6]
    ldrsh.w r7, [r1, #8]
    ldrsh.w r3, [r1], #10
    ldrsh.w r9, [r2, #2]
    ldrsh.w r10, [r2, #4]
    ldrsh.w r11, [r2, #6]
    ldrsh.w r12, [r2, #8]
    ldrsh.w r8, [r2], #10

    sub.w r3, r3, r8
    sub.w r4, r4, r9
    sub.w r5, r5, r10
    sub.w r6, r6, r11
    sub.w r7, r7, r12

    strh.w r4, [r0, #2]
    strh.w r5, [r0, #4]
    strh.w r6, [r0, #6]
    strh.w r7, [r0, #8]
    strh.w r3, [r0], #10
    subs.w r14, #1
  bne.w 1b

  ldrsh.w r3, [r1]
  ldrsh.w r4, [r2]
  sub.w r3, r3, r4
  strh.w r3, [r0]

  pop.w {r4-r11, pc}
SYM_FUNC_END(kyber_poly_sub_armv7)

SYM_FUNC_START(kyber_poly_add_armv7)
SYM_FUNC_ENTER(kyber_poly_add_armv7)
.align 2
  push.w {r4-r11, lr}
  movw.w r14, #51
  1:
    ldrsh.w r4, [r1, #2]
    ldrsh.w r5, [r1, #4]
    ldrsh.w r6, [r1, #6]
    ldrsh.w r7, [r1, #8]
    ldrsh.w r3, [r1], #10
    ldrsh.w r9, [r2, #2]
    ldrsh.w r10, [r2, #4]
    ldrsh.w r11, [r2, #6]
    ldrsh.w r12, [r2, #8]
    ldrsh.w r8, [r2], #10

    add.w r3, r3, r8
    add.w r4, r4, r9
    add.w r5, r5, r10
    add.w r6, r6, r11
    add.w r7, r7, r12

    strh.w r4, [r0, #2]
    strh.w r5, [r0, #4]
    strh.w r6, [r0, #6]
    strh.w r7, [r0, #8]
    strh.w r3, [r0], #10
    subs.w r14, #1
  bne.w 1b

  ldrsh.w r3, [r1]
  ldrsh.w r4, [r2]
  add.w r3, r3, r4
  strh.w r3, [r0]
  pop.w {r4-r11, pc}
SYM_FUNC_END(kyber_poly_add_armv7)

SYM_FUNC_START(kyber_barrett_reduce_armv7)
SYM_FUNC_ENTER(kyber_barrett_reduce_armv7)
.align 2
  push.w    {r4-r11, r14}

  poly        .req r0
  poly0       .req r1
  poly1       .req r2
  poly2       .req r3
  poly3       .req r4
  poly4       .req r5
  poly5       .req r6
  poly6       .req r7
  poly7       .req r8
  poly8       .req r14
  loop        .req r9
  barrettconst .req r10
  q           .req r11
  tmp         .req r12

  movw barrettconst, #20159
  movw q, #3329

  movw loop, #28
  1:
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    ldrsh.w poly4, [poly, #8]
    ldrsh.w poly5, [poly, #10]
    ldrsh.w poly6, [poly, #12]
    ldrsh.w poly7, [poly, #14]
    ldrsh.w poly8, [poly, #16]

    barrettm3 poly0, tmp, q, barrettconst
    barrettm3 poly1, tmp, q, barrettconst
    barrettm3 poly2, tmp, q, barrettconst
    barrettm3 poly3, tmp, q, barrettconst
    barrettm3 poly4, tmp, q, barrettconst
    barrettm3 poly5, tmp, q, barrettconst
    barrettm3 poly6, tmp, q, barrettconst
    barrettm3 poly7, tmp, q, barrettconst
    barrettm3 poly8, tmp, q, barrettconst

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly4, [poly, #8]
    strh.w poly5, [poly, #10]
    strh.w poly6, [poly, #12]
    strh.w poly7, [poly, #14]
    strh.w poly8, [poly, #16]
    strh.w poly0, [poly], #18
    subs.w loop, #1
  bne.w 1b

  ldrsh.w poly0, [poly, #0]
  ldrsh.w poly1, [poly, #2]
  ldrsh.w poly2, [poly, #4]
  ldrsh.w poly3, [poly, #6]
  barrettm3 poly0, tmp, q, barrettconst
  barrettm3 poly1, tmp, q, barrettconst
  barrettm3 poly2, tmp, q, barrettconst
  barrettm3 poly3, tmp, q, barrettconst
  strh.w poly0, [poly, #0]
  strh.w poly1, [poly, #2]
  strh.w poly2, [poly, #4]
  strh.w poly3, [poly, #6]
  pop.w     {r4-r11, pc}

  .unreq poly0
  .unreq poly1
  .unreq poly2
  .unreq poly3
  .unreq q
  .unreq tmp
  .unreq loop
SYM_FUNC_END(kyber_barrett_reduce_armv7)

SYM_FUNC_START(kyber_basemul_armv7)
SYM_FUNC_ENTER(kyber_basemul_armv7)
.align 2
    push.w {r4-r11, lr}

    rptr    .req r0
    aptr    .req r1
    bptr    .req r2
    zetaptr .req r3
    poly0   .req r4
    poly1   .req r6
    poly2   .req r5
    poly3   .req r7
    q       .req r8
    qinv    .req r11
    tmp     .req r9
    tmp2    .req r10
    zeta    .req r12
    loop    .req r14

    movw q, #3329
    movw qinv, #3327

    movw loop, #64
    1:
      ldrsh.w zeta, [zetaptr], #2

      ldrsh.w poly1, [aptr,  #2]
      ldrsh.w poly0, [aptr], #4
      ldrsh.w poly3, [bptr, #2]
      ldrsh.w poly2, [bptr], #4

      mul.w tmp, poly1, poly3
      montgomerym3 q, qinv, tmp, tmp2
      mul.w tmp, tmp, zeta
      mla.w tmp, poly0, poly2, tmp
      montgomerym3 q, qinv, tmp, tmp2
      strh.w tmp, [rptr], #2

      mul.w tmp, poly0, poly3
      mla.w tmp, poly1, poly2, tmp
      montgomerym3 q, qinv, tmp, tmp2
      strh.w tmp, [rptr], #2

      neg.w zeta, zeta

      ldrsh.w poly1, [aptr,  #2]
      ldrsh.w poly0, [aptr], #4
      ldrsh.w poly3, [bptr, #2]
      ldrsh.w poly2, [bptr], #4

      mul.w tmp, poly1, poly3
      montgomerym3 q, qinv, tmp, tmp2
      mul.w tmp, tmp, zeta
      mla.w tmp, poly0, poly2, tmp
      montgomerym3 q, qinv, tmp, tmp2
      strh.w tmp, [rptr], #2

      mul.w tmp, poly0, poly3
      mla.w tmp, poly1, poly2, tmp
      montgomerym3 q, qinv, tmp, tmp2
      strh.w tmp, [rptr], #2

      subs.w loop, #1
    bne.w 1b

    pop.w {r4-r11, pc}

.unreq qinv
SYM_FUNC_END(kyber_basemul_armv7)

LC_ASM_END
