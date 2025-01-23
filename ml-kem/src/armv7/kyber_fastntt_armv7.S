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

.macro butterflym3 a0, a1, twiddle, q, qinv, tmp
    mul.w \a1, \a1, \twiddle
    mul.w \tmp, \a1, \qinv
    sxth.w \tmp, \tmp
    mla.w \tmp, \tmp, \q, \a1
    sub.w \a1, \a0, \tmp, asr#16
    add.w \a0, \a0, \tmp, asr#16
.endm

.macro barrettm3 a, tmp, q, barrettconst
    mul.w \tmp, \a, \barrettconst
    asr.w \tmp, \tmp, #26
    mul.w \tmp, \tmp, \q
    sub.w \a, \a, \tmp
.endm

SYM_FUNC_START(kyber_ntt_armv7)
SYM_FUNC_ENTER(kyber_ntt_armv7)
.align 2
  push.w {r4-r11, r14}

  poly        .req r0
  twiddle_ptr .req r1
  poly0       .req r2
  poly1       .req r3
  poly2       .req r4
  poly3       .req r5
  poly4       .req r6
  poly5       .req r7
  poly6       .req r8
  poly7       .req r9
  twiddle     .req r10
  barrettconst .req r10
  qinv        .req r11
  q           .req r12
  tmp         .req r14

  .equ barrett_constant, 20159

  movw qinv, #3327
  movw q, #3329

  ### LAYER 7+6+5
  movw tmp, #32
  1:
    push.w {tmp}

    ldrsh.w poly0, [poly]
    ldrsh.w poly1, [poly, #64]
    ldrsh.w poly2, [poly, #128]
    ldrsh.w poly3, [poly, #192]
    ldrsh.w poly4, [poly, #256]
    ldrsh.w poly5, [poly, #320]
    ldrsh.w poly6, [poly, #384]
    ldrsh.w poly7, [poly, #448]

    ldrsh.w twiddle, [twiddle_ptr]
    butterflym3 poly0, poly4, twiddle, q, qinv, tmp
    butterflym3 poly1, poly5, twiddle, q, qinv, tmp
    butterflym3 poly2, poly6, twiddle, q, qinv, tmp
    butterflym3 poly3, poly7, twiddle, q, qinv, tmp

    ldrsh.w twiddle, [twiddle_ptr, #2]
    butterflym3 poly0, poly2, twiddle, q, qinv, tmp
    butterflym3 poly1, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #4]
    butterflym3 poly4, poly6, twiddle, q, qinv, tmp
    butterflym3 poly5, poly7, twiddle, q, qinv, tmp

    ldrsh.w twiddle, [twiddle_ptr, #6]
    butterflym3 poly0, poly1, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #8]
    butterflym3 poly2, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #10]
    butterflym3 poly4, poly5, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #12]
    butterflym3 poly6, poly7, twiddle, q, qinv, tmp

    strh.w poly1, [poly, #64]
    strh.w poly2, [poly, #128]
    strh.w poly3, [poly, #192]
    strh.w poly4, [poly, #256]
    strh.w poly5, [poly, #320]
    strh.w poly6, [poly, #384]
    strh.w poly7, [poly, #448]
    strh.w poly0, [poly], #2

    pop.w {tmp}
    subs.w tmp, #1
  bne.w 1b

  sub.w poly, #64
  add.w twiddle_ptr, #14

  ### LAYER 4+3+2
  movw tmp, #8
  2:
    push.w {tmp}

    .set k, 1
    .rept 4
      ldrsh.w poly0, [poly]
      ldrsh.w poly1, [poly, #8]
      ldrsh.w poly2, [poly, #16]
      ldrsh.w poly3, [poly, #24]
      ldrsh.w poly4, [poly, #32]
      ldrsh.w poly5, [poly, #40]
      ldrsh.w poly6, [poly, #48]
      ldrsh.w poly7, [poly, #56]

      ldrsh.w twiddle, [twiddle_ptr]
      butterflym3 poly0, poly4, twiddle, q, qinv, tmp
      butterflym3 poly1, poly5, twiddle, q, qinv, tmp
      butterflym3 poly2, poly6, twiddle, q, qinv, tmp
      butterflym3 poly3, poly7, twiddle, q, qinv, tmp

      ldrsh.w twiddle, [twiddle_ptr, #2]
      butterflym3 poly0, poly2, twiddle, q, qinv, tmp
      butterflym3 poly1, poly3, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #4]
      butterflym3 poly4, poly6, twiddle, q, qinv, tmp
      butterflym3 poly5, poly7, twiddle, q, qinv, tmp


      ldrsh.w twiddle, [twiddle_ptr, #6]
      butterflym3 poly0, poly1, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #8]
      butterflym3 poly2, poly3, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #10]
      butterflym3 poly4, poly5, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #12]
      butterflym3 poly6, poly7, twiddle, q, qinv, tmp

      strh.w poly1, [poly, #8]
      strh.w poly2, [poly, #16]
      strh.w poly3, [poly, #24]
      strh.w poly4, [poly, #32]
      strh.w poly5, [poly, #40]
      strh.w poly6, [poly, #48]
      strh.w poly7, [poly, #56]
      .if k != 4
      strh.w poly0, [poly], #2
      .else
      strh.w poly0, [poly], #58
      .endif
      .set k, k+1
    .endr
    add.w twiddle_ptr, #14

    pop.w {tmp}
    subs.w tmp, #1
  bne.w 2b

  sub.w poly, #512


  ### LAYER 1 (skip layer 0)
  movw tmp, #32
  4:
    push.w {tmp}

    ldrsh.w poly0, [poly]
    ldrsh.w poly1, [poly,#2]
    ldrsh.w poly2, [poly,#4]
    ldrsh.w poly3, [poly,#6]
    ldrsh.w poly4, [poly,#8]
    ldrsh.w poly5, [poly,#10]
    ldrsh.w poly6, [poly,#12]
    ldrsh.w poly7, [poly,#14]

    ldrsh.w twiddle, [twiddle_ptr], #2
    butterflym3 poly0, poly2, twiddle, q, qinv, tmp
    butterflym3 poly1, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr], #2
    butterflym3 poly4, poly6, twiddle, q, qinv, tmp
    butterflym3 poly5, poly7, twiddle, q, qinv, tmp

    movw barrettconst, #barrett_constant
    barrettm3 poly0, tmp, q, barrettconst
    barrettm3 poly1, tmp, q, barrettconst
    barrettm3 poly2, tmp, q, barrettconst
    barrettm3 poly3, tmp, q, barrettconst
    barrettm3 poly4, tmp, q, barrettconst
    barrettm3 poly5, tmp, q, barrettconst
    barrettm3 poly6, tmp, q, barrettconst
    barrettm3 poly7, tmp, q, barrettconst

    strh.w poly1, [poly,#2]
    strh.w poly2, [poly,#4]
    strh.w poly3, [poly,#6]
    strh.w poly4, [poly,#8]
    strh.w poly5, [poly,#10]
    strh.w poly6, [poly,#12]
    strh.w poly7, [poly,#14]
    strh.w poly0, [poly], #16

    pop.w {tmp}
    subs.w tmp, #1
  bne.w 4b
  pop.w {r4-r11, pc}

SYM_FUNC_END(kyber_ntt_armv7)
