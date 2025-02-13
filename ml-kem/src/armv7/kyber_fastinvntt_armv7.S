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

.macro montgomerym3 q, qinv, a, tmp
    mul.w \tmp, \a, \qinv
    sxth.w \tmp, \tmp
    mla.w \a, \tmp, \q, \a
    asr.w \a, \a, #16
.endm

.macro gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    sub.w \tmp, \poly0, \poly1
    add.w \poly0, \poly0, \poly1

    mul.w \poly1, \tmp, \twiddle
    montgomerym3 \q, \qinv, \poly1, \tmp
.endm

.macro fqmulprecompm3 a, twiddle, tmp,  q, qinv
    mul.w \a, \a, \twiddle
    montgomerym3 \q, \qinv, \a, \tmp
.endm

.macro signed_barrettm3 a, q, tmp, barrettconst
  mul.w \tmp, \a, \barrettconst
  // 2^26
  add.w \tmp, \tmp, #67108864
  asr.w \tmp, \tmp, #27
  mla.w \a, \tmp, \q, \a
.endm

SYM_FUNC_START(kyber_invntt_armv7)
SYM_FUNC_ENTER(kyber_invntt_armv7)
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
  montconst   .req r10
  barrettconst .req r10

  qinv        .req r14
  q           .req r11
  tmp         .req r12

  movw q, #3329
  movw qinv, #3327

  ### LAYER 1 (skip layer 0)
  movw tmp, #32
  1:
    push.w {tmp}

    ldrsh.w poly0, [poly,#0]
    ldrsh.w poly1, [poly,#2]
    ldrsh.w poly2, [poly,#4]
    ldrsh.w poly3, [poly,#6]
    ldrsh.w poly4, [poly,#8]
    ldrsh.w poly5, [poly,#10]
    ldrsh.w poly6, [poly,#12]
    ldrsh.w poly7, [poly,#14]

    ldrsh.w twiddle, [twiddle_ptr], #2
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr], #2
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv


    //-40318
    movw barrettconst, #25218
    sxth barrettconst, barrettconst
    signed_barrettm3 poly0, q, tmp, barrettconst
    signed_barrettm3 poly1, q, tmp, barrettconst
    signed_barrettm3 poly4, q, tmp, barrettconst
    signed_barrettm3 poly5, q, tmp, barrettconst

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
  bne.w 1b

  sub.w poly, #512

  ### LAYER 2+3+4
  movw tmp, #8
  2:
    push.w {tmp}

    .set k, 1
    .rept 4
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #8]
    ldrsh.w poly2, [poly, #16]
    ldrsh.w poly3, [poly, #24]
    ldrsh.w poly4, [poly, #32]
    ldrsh.w poly5, [poly, #40]
    ldrsh.w poly6, [poly, #48]
    ldrsh.w poly7, [poly, #56]

    ldrsh.w twiddle, [twiddle_ptr, #0]
    gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #2]
    gsbutterflym3 poly2, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #4]
    gsbutterflym3 poly4, poly5, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #6]
    gsbutterflym3 poly6, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #8]
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #10]
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #12]
    gsbutterflym3 poly0, poly4, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly5, twiddle, tmp, q, qinv
    gsbutterflym3 poly2, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly3, poly7, twiddle, tmp, q, qinv

    // TODO: I don't quite know why this does not work.
    //-40318
    //movw barrettconst, #25218
    //sxth barrettconst, barrettconst
    //signed_barrettm3 poly0, q, tmp, barrettconst
    //signed_barrettm3 poly1, q, tmp, barrettconst
    //signed_barrettm3 poly2, q, tmp, barrettconst
    //signed_barrettm3 poly3, q, tmp, barrettconst
    /* montgomery */
    movw montconst, #2285
    fqmulprecompm3 poly0, montconst, tmp, q, qinv
    fqmulprecompm3 poly1, montconst, tmp, q, qinv
    fqmulprecompm3 poly2, montconst, tmp, q, qinv
    fqmulprecompm3 poly3, montconst, tmp, q, qinv

    strh.w poly1, [poly,#8]
    strh.w poly2, [poly,#16]
    strh.w poly3, [poly,#24]
    strh.w poly4, [poly,#32]
    strh.w poly5, [poly,#40]
    strh.w poly6, [poly,#48]
    strh.w poly7, [poly,#56]
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
  sub poly, #512

  ### LAYER 5+6+7
  movw tmp, #32
  3:
    push.w {tmp}

    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #64]
    ldrsh.w poly2, [poly, #128]
    ldrsh.w poly3, [poly, #192]
    ldrsh.w poly4, [poly, #256]
    ldrsh.w poly5, [poly, #320]
    ldrsh.w poly6, [poly, #384]
    ldrsh.w poly7, [poly, #448]

    ldrsh.w twiddle, [twiddle_ptr]
    gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #2]
    gsbutterflym3 poly2, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #4]
    gsbutterflym3 poly4, poly5, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #6]
    gsbutterflym3 poly6, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #8]
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #10]
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #12]
    gsbutterflym3 poly0, poly4, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly5, twiddle, tmp, q, qinv
    gsbutterflym3 poly2, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly3, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #14]
    fqmulprecompm3 poly0, twiddle, tmp,  q, qinv
    fqmulprecompm3 poly1, twiddle, tmp,  q, qinv
    fqmulprecompm3 poly2, twiddle, tmp,  q, qinv
    fqmulprecompm3 poly3, twiddle, tmp,  q, qinv

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
  bne.w 3b
  pop.w {r4-r11, pc}

SYM_FUNC_END(kyber_invntt_armv7)

LC_ASM_END
