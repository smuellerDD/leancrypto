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
 * git@github.com:dsprenkels/dilithium-cortexm.git
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

.syntax unified


// ##############################
// ##########   NTT    ##########
// ##############################

//CT butterfly with Montgomery reduction  -- SIGNED
.macro ct_butterfly_montg pol0, pol1, zeta, q, qinv, th, tl
  smull \tl, \th, \pol1, \zeta
  mul \pol1, \tl, \qinv  // q is -qinv
  smlal \tl, \th, \pol1, \q
  sub \pol1, \pol0, \th
  add \pol0, \pol0, \th
.endm

//void armv7_ntt_asm_smull(int32_t p[N], const uint32_t zetas_asm[N]);
SYM_FUNC_START(armv7_ntt_asm_smull)
SYM_FUNC_ENTER(armv7_ntt_asm_smull)
.align 2
  //bind aliases
  ptr_p     .req R0
  ptr_zeta  .req R1
  qinv      .req R2
  q         .req R3
  cntr      .req R4
  pol0      .req R5
  pol1      .req R6
  pol2      .req R7
  pol3      .req R8
  temp_h    .req R9
  temp_l    .req R10
  zeta0     .req R11
  zeta1     .req R12
  zeta2     .req R14

  //preserve registers
  push {R4-R11, R14}
  add ptr_zeta, #4
  //load constants, ptr
  ldr qinv, inv_ntt_asm_smull_qinv  //-qinv_signed
  ldr q, inv_ntt_asm_smull_q
  //stage 1 and 2
  ldr cntr, inv_ntt_asm_smull_64

  ldr zeta1, [ptr_zeta, #4]  //z2
  ldr zeta2, [ptr_zeta, #8]  //z3
  ldr zeta0, [ptr_zeta], #12  //z1
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #256]  //64*4
    ldr pol2, [ptr_p, #512]  //128*4
    ldr pol3, [ptr_p, #768]  //192*4
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage1
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage1
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage2
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage2

    str pol1, [ptr_p, #256]
    str pol2, [ptr_p, #512]
    str pol3, [ptr_p, #768]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  sub ptr_p, #256      // on pol0 again

  //stage 3 and 4
  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]  //z8
  ldr zeta2, [ptr_zeta, #8]  //z9
  ldr zeta0, [ptr_zeta], #12  //z4
  1:
    ldr pol0, [ptr_p]  //16*4
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage4
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4

    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, ptr_p, #192      //(64-16)*4

  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]  //z10
  ldr zeta2, [ptr_zeta, #8]  //z11
  ldr zeta0, [ptr_zeta], #12  //z5
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage4
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4

    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]  //(16*3-1)*4
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, ptr_p, #192      //(64-16)*4

  movw cntr, #16

  ldr zeta1, [ptr_zeta, #4]  //z12
  ldr zeta2, [ptr_zeta, #8]  //z13
  ldr zeta0, [ptr_zeta], #12  //z6
  1:
    ldr pol0, [ptr_p]  //16*4
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]  //(16*3)*4
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage4
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4
    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, #192      //(64-16)*4

  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]  //z14
  ldr zeta2, [ptr_zeta, #8]  //z15
  ldr zeta0, [ptr_zeta], #12  //z7
  1:
    ldr pol0, [ptr_p]  //16*4
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage3
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage4
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4
    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192] //(16*3-1)*4
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  sub ptr_p, #832      //(208)*4

  //stage 5 and 6
  movw cntr, #16
  1:
    ldr zeta1, [ptr_zeta, #4]  //z32, ..., z62
    ldr zeta2, [ptr_zeta, #8]  //z33, ..., z63
    ldr zeta0, [ptr_zeta], #12  //z16, ..., z31

    ldr pol0, [ptr_p]  //4*4
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]  //(4*3)*4
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage6
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]  //(4*3-1)*4
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage6
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p] //4*4
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage6
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48] //(4*3-1)*4
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p]  //4*4
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]  //(4*3)*4
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage5
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage6
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]
    str pol0, [ptr_p], #52

    subs cntr, cntr, #1
    bne 1b
  sub ptr_p, #1024      //256*4

  //stage 7 and 8
  mov cntr, #64
  1:

    ldr zeta1, [ptr_zeta, #4]  //z128,..., z254
    ldr zeta2, [ptr_zeta, #8]  //z129,..., z255
    ldr zeta0, [ptr_zeta], #12  //z64, ..., z127
    ldr pol0, [ptr_p]  //1*4
    ldr pol1, [ptr_p, #4]
    ldr pol2, [ptr_p, #8]
    ldr pol3, [ptr_p, #12]  //3*4
    ct_butterfly_montg pol0, pol2, zeta0, q, qinv, temp_h, temp_l  //stage7
    ct_butterfly_montg pol1, pol3, zeta0, q, qinv, temp_h, temp_l  //stage7
    ct_butterfly_montg pol0, pol1, zeta1, q, qinv, temp_h, temp_l  //stage8
    ct_butterfly_montg pol2, pol3, zeta2, q, qinv, temp_h, temp_l  //stage8

    str pol1, [ptr_p, #4]
    str pol2, [ptr_p, #8]
    str pol3, [ptr_p, #12]
    str pol0, [ptr_p], #16
    subs cntr, #1
    bne 1b

    //restore registers
    pop {R4-R11, PC}

    //unbind aliases
    .unreq ptr_p
    .unreq ptr_zeta
    .unreq qinv
    .unreq q
    .unreq cntr
    .unreq pol0
    .unreq pol1
    .unreq pol2
    .unreq pol3
    .unreq temp_h
    .unreq temp_l
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2

SYM_FUNC_END(armv7_ntt_asm_smull)

// ##############################
// ##########  NTT^-1  ##########
// ##############################

//GS butterfly with Montgomery reduction  -- SIGNED
.macro gs_butterfly_montg pol0, pol1, zeta, q, qinv, x, y
  sub \x, \pol0, \pol1  //sub \x, \x, \pol1
  add \pol0, \pol0, \pol1
  smull \y, \pol1, \x, \zeta //umull \y, \pol1, \x, \zeta
  mul \x, \y, \qinv  //qinv is -qinv
  smlal \y, \pol1, \x, \q //umlal \y, \pol1, \x, \q
.endm

// Montgomery reduction -- SIGNED
.macro montg_red f, pol, q, qinv, x, y
  smull \y, \pol, \pol, \f //umull \y, \pol, \pol, \f
  mul \x, \y, \qinv   //qinv is -qinv
  smlal \y, \pol, \x, \q //umlal \y, \pol, \x, \q
.endm

//void armv7_inv_ntt_asm_smull(int32_t p[N], const uint32_t zetas_inv_asm[N]);
SYM_FUNC_START(armv7_inv_ntt_asm_smull)
SYM_FUNC_ENTER(armv7_inv_ntt_asm_smull)
.align 2
  //bind aliases
  ptr_p     .req R0
  ptr_zeta  .req R1
  qinv      .req R2
  q         .req R3
  cntr      .req R4
  pol0      .req R5
  pol1      .req R6
  pol2      .req R7
  pol3      .req R8
  temp_h    .req R9
  temp_l    .req R10
  zeta0     .req R11
  zeta1     .req R12
  zeta2     .req R14

  //preserve registers
  push {R4-R11, R14}
  //load constants, ptr
  ldr qinv, inv_ntt_asm_smull_qinv  //-qinv_signed
  ldr q  , inv_ntt_asm_smull_q

  //stage 1 and 2
  ldr cntr, inv_ntt_asm_smull_64
  1:
    ldr zeta1, [ptr_zeta, #4]  //z1, ..., z127
    ldr zeta2, [ptr_zeta, #8]  //z128,.., z191
    ldr zeta0, [ptr_zeta], #12  //z0, ..., z126
    ldr pol0, [ptr_p]  //1*4
    ldr pol1, [ptr_p, #4]
    ldr pol2, [ptr_p, #8]
    ldr pol3, [ptr_p, #12]  //3*4
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage1
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage1
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage2
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage2
    str pol1, [ptr_p, #4]
    str pol2, [ptr_p, #8]
    str pol3, [ptr_p, #12]
    str pol0, [ptr_p], #16
    subs cntr, #1
    bne 1b
  sub ptr_p, #1024      // on pol0 again

  //stage 3 and 4
  movw cntr, #16
  1:
    ldr zeta1, [ptr_zeta, #4]
    ldr zeta2, [ptr_zeta, #8]
    ldr zeta0, [ptr_zeta], #12

    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage4
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage4
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage4
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4

    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48] //(4*3-1)*4
    str pol0, [ptr_p], #4

    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #16]
    ldr pol2, [ptr_p, #32]
    ldr pol3, [ptr_p, #48]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage3
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage4
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage4
    str pol1, [ptr_p, #16]
    str pol2, [ptr_p, #32]
    str pol3, [ptr_p, #48]
    str pol0, [ptr_p], #52
    subs cntr, cntr, #1
    bne 1b
  sub ptr_p, #1024      //256*4

  //stage 5 and 6
  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]
  ldr zeta2, [ptr_zeta, #8]
  ldr zeta0, [ptr_zeta], #12
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage6
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6

    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192] //(16*3-1)*4
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, #192      //(64-16)*4

  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]
  ldr zeta2, [ptr_zeta, #8]
  ldr zeta0, [ptr_zeta], #12
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage6
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6
    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, ptr_p, #192      //(64-16)*4

  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]
  ldr zeta2, [ptr_zeta, #8]
  ldr zeta0, [ptr_zeta], #12
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage6
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6
    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  add ptr_p, #192      //(64-16)*4

  movw cntr, #16
  ldr zeta1, [ptr_zeta, #4]
  ldr zeta2, [ptr_zeta, #8]
  ldr zeta0, [ptr_zeta], #12
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #64]
    ldr pol2, [ptr_p, #128]
    ldr pol3, [ptr_p, #192]
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage5
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage6
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage6
    str pol1, [ptr_p, #64]
    str pol2, [ptr_p, #128]
    str pol3, [ptr_p, #192]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b
  sub ptr_p, #832      //(208)*4

  //stage 7 and 8
  movw cntr, #64
  ldr zeta0, [ptr_zeta]
  ldr zeta1, [ptr_zeta, #4]
  ldr zeta2, [ptr_zeta, #8]
  ldr ptr_zeta, inv_ntt_asm_smull_f //ptr_zeta not needed anymore, contains now value f for final reduction
  1:
    ldr pol0, [ptr_p]
    ldr pol1, [ptr_p, #256]  //64*4
    ldr pol2, [ptr_p, #512]  //128*4
    ldr pol3, [ptr_p, #768]  //192*4
    gs_butterfly_montg pol0, pol1, zeta0, q, qinv, temp_h, temp_l  //stage7
    gs_butterfly_montg pol2, pol3, zeta1, q, qinv, temp_h, temp_l  //stage7
    gs_butterfly_montg pol0, pol2, zeta2, q, qinv, temp_h, temp_l  //stage8
    gs_butterfly_montg pol1, pol3, zeta2, q, qinv, temp_h, temp_l  //stage8
    montg_red ptr_zeta, pol0, q, qinv, temp_h, temp_l        //final reduction
    montg_red ptr_zeta, pol1, q, qinv, temp_h, temp_l        //final reduction

    // We can save the multiplication by f here by instead pre-computing it and putting it into the
    // twiddle factor of the previous butterfly
    // zeta2 is 3975713 instead of 8354570 (3975713 = (8354570 * 16382) % Q)

    //montg_red ptr_zeta, pol2, q, qinv, temp_h, temp_l        //final reduction
    //montg_red ptr_zeta, pol3, q, qinv, temp_h, temp_l        //final reduction
    str pol1, [ptr_p, #256]
    str pol2, [ptr_p, #512]
    str pol3, [ptr_p, #768]
    str pol0, [ptr_p], #4
    subs cntr, #1
    bne 1b

    //restore registers
    pop {R4-R11, PC}

    //unbind aliases
    .unreq ptr_p
    .unreq ptr_zeta
    .unreq qinv
    .unreq q
    .unreq cntr
    .unreq pol0
    .unreq pol1
    .unreq pol2
    .unreq pol3
    .unreq temp_h
    .unreq temp_l
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2

SYM_FUNC_END(armv7_inv_ntt_asm_smull)

.align 2
inv_ntt_asm_smull_f:
.word 41978
.align 2
inv_ntt_asm_smull_qinv:
.word 0xfc7fdfff
.align 2
inv_ntt_asm_smull_q:
.word 8380417
.align 2
inv_ntt_asm_smull_64:
.word 64
