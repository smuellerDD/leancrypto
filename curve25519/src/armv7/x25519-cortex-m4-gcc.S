/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This file is dervied from https://github.com/Emill/X25519-AArch64 which uses
 * the following license.
 */
// Curve25519 scalar multiplication
// Copyright (c) 2017, Emil Lenngren
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form, except as embedded into a Nordic
//    Semiconductor ASA or Dialog Semiconductor PLC integrated circuit in a product
//    or a software update for such product, must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This is an armv7 implementation of X25519.
// It follows the reference implementation where the representation of
// a field element [0..2^255-19) is represented by a 256-bit little ian integer,
// reduced modulo 2^256-38, and may possibly be in the range [2^256-38..2^256).
// The scalar is a 256-bit integer where certain bits are hardcoded per specification.
//
// The implementation runs in constant time (548 873 cycles on ARM Cortex-M4,
// assuming no wait states), and no conditional branches or memory access
// pattern dep on secret data.

#include "assembler_support.h"

	.syntax unified
	.thumb

	.text
	.align 2

// input: *r8=a, *r9=b
// output: r0-r7
// clobbers all other registers
// cycles: 45
SYM_FUNC_START(fe25519_add)
SYM_FUNC_ENTER(fe25519_add)
	ldr r0,[r8,#28]
	ldr r4,[r9,#28]
	adds r0,r0,r4
	mov r11,#0
	adc r11,r11,r11
	lsl r11,r11,#1
	add r11,r11,r0, lsr #31
	movs r7,#19
	mul r11,r11,r7
	bic r7,r0,#0x80000000
	
	ldm r8!,{r0-r3}
	ldm r9!,{r4-r6,r10}
	mov r12,#1
	umaal r0,r11,r12,r4
	umaal r1,r11,r12,r5
	umaal r2,r11,r12,r6
	umaal r3,r11,r12,r10
	ldm r9,{r4-r6}
	ldm r8,{r8-r10}
	umaal r4,r11,r12,r8
	umaal r5,r11,r12,r9
	umaal r6,r11,r12,r10
	add r7,r7,r11
	bx lr
SYM_FUNC_END(fe25519_add)

// input: *r8=a, *r9=b
// output: r0-r7
// clobbers all other registers
// cycles: 46
SYM_FUNC_START(fe25519_sub)
SYM_FUNC_ENTER(fe25519_sub)
	ldm r8,{r0-r7}
	ldm r9!,{r8,r10-r12}
	subs r0,r8
	sbcs r1,r10
	sbcs r2,r11
	sbcs r3,r12
	ldm r9,{r8-r11}
	sbcs r4,r8
	sbcs r5,r9
	sbcs r6,r10
	sbcs r7,r11
	
	// if subtraction goes below 0, set r8 to -1 and r9 to -38, else set both to 0
	sbc r8,r8
	and r9,r8,#-38
	
	adds r0,r9
	adcs r1,r8
	adcs r2,r8
	adcs r3,r8
	adcs r4,r8
	adcs r5,r8
	adcs r6,r8
	adcs r7,r8
	
	// if the subtraction did not go below 0, we are done and (r8,r9) are set to 0
	// if the subtraction went below 0 and the addition overflowed, we are done, so set (r8,r9) to 0
	// if the subtraction went below 0 and the addition did not overflow, we need to add once more
	// (r8,r9) will be correctly set to (-1,-38) only when r8 was -1 and we don't have a carry,
	// note that the carry will always be 0 in case (r8,r9) was (0,0) since then there was no real addition
	// also note that it is extremely unlikely we will need an extra addition:
	//   that can only happen if input1 was slightly >= 0 and input2 was > 2^256-38 (really input2-input1 > 2^256-38)
	//   in that case we currently have 2^256-38 < (r0...r7) < 2^256, so adding -38 will only affect r0
	adcs r8,#0
	and r9,r8,#-38
	
	adds r0,r9
	
	bx lr
SYM_FUNC_END(fe25519_sub)

// input: *r1=a, *r2=b
// output: r0-r7
// clobbers all other registers
// cycles: 173
SYM_FUNC_START(fe25519_mul)
SYM_FUNC_ENTER(fe25519_mul)
	push {r2,lr}
	//frame push {lr}
	//frame address sp,8
	
	sub sp,#28
	//frame address sp,36
	ldm r2,{r2,r3,r4,r5}
	
	ldm r1!,{r0,r10,lr}
	umull r6,r11,r2,r0
	
	umull r7,r12,r3,r0
	umaal r7,r11,r2,r10
	
	push {r6,r7}
	//frame address sp,44
	
	umull r8,r6,r4,r0
	umaal r8,r11,r3,r10
	
	umull r9,r7,r5,r0
	umaal r9,r11,r4,r10
	
	umaal r11,r7,r5,r10
	
	umaal r8,r12,r2,lr
	umaal r9,r12,r3,lr
	umaal r11,r12,r4,lr
	umaal r12,r7,r5,lr
	
	ldm r1!,{r0,r10,lr}
	
	umaal r9,r6,r2,r0
	umaal r11,r6,r3,r0
	umaal r12,r6,r4,r0
	umaal r6,r7,r5,r0
	
	strd r8,r9,[sp,#8]
	
	mov r9,#0
	umaal r11,r9,r2,r10
	umaal r12,r9,r3,r10
	umaal r6,r9,r4,r10
	umaal r7,r9,r5,r10
	
	mov r10,#0
	umaal r12,r10,r2,lr
	umaal r6,r10,r3,lr
	umaal r7,r10,r4,lr
	umaal r9,r10,r5,lr
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal lr,r6,r2,r8
	umaal r7,r6,r3,r8
	umaal r9,r6,r4,r8
	umaal r10,r6,r5,r8
	
	//_ _ _ _ _ 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r8,[r1],#-28
	mov r0,#0
	umaal r7,r0,r2,r8
	umaal r9,r0,r3,r8
	umaal r10,r0,r4,r8
	umaal r6,r0,r5,r8
	
	push {r0}
	//frame address sp,48
	
	//_ _ _ _ s 6 10 9| 7 | lr 12 11 _ _ _ _
	
	ldr r2,[sp,#40]
	adds r2,r2,#16
	ldm r2,{r2,r3,r4,r5}
	
	ldr r8,[r1],#4
	mov r0,#0
	umaal r11,r0,r2,r8
	str r11,[sp,#16+4]
	umaal r12,r0,r3,r8
	umaal lr,r0,r4,r8
	umaal r0,r7,r5,r8 // 7=carry for 9
	
	//_ _ _ _ s 6 10 9+7| 0 | lr 12 _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r11,#0
	umaal r12,r11,r2,r8
	str r12,[sp,#20+4]
	umaal lr,r11,r3,r8
	umaal r0,r11,r4,r8
	umaal r11,r7,r5,r8 // 7=carry for 10
	
	//_ _ _ _ s 6 10+7 9+11| 0 | lr _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov r12,#0
	umaal lr,r12,r2,r8
	str lr,[sp,#24+4]
	umaal r0,r12,r3,r8
	umaal r11,r12,r4,r8
	umaal r10,r12,r5,r8 // 12=carry for 6
	
	//_ _ _ _ s 6+12 10+7 9+11| 0 | _ _ _ _ _ _ _
	
	ldr r8,[r1],#4
	mov lr,#0
	umaal r0,lr,r2,r8
	str r0,[sp,#28+4]
	umaal r11,lr,r3,r8
	umaal r10,lr,r4,r8
	umaal r6,lr,r5,r8 // lr=carry for saved
	
	//_ _ _ _ s+lr 6+12 10+7 9+11| _ | _ _ _ _ _ _ _
	
	ldm r1!,{r0,r8}
	umaal r11,r9,r2,r0
	str r11,[sp,#32+4]
	umaal r9,r10,r3,r0
	umaal r10,r6,r4,r0
	pop {r11}
	//frame address sp,44
	umaal r11,r6,r5,r0 // 6=carry for next
	
	//_ _ _ 6 11+lr 10+12 9+7 _ | _ | _ _ _ _ _ _ _
	
	umaal r9,r7,r2,r8
	umaal r10,r7,r3,r8
	umaal r11,r7,r4,r8
	umaal r6,r7,r5,r8
	
	ldm r1!,{r0,r8}
	umaal r10,r12,r2,r0
	umaal r11,r12,r3,r0
	umaal r6,r12,r4,r0
	umaal r7,r12,r5,r0
	
	umaal r11,lr,r2,r8
	umaal r6,lr,r3,r8
	umaal lr,r7,r4,r8
	umaal r7,r12,r5,r8
	
	// 12 7 lr 6 11 10 9 stack*9
	
	//now reduce
	
	ldrd r4,r5,[sp,#28]
	movs r3,#38
	mov r8,#0
	umaal r4,r8,r3,r12
	lsl r8,r8,#1
	orr r8,r8,r4, lsr #31
	and r12,r4,#0x7fffffff
	movs r4,#19
	mul r8,r8,r4
	
	pop {r0-r2}
	//frame address sp,32
	umaal r0,r8,r3,r5
	umaal r1,r8,r3,r9
	umaal r2,r8,r3,r10
	mov r9,#38
	pop {r3,r4}
	//frame address sp,24
	umaal r3,r8,r9,r11
	umaal r4,r8,r9,r6
	pop {r5,r6}
	//frame address sp,16
	umaal r5,r8,r9,lr
	umaal r6,r8,r9,r7
	add r7,r8,r12
	
	add sp,#12
	//frame address sp,4
	pop {pc}
SYM_FUNC_END(fe25519_mul)

// input/result in (r0-r7)
// clobbers all other registers
// cycles: 115
SYM_FUNC_START(fe25519_sqr)
SYM_FUNC_ENTER(fe25519_sqr)
	push {lr}
	//frame push {lr}
	sub sp,#20
	//frame address sp,24
	
	//mul 01, 00
	umull r9,r10,r0,r0
	umull r11,r12,r0,r1
	adds r11,r11,r11
	mov lr,#0
	umaal r10,r11,lr,lr
	
	//r9 r10 done
	//r12 carry for 3rd before col
	//r11+C carry for 3rd final col
	
	push {r9,r10}
	//frame address sp,32
	
	//mul 02, 11
	mov r8,#0
	umaal r8,r12,r0,r2
	adcs r8,r8,r8
	umaal r8,r11,r1,r1
	
	//r8 done (3rd col)
	//r12 carry for 4th before col
	//r11+C carry for 4th final col
	
	//mul 03, 12
	umull r9,r10,r0,r3
	umaal r9,r12,r1,r2
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (4th col)
	//r10+r12 carry for 5th before col
	//r11+C carry for 5th final col
	
	strd r8,r9,[sp,#8]
	
	//mul 04, 13, 22
	mov r9,#0
	umaal r9,r10,r0,r4
	umaal r9,r12,r1,r3
	adcs r9,r9,r9
	umaal r9,r11,r2,r2
	
	//r9 done (5th col)
	//r10+r12 carry for 6th before col
	//r11+C carry for 6th final col
	
	str r9,[sp,#16]
	
	//mul 05, 14, 23
	umull r9,r8,r0,r5
	umaal r9,r10,r1,r4
	umaal r9,r12,r2,r3
	adcs r9,r9,r9
	umaal r9,r11,lr,lr
	
	//r9 done (6th col)
	//r10+r12+r8 carry for 7th before col
	//r11+C carry for 7th final col
	
	str r9,[sp,#20]
	
	//mul 06, 15, 24, 33
	mov r9,#0
	umaal r9,r8,r1,r5
	umaal r9,r12,r2,r4
	umaal r9,r10,r0,r6
	adcs r9,r9,r9
	umaal r9,r11,r3,r3
	
	//r9 done (7th col)
	//r8+r10+r12 carry for 8th before col
	//r11+C carry for 8th final col
	
	str r9,[sp,#24]
	
	//mul 07, 16, 25, 34
	umull r0,r9,r0,r7
	umaal r0,r10,r1,r6
	umaal r0,r12,r2,r5
	umaal r0,r8,r3,r4
	adcs r0,r0,r0
	umaal r0,r11,lr,lr
	
	//r0 done (8th col)
	//r9+r8+r10+r12 carry for 9th before col
	//r11+C carry for 9th final col
	
	//mul 17, 26, 35, 44
	umaal r9,r8,r1,r7 //r1 is now dead
	umaal r9,r10,r2,r6
	umaal r12,r9,r3,r5
	adcs r12,r12,r12
	umaal r11,r12,r4,r4
	
	//r11 done (9th col)
	//r8+r10+r9 carry for 10th before col
	//r12+C carry for 10th final col
	
	//mul 27, 36, 45
	umaal r9,r8,r2,r7 //r2 is now dead
	umaal r10,r9,r3,r6
	movs r2,#0
	umaal r10,r2,r4,r5
	adcs r10,r10,r10
	umaal r12,r10,lr,lr
	
	//r12 done (10th col)
	//r8+r9+r2 carry for 11th before col
	//r10+C carry for 11th final col
	
	//mul 37, 46, 55
	umaal r2,r8,r3,r7 //r3 is now dead
	umaal r9,r2,r4,r6
	adcs r9,r9,r9
	umaal r10,r9,r5,r5
	
	//r10 done (11th col)
	//r8+r2 carry for 12th before col
	//r9+C carry for 12th final col
	
	//mul 47, 56
	movs r3,#0
	umaal r3,r8,r4,r7 //r4 is now dead
	umaal r3,r2,r5,r6
	adcs r3,r3,r3
	umaal r9,r3,lr,lr
	
	//r9 done (12th col)
	//r8+r2 carry for 13th before col
	//r3+C carry for 13th final col
	
	//mul 57, 66
	umaal r8,r2,r5,r7 //r5 is now dead
	adcs r8,r8,r8
	umaal r3,r8,r6,r6
	
	//r3 done (13th col)
	//r2 carry for 14th before col
	//r8+C carry for 14th final col
	
	//mul 67
	umull r4,r5,lr,lr // set 0
	umaal r4,r2,r6,r7
	adcs r4,r4,r4
	umaal r4,r8,lr,lr
	
	//r4 done (14th col)
	//r2 carry for 15th before col
	//r8+C carry for 15th final col
	
	//mul 77
	adcs r2,r2,r2
	umaal r8,r2,r7,r7
	adcs r2,r2,lr
	
	//r8 done (15th col)
	//r2 done (16th col)
	
	//msb -> lsb: r2 r8 r4 r3 r9 r10 r12 r11 r0 sp+24 sp+20 sp+16 sp+12 sp+8 sp+4 sp
	//lr: 0
	//now do reduction
	
	mov r6,#38
	umaal r0,lr,r6,r2
	lsl lr,lr,#1
	orr lr,lr,r0, lsr #31
	and r7,r0,#0x7fffffff
	movs r5,#19
	mul lr,lr,r5
	
	pop {r0,r1}
	//frame address sp,24
	umaal r0,lr,r6,r11
	umaal r1,lr,r6,r12
	
	mov r11,r3
	mov r12,r4
	
	pop {r2,r3,r4,r5}
	//frame address sp,8
	umaal r2,lr,r6,r10
	umaal r3,lr,r6,r9
	
	umaal r4,lr,r6,r11
	umaal r5,lr,r6,r12
	
	pop {r6}
	//frame address sp,4
	mov r12,#38
	umaal r6,lr,r12,r8
	add r7,r7,lr
	
	pop {pc}
SYM_FUNC_END(fe25519_sqr)


// in: r0-r7, count: r8
// out: r0-r7 + sets result also to top of stack
// clobbers all other registers
// cycles: 19 + 123*n
SYM_FUNC_START(fe25519_sqr_many)
SYM_FUNC_ENTER(fe25519_sqr_many)
	push {r8,lr}
	//frame push {r8,lr}
0:
	bl fe25519_sqr
	
	ldr r8,[sp,#0]
	subs r8,r8,#1
	str r8,[sp,#0]
	bne 0b
	
	add sp,sp,#4
	//frame address sp,4
	add r8,sp,#4
	stm r8,{r0-r7}
	pop {pc}
SYM_FUNC_END(fe25519_sqr_many)

// This kind of load supports unaligned access
// in: *r1
// out: r0-r7
// cycles: 22
	.type loadm, %function
loadm:
	ldr r0,[r1,#0]
	ldr r2,[r1,#8]
	ldr r3,[r1,#12]
	ldr r4,[r1,#16]
	ldr r5,[r1,#20]
	ldr r6,[r1,#24]
	ldr r7,[r1,#28]
	ldr r1,[r1,#4]
	bx lr
	.size loadm, .-loadm

// in: *r0 = result, *r1 = scalar, *r2 = basepoint (all pointers may be unaligned)
// cycles: 548 873
SYM_FUNC_START(crypto_scalarmult_curve25519_armv7)
SYM_FUNC_ENTER(crypto_scalarmult_curve25519_armv7)
	
	// stack layout: xp zp xq zq x0  bitpos lastbit scalar result_ptr r4-r11,lr
	//               0  32 64 96 128 160    164     168    200        204

	push {r0,r4-r11,lr}
	//frame push {r4-r11,lr}
	//frame address sp,40
	
	mov r10,r2
	bl loadm
	
	and r0,r0,#0xfffffff8
	//and r7,r7,#0x7fffffff not needed since we don't inspect the msb anyway
	orr r7,r7,#0x40000000
	push {r0-r7}
	//frame address sp,72
	movs r8,#0
	push {r2,r8}
	//frame address sp,80
	
	//ldm r1,{r0-r7}
	mov r1,r10
	bl loadm
	
	and r7,r7,#0x7fffffff
	push {r0-r7}
	//frame address sp,112
	
	movs r9,#1
	umull r10,r11,r8,r8
	mov r12,#0
	push {r8,r10,r11,r12}
	//frame address sp,128
	push {r9,r10,r11,r12}
	//frame address sp,144
	
	push {r0-r7}
	//frame address sp,176
	
	umull r6,r7,r8,r8
	push {r6,r7,r8,r10,r11,r12}
	//frame address sp,200
	push {r6,r7,r8,r10,r11,r12}
	//frame address sp,224
	push {r9,r10,r11,r12}
	//frame address sp,240
	
	movs r0,#254
	movs r3,#0
	// 129 cycles so far
0:
	// load scalar bit into r1
	lsrs r1,r0,#5
	adds r2,sp,#168
	ldr r1,[r2,r1,lsl #2]
	and r4,r0,#0x1f
	lsrs r1,r1,r4
	and r1,r1,#1
	
	strd r0,r1,[sp,#160]
	
	eors r1,r1,r3
	rsbs lr,r1,#0
	
	mov r0,sp
	add r1,sp,#64
	
	mov r11,#4
	// 15 cycles
1:
	ldm r0,{r2-r5}
	ldm r1,{r6-r9}
	
	eors r2,r2,r6
	and r10,r2,lr
	eors r6,r6,r10
	eors r2,r2,r6
	
	eors r3,r3,r7
	and r10,r3,lr
	eors r7,r7,r10
	eors r3,r3,r7
	
	eors r4,r4,r8
	and r10,r4,lr
	eors r8,r8,r10
	eors r4,r4,r8
	
	eors r5,r5,r9
	and r10,r5,lr
	eors r9,r9,r10
	eors r5,r5,r9
	
	stm r0!,{r2-r5}
	stm r1!,{r6-r9}
	
	subs r11,#1
	bne 1b
	// 40*4 - 2 = 158 cycles
	
	mov r8,sp
	add r9,sp,#32
	bl fe25519_add
	push {r0-r7}
	//frame address sp,272
	
	bl fe25519_sqr
	push {r0-r7}
	//frame address sp,304
	
	add r8,sp,#64
	add r9,sp,#96
	bl fe25519_sub
	push {r0-r7}
	//frame address sp,336
	
	bl fe25519_sqr
	push {r0-r7}
	//frame address sp,368
	
	mov r1,sp
	add r2,sp,#64
	bl fe25519_mul
	add r8,sp,#128
	stm r8,{r0-r7}
	
	add r8,sp,#64
	mov r9,sp
	bl fe25519_sub
	add r8,sp,#64
	stm r8,{r0-r7}
	
	// 64 + 1*45 + 2*46 + 1*173 + 2*115 = 604 cycles
	
	//multiplies (r0-r7) with 121666, adds *sp and puts the result on the top of the stack (replacing old content)
	ldr lr,=121666
	//mov lr,#56130
	//add lr,lr,#65536
	ldr r12,[sp,#28]
	mov r11,#0
	umaal r12,r11,lr,r7
	lsl r11,r11,#1
	add r11,r11,r12, lsr #31
	movs r7,#19
	mul r11,r11,r7
	bic r7,r12,#0x80000000
	ldm sp!,{r8,r9,r10,r12}
	//frame address sp,352
	umaal r8,r11,lr,r0
	umaal r9,r11,lr,r1
	umaal r10,r11,lr,r2
	umaal r12,r11,lr,r3
	ldm sp!,{r0,r1,r2}
	//frame address sp,340
	umaal r0,r11,lr,r4
	umaal r1,r11,lr,r5
	umaal r2,r11,lr,r6
	add r7,r7,r11
	add sp,sp,#4
	//frame address sp,338
	push {r0,r1,r2,r7}
	//frame address sp,352
	push {r8,r9,r10,r12}
	//frame address sp,368
	// 39 cycles
	
	mov r1,sp
	add r2,sp,#64
	bl fe25519_mul
	add r8,sp,#160
	stm r8,{r0-r7}
	
	add r8,sp,#192
	add r9,sp,#224
	bl fe25519_add
	stm sp,{r0-r7}
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add r8,sp,#32
	stm r8,{r0-r7}
	
	add r8,sp,#192
	add r9,sp,#224
	bl fe25519_sub
	stm sp,{r0-r7}
	
	mov r1,sp
	add r2,sp,#96
	bl fe25519_mul
	stm sp,{r0-r7}
	
	mov r8,sp
	add r9,sp,#32
	bl fe25519_add
	
	bl fe25519_sqr
	
	add r8,sp,#192
	stm r8,{r0-r7}
	
	mov r8,sp
	add r9,sp,#32
	bl fe25519_sub
	
	bl fe25519_sqr
	stm sp,{r0-r7}
	
	mov r1,sp
	add r2,sp,#256
	bl fe25519_mul
	add r8,sp,#224
	stm r8,{r0-r7}
	
	add sp,sp,#128
	//frame address sp,240
	
	ldrd r2,r3,[sp,#160]
	subs r0,r2,#1
	// 97 + 2*45 + 2*46 + 4*173 + 2*115 = 1201 cycles
	bpl 0b
	// in total 2020 cycles per iteration, in total 515 098 cycles for 255 iterations

	//These cswap lines are not needed for curve25519 since the lowest bit is hardcoded to 0
	//----------
	//rsbs lr,r3,#0
	
	//mov r0,sp
	//add r1,sp,#64
	
	//mov r11,#4
//1
	//ldm r0,{r2-r5}
	//ldm r1!,{r6-r9}
	
	//eors r2,r2,r6
	//and r10,r2,lr
	//eors r6,r6,r10
	//eors r2,r2,r6
	
	//eors r3,r3,r7
	//and r10,r3,lr
	//eors r7,r7,r10
	//eors r3,r3,r7
	
	//eors r4,r4,r8
	//and r10,r4,lr
	//eors r8,r8,r10
	//eors r4,r4,r8
	
	//eors r5,r5,r9
	//and r10,r5,lr
	//eors r9,r9,r10
	//eors r5,r5,r9
	
	//stm r0!,{r2-r5}
	
	//subs r11,#1
	//bne 1b
	//----------

	// now we must invert zp
	add r0,sp,#32
	ldm r0,{r0-r7}
	bl fe25519_sqr
	push {r0-r7}
	//frame address sp,272
	
	bl fe25519_sqr
	bl fe25519_sqr
	push {r0-r7}
	//frame address sp,304
	
	add r1,sp,#96
	mov r2,sp
	bl fe25519_mul
	stm sp,{r0-r7}
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// current stack: z^(2^9) z^(2^11) x z
	
	bl fe25519_sqr
	push {r0-r7}
	//frame address sp,336
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// current stack: _ z^(2^5 - 2^0) z^(2^11) x z
	
	mov r8,#5
	// 1052 cycles
	bl fe25519_sqr_many // 634 cycles
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// current stack: _ z^(2^10 - 2^0) z^(2^11) x z <scratch> ...
	
	movs r8,#10
	bl fe25519_sqr_many // 1249 cycles
	//z^(2^20 - 2^10)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	stm sp,{r0-r7}
	//z^(2^20 - 2^0)
	
	// current stack: z^(2^20 - 2^0) z^(2^10 - 2^0) z^(2^11) x z <scratch> ...
	
	movs r8,#20
	sub sp,sp,#32
	//frame address sp,368
	bl fe25519_sqr_many // 2479 cycles
	//z^(2^40 - 2^20)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add sp,sp,#32
	//frame address sp,336
	//z^(2^40 - 2^0)
	
	movs r8,#10
	bl fe25519_sqr_many // 1249 cycles
	//z^(2^50 - 2^10)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add r8,sp,#32
	stm r8,{r0-r7}
	
	// current stack: _ z^(2^50 - 2^0) z^(2^11) x z <scratch> ...
	
	movs r8,#50
	bl fe25519_sqr_many // 6169 cycles
	//z^(2^100 - 2^50)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	stm sp,{r0-r7}
	
	// 13751 cycles so far for inversion
	
	// current stack: z^(2^100 - 2^0) z^(2^50 - 2^0) z^(2^11) x z <scratch> ...
	
	movs r8,#100
	sub sp,sp,#32
	//frame address sp,368
	bl fe25519_sqr_many // 12319 cycles
	//z^(2^200 - 2^100)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	add sp,sp,#32
	//frame address sp,336
	//z^(2^200 - 2^0)
	
	// current stack: _ z^(2^50 - 2^0) z^(2^11) x z <scratch> ...
	
	movs r8,#50
	bl fe25519_sqr_many // 6169 cycles
	//z^(2^250 - 2^50)
	
	mov r1,sp
	add r2,sp,#32
	bl fe25519_mul
	//z^(2^250 - 2^0)
	
	movs r8,#5
	bl fe25519_sqr_many // 634 cycles
	//z^(2^255 - 2^5)
	
	mov r1,sp
	add r2,sp,#64
	bl fe25519_mul
	stm sp,{r0-r7}
	//z^(2^255 - 21)
	
	// 19661 for second half of inversion
	
	// done inverting!
	// total inversion cost: 33412 cycles
	
	mov r1,sp
	add r2,sp,#96
	bl fe25519_mul
	
	// now final reduce
	lsr r8,r7,#31
	mov r9,#19
	mul r8,r8,r9
	mov r10,#0
	
	// handle the case when 2^255 - 19 <= x < 2^255
	add r8,r8,#19
	
	adds r8,r0,r8
	adcs r8,r1,r10
	adcs r8,r2,r10
	adcs r8,r3,r10
	adcs r8,r4,r10
	adcs r8,r5,r10
	adcs r8,r6,r10
	adcs r8,r7,r10
	adcs r11,r10,r10
	
	lsr r8,r8,#31
	orr r8,r8,r11, lsl #1
	mul r8,r8,r9
	
	ldr r9,[sp,#296]
	
	adds r0,r0,r8
	str r0,[r9,#0]
	movs r0,#0
	adcs r1,r1,r0
	str r1,[r9,#4]
	mov r1,r9
	adcs r2,r2,r0
	adcs r3,r3,r0
	adcs r4,r4,r0
	adcs r5,r5,r0
	adcs r6,r6,r0
	adcs r7,r7,r0
	and r7,r7,#0x7fffffff
	
	str r2,[r1,#8]
	str r3,[r1,#12]
	str r4,[r1,#16]
	str r5,[r1,#20]
	str r6,[r1,#24]
	str r7,[r1,#28]
	
	add sp,sp,#300
	//frame address sp,36
	
	pop {r4-r11,pc}
	
	// 234 cycles after inversion
	// in total for whole function 548 873 cycles

SYM_FUNC_END(crypto_scalarmult_curve25519_armv7)
