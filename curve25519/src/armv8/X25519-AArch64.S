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
/* X25519-AArch64 by Emil Lenngren (2018)
 *
 * To the extent possible under law, the person who associated CC0 with
 * X25519-AArch64 has waived all copyright and related or neighboring rights
 * to X25519-AArch64.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
 
/*
 * This is an AArch64 implementation of X25519.
 * It follows the reference implementation where the representation of
 * a field element [0..2^255-19) is represented by a 256-bit little endian integer,
 * reduced modulo 2^256-38, and may possibly be in the range [2^256-38..2^256).
 * The scalar is a 256-bit integer where certain bits are hardcoded per specification.
 *
 * The implementation runs in constant time (~145k cycles on Cortex-A53),
 * and no conditional branches or memory access pattern depend on secret data.
 */

 #include "assembler_support.h"

.cpu generic+fp+simd
	.text
	.align	2
	
	// in: x0: pointer
	// out: x0: loaded value
	.type	load64unaligned, %function
load64unaligned:
	ldrb w1, [x0]
	ldrb w2, [x0, #1]
	ldrb w3, [x0, #2]
	ldrb w4, [x0, #3]
	ldrb w5, [x0, #4]
	ldrb w6, [x0, #5]
	ldrb w7, [x0, #6]
	ldrb w8, [x0, #7]
	
	orr	w1, w1, w2, lsl #8
	orr	w3, w3, w4, lsl #8
	orr	w5, w5, w6, lsl #8
	orr	w7, w7, w8, lsl #8
	
	orr	w1, w1, w3, lsl #16
	orr	w5, w5, w7, lsl #16
	
	orr	x0, x1, x5, lsl #32
	
	RET
	.size	load64unaligned, .-load64unaligned

	// in: x0: pointer
	// out: x0-x3: loaded value
	.type	load256unaligned, %function
load256unaligned:
	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	
	mov	x19, x0
	bl	load64unaligned
	mov	x20, x0
	add	x0, x19, #8
	bl	load64unaligned
	mov	x21, x0
	add	x0, x19, #16
	bl	load64unaligned
	mov	x22, x0
	add	x0, x19, #24
	bl	load64unaligned
	mov	x3, x0
	
	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x29, x30, [sp], #64
	RET
	.size load256unaligned, .-load256unaligned

	// in: x1: scalar pointer, x2: base point pointer
	// out: x0: result pointer
SYM_FUNC_START(crypto_scalarmult_curve25519_armv8)
SYM_FUNC_ENTER(crypto_scalarmult_curve25519_armv8)
	stp	x29, x30, [sp, #-160]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	stp	x23, x24, [sp, #48]
	stp	x25, x26, [sp, #64]
	stp	x27, x28, [sp, #80]
	stp	d8, d9, [sp, #96]
	stp	d10, d11, [sp, #112]
	stp	d12, d13, [sp, #128]
	stp	d14, d15, [sp, #144]
	sub	sp, sp, 192
	
	// 0: mask1, 8: mask2, 16: AA, 56: B/BB, 96: counter, 100: lastbit, 104: scalar, 136: X1, 176: outptr, 184: padding, 192: fp, 200: lr
	
	str	x0, [sp, #176] // outptr
	mov	x19, x2 // point
	
	mov	x0, x1 // scalar
	bl	load256unaligned
	
	and	x3, x3, #0x7fffffffffffffff
	and	x0, x0, #0xfffffffffffffff8
	orr	x3, x3, #0x4000000000000000
	
	stp	x0, x1, [sp, #104]
	stp	x2, x3, [sp, #104+16]
	
	mov	x0, x19 // point
	bl	load256unaligned
	
	// Unpack point (discard most significant bit)
	lsr	x12, x0, #51
	lsr	x17, x2, #51
	orr	w12, w12, w1, lsl #13
	orr	w17, w17, w3, lsl #13
	ubfx	x8, x3, #12, #26
	ubfx	x9, x3, #38, #25
	ubfx	x11, x0, #26, #25
	ubfx	x13, x1, #13, #25
	lsr	x14, x1, #38
	ubfx	x16, x2, #25, #26
	and	w10, w0, #0x3ffffff
	and	w12, w12, #0x3ffffff
	and	w15, w2, #0x1ffffff
	and	w17, w17, #0x1ffffff
	stp	w10, w11, [sp, #136]
	stp	w12, w13, [sp, #136+8]
	stp	w14, w15, [sp, #136+16]
	stp	w16, w17, [sp, #136+24]
	stp	w8, w9, [sp, #136+32]
	
	// X2 (initially set to 1)
	mov	x1, #1
	mov	v0.d[0], x1
	mov	v2.d[0], xzr
	mov	v4.d[0], xzr
	mov	v6.d[0], xzr
	mov	v8.d[0], xzr
	
	// Z2 (initially set to 0)
	mov	v1.d[0], xzr
	mov	v3.d[0], xzr
	mov	v5.d[0], xzr
	mov	v7.d[0], xzr
	mov	v9.d[0], xzr
	
	// X3 (initially set to X1)
	mov	v10.s[0], w10
	mov	v10.s[1], w11
	mov	v12.s[0], w12
	mov	v12.s[1], w13
	mov	v14.s[0], w14
	mov	v14.s[1], w15
	mov	v16.s[0], w16
	mov	v16.s[1], w17
	mov	v18.s[0], w8
	mov	v18.s[1], w9
	
	// Z3 (initially set to 1)
	mov	v11.d[0], x1
	mov	v13.d[0], xzr
	mov	v15.d[0], xzr
	mov	v17.d[0], xzr
	mov	v19.d[0], xzr
	
	mov	x0,  #255-1 // 255 iterations
	str	w0, [sp, #96]
	
	
	mov	w30, #19
	dup	v31.2s, w30
	mov	x0, #(1<<26)-1
	dup	v30.2d, x0
	ldr	x0, =0x07fffffe07fffffc
	stp	x0, x0, [sp]
	sub	x1, x0, #0xfc-0xb4
	stp	x1, x0, [sp, #8]
	
	ldr	d28, [sp, #8]
	ldr	d29, [sp]
	
	ldrb	w1, [sp, #135]
	lsr	w1, w1, #6
	str	w1, [sp, #100]

.Lmainloop:
	tst	w1, #1

	// (2^255-19)*4 - Z_
	sub	v20.2s, v28.2s, v1.2s
	sub	v21.2s, v29.2s, v3.2s
	sub	v22.2s, v29.2s, v5.2s
	sub	v23.2s, v29.2s, v7.2s
	sub	v24.2s, v29.2s, v9.2s

	sub	v25.2s, v28.2s, v11.2s
	sub	v26.2s, v29.2s, v13.2s
	sub	v27.2s, v29.2s, v15.2s

	sub	v28.2s, v29.2s, v17.2s
	sub	v29.2s, v29.2s, v19.2s

	// ... + X_
	add	v20.2s, v0.2s, v20.2s
	add	v21.2s, v2.2s, v21.2s
	add	v22.2s, v4.2s, v22.2s
	add	v23.2s, v6.2s, v23.2s
	add	v24.2s, v8.2s, v24.2s

	add	v25.2s, v10.2s, v25.2s
	add	v26.2s, v12.2s, v26.2s
	add	v27.2s, v14.2s, v27.2s
	add	v28.2s, v16.2s, v28.2s
	add	v29.2s, v18.2s, v29.2s

	// X_ + Z_
	add	v0.2s, v0.2s, v1.2s
	add	v10.2s, v10.2s, v11.2s
	add	v2.2s, v2.2s, v3.2s
	add	v12.2s, v12.2s, v13.2s
	fcsel	d1, d0, d10, eq
	add	v4.2s, v4.2s, v5.2s
	fcsel	d3, d2, d12, eq
	add	v14.2s, v14.2s, v15.2s
	add	v6.2s, v6.2s, v7.2s
	add	v16.2s, v16.2s, v17.2s
	mov	x0, v1.d[0]
	add	v8.2s, v8.2s, v9.2s
	mov	x2, v3.d[0]
	add	v18.2s, v18.2s, v19.2s
	fcsel	d5, d4, d14, eq

	// [B A]
	trn2	v1.2s, v0.2s, v20.2s
	fcsel	d7, d6, d16, eq
	trn1	v0.2s, v0.2s, v20.2s
	fcsel	d9, d8, d18, eq
	trn2	v3.2s, v2.2s, v21.2s
	mov	x4, v5.d[0]
	trn1	v2.2s, v2.2s, v21.2s
	mov	x6, v7.d[0]
	trn2	v5.2s, v4.2s, v22.2s
	mov	x8, v9.d[0]
	trn1	v4.2s, v4.2s, v22.2s
	fcsel	d20, d20, d25, eq
	trn2	v7.2s, v6.2s, v23.2s
	fcsel	d21, d21, d26, eq
	trn1	v6.2s, v6.2s, v23.2s
	fcsel	d22, d22, d27, eq
	trn2	v9.2s, v8.2s, v24.2s
	fcsel	d23, d23, d28, eq
	trn1	v8.2s, v8.2s, v24.2s
	fcsel	d24, d24, d29, eq

	// [C D]
	trn2	v11.2s, v25.2s, v10.2s
	trn1	v10.2s, v25.2s, v10.2s
	trn2	v13.2s, v26.2s, v12.2s
	trn1	v12.2s, v26.2s, v12.2s
	trn2	v15.2s, v27.2s, v14.2s
	trn1	v14.2s, v27.2s, v14.2s
	trn2	v17.2s, v28.2s, v16.2s
	trn1	v16.2s, v28.2s, v16.2s
	stp	d20, d21, [sp, #56]
	trn2	v19.2s, v29.2s, v18.2s
	stp	d22, d23, [sp, #56+16]
	trn1	v18.2s, v29.2s, v18.2s
	str	d24, [sp, #56+32]


	//v0-v9:   [B A]
	//v10-v19: [C D]


	umull	v29.2d, v0.2s, v19.2s
	lsr	x1, x0, #32
	umlal	v29.2d, v2.2s, v17.2s
	lsr	x3, x2, #32
	umlal	v29.2d, v4.2s, v15.2s
	lsr	x5, x4, #32
	umlal	v29.2d, v6.2s, v13.2s
	lsr	x7, x6, #32
	umlal	v29.2d, v8.2s, v11.2s
	lsr	x9, x8, #32
	mul	v19.2s, v19.2s, v31.2s
	add	x21, x9, x9
	umull	v28.2d, v1.2s, v17.2s
	add	x17, x8, x8
	umlal	v28.2d, v3.2s, v15.2s
	add	x16, x7, x7
	umlal	v28.2d, v5.2s, v13.2s
	add	x15, x6, x6
	umlal	v28.2d, v7.2s, v11.2s
	add	x14, x5, x5
	umlal	v28.2d, v9.2s, v19.2s
	add	x13, x4, x4
	umlal	v29.2d, v1.2s, v18.2s
	add	x12, x3, x3
	umlal	v29.2d, v3.2s, v16.2s
	add	x11, x2, x2
	umlal	v29.2d, v5.2s, v14.2s
	add	x10, x1, x1
	umlal	v29.2d, v7.2s, v12.2s
	umull	x28, w4, w4
	umlal	v29.2d, v9.2s, v10.2s
	umull	x19, w4, w14
	shl	v28.2d, v28.2d, #1
	mul	w9, w9, w30
	umull	v27.2d, v0.2s, v17.2s
	mul	w7, w7, w30
	umlal	v27.2d, v2.2s, v15.2s
	mul	w5, w5, w30
	umlal	v27.2d, v4.2s, v13.2s
	umaddl	x28, w9, w21, x28
	umlal	v27.2d, v6.2s, v11.2s
	umaddl	x19, w0, w21, x19
	umlal	v27.2d, v8.2s, v19.2s
	umull	x20, w0, w0
	mul	v17.2s, v17.2s, v31.2s
	umull	x21, w0, w10
	umlal	v28.2d, v0.2s, v18.2s
	umull	x22, w0, w11
	umlal	v28.2d, v2.2s, v16.2s
	umull	x23, w0, w12
	umlal	v28.2d, v4.2s, v14.2s
	umull	x24, w0, w13
	umlal	v28.2d, v6.2s, v12.2s
	umull	x25, w0, w14
	umlal	v28.2d, v8.2s, v10.2s
	umull	x26, w0, w15
	mul	v18.2s, v18.2s, v31.2s
	umull	x27, w0, w16
	umull	v26.2d, v1.2s, v15.2s
	umaddl	x28, w0, w17, x28
	umlal	v26.2d, v3.2s, v13.2s
	mul	w0, w6, w30
	umlal	v26.2d, v5.2s, v11.2s
	umaddl	x22, w1, w10, x22
	umlal	v26.2d, v7.2s, v19.2s
	umaddl	x23, w1, w11, x23
	umlal	v26.2d, v9.2s, v17.2s
	umaddl	x24, w10, w12, x24
	umlal	v27.2d, v1.2s, v16.2s
	umaddl	x25, w1, w13, x25
	umlal	v27.2d, v3.2s, v14.2s
	umaddl	x26, w10, w14, x26
	umlal	v27.2d, v5.2s, v12.2s
	umaddl	x27, w1, w15, x27
	umlal	v27.2d, v7.2s, v10.2s
	umaddl	x28, w10, w16, x28
	umlal	v27.2d, v9.2s, v18.2s
	umaddl	x19, w1, w17, x19
	shl	v26.2d, v26.2d, #1
	mul	w1, w8, w30
	umull	v25.2d, v0.2s, v15.2s
	umaddl	x24, w2, w2, x24
	umlal	v25.2d, v2.2s, v13.2s
	umaddl	x25, w2, w12, x25
	umlal	v25.2d, v4.2s, v11.2s
	umaddl	x26, w2, w13, x26
	umlal	v25.2d, v6.2s, v19.2s
	umaddl	x27, w2, w14, x27
	umlal	v25.2d, v8.2s, v17.2s
	umaddl	x28, w2, w15, x28
	mul	v15.2s, v15.2s, v31.2s
	umaddl	x19, w2, w16, x19
	umlal	v26.2d, v0.2s, v16.2s
	umaddl	x26, w3, w12, x26
	umlal	v26.2d, v2.2s, v14.2s
	umaddl	x27, w3, w13, x27
	umlal	v26.2d, v4.2s, v12.2s
	umaddl	x28, w12, w14, x28
	umlal	v26.2d, v6.2s, v10.2s
	umaddl	x19, w3, w15, x19
	umlal	v26.2d, v8.2s, v18.2s
	umaddl	x26, w1, w8, x26
	mul	v16.2s, v16.2s, v31.2s
	umaddl	x22, w0, w6, x22
	umull	v24.2d, v1.2s, v13.2s
	add	x19, x19, x28, lsr #26
	umlal	v24.2d, v3.2s, v11.2s
	umaddl	x20, w5, w14, x20
	umlal	v24.2d, v5.2s, v19.2s
	add	x20, x20, x19, lsr #25
	umlal	v24.2d, v7.2s, v17.2s
	bic	x2, x19, #0x1ffffff
	umlal	v24.2d, v9.2s, v15.2s
	add	x20, x20, x2, lsr #24
	umlal	v25.2d, v1.2s, v14.2s
	and	x19, x19, #0x1ffffff
	umlal	v25.2d, v3.2s, v12.2s
	add	x20, x20, x2, lsr #21
	umlal	v25.2d, v5.2s, v10.2s
	umaddl	x24, w7, w16, x24
	umlal	v25.2d, v7.2s, v18.2s
	add	x2, x10, x10
	umlal	v25.2d, v9.2s, v16.2s
	add	x3, x12, x12
	shl	v24.2d, v24.2d, #1
	add	x4, x14, x14
	umull	v23.2d, v0.2s, v13.2s
	add	x5, x16, x16
	umlal	v23.2d, v2.2s, v11.2s
	umaddl	x20, w0, w13, x20
	umlal	v23.2d, v4.2s, v19.2s
	umaddl	x21, w0, w14, x21
	umlal	v23.2d, v6.2s, v17.2s
	and	x28, x28, #0x3ffffff
	umlal	v23.2d, v8.2s, v15.2s
	umaddl	x20, w7, w3, x20
	mul	v13.2s, v13.2s, v31.2s
	umaddl	x21, w7, w13, x21
	umlal	v24.2d, v0.2s, v14.2s
	umaddl	x22, w7, w4, x22
	umlal	v24.2d, v2.2s, v12.2s
	umaddl	x23, w7, w15, x23
	umlal	v24.2d, v4.2s, v10.2s
	umaddl	x20, w1, w11, x20
	umlal	v24.2d, v6.2s, v18.2s
	umaddl	x21, w1, w12, x21
	umlal	v24.2d, v8.2s, v16.2s
	umaddl	x22, w1, w13, x22
	mul	v14.2s, v14.2s, v31.2s
	umaddl	x23, w1, w14, x23
	umull	v22.2d, v1.2s, v11.2s
	umaddl	x24, w1, w15, x24
	umlal	v22.2d, v3.2s, v19.2s
	umaddl	x25, w1, w16, x25
	umlal	v22.2d, v5.2s, v17.2s
	umaddl	x20, w9, w2, x20
	umlal	v22.2d, v7.2s, v15.2s
	umaddl	x21, w9, w11, x21
	umlal	v22.2d, v9.2s, v13.2s
	umaddl	x22, w9, w3, x22
	umlal	v23.2d, v1.2s, v12.2s
	umaddl	x23, w9, w13, x23
	umlal	v23.2d, v3.2s, v10.2s
	umaddl	x24, w9, w4, x24
	umlal	v23.2d, v5.2s, v18.2s
	umaddl	x25, w9, w15, x25
	umlal	v23.2d, v7.2s, v16.2s
	umaddl	x26, w9, w5, x26
	umlal	v23.2d, v9.2s, v14.2s
	umaddl	x27, w9, w17, x27
	shl	v22.2d, v22.2d, #1
	add	x21, x21, x20, lsr #26
	umull	v21.2d, v0.2s, v11.2s
	and	x20, x20, #0x3ffffff
	umlal	v21.2d, v2.2s, v19.2s
	add	x22, x22, x21, lsr #25
	umlal	v21.2d, v4.2s, v17.2s
	bfi	x20, x21, #32, #25
	umlal	v21.2d, v6.2s, v15.2s
	add	x23, x23, x22, lsr #26
	umlal	v21.2d, v8.2s, v13.2s
	and	x22, x22, #0x3ffffff
	mul	v11.2s, v11.2s, v31.2s
	add	x24, x24, x23, lsr #25
	umlal	v22.2d, v0.2s, v12.2s
	bfi	x22, x23, #32, #25
	umlal	v22.2d, v2.2s, v10.2s
	add	x25, x25, x24, lsr #26
	umlal	v22.2d, v4.2s, v18.2s
	and	x24, x24, #0x3ffffff
	umlal	v22.2d, v6.2s, v16.2s
	add	x26, x26, x25, lsr #25
	umlal	v22.2d, v8.2s, v14.2s
	bfi	x24, x25, #32, #25
	mul	v12.2s, v12.2s, v31.2s
	add	x27, x27, x26, lsr #26
	umull	v20.2d, v1.2s, v19.2s
	and	x26, x26, #0x3ffffff
	umlal	v20.2d, v3.2s, v17.2s
	add	x28, x28, x27, lsr #25
	umlal	v20.2d, v5.2s, v15.2s
	bfi	x26, x27, #32, #25
	ushr	v15.2d, v30.2d, #1
	add	x19, x19, x28, lsr #26
	usra	v23.2d, v22.2d, #26
	and	x28, x28, #0x3ffffff
	and	v22.16b, v22.16b, v30.16b
	bfi	x28, x19, #32, #26
	umlal	v21.2d, v1.2s, v10.2s
	stp	x20, x22, [sp, #16]
	usra	v24.2d, v23.2d, #25
	stp	x24, x26, [sp, #32]
	and	v23.16b, v23.16b, v15.16b
	str	x28, [sp, #48]
	umlal	v20.2d, v7.2s, v13.2s
	ldr	x8, [sp, #88]
	usra	v25.2d, v24.2d, #26
	ldr	x6, [sp, #80]
	and	v24.16b, v24.16b, v30.16b
	ldr	x4, [sp, #72]
	umlal	v21.2d, v3.2s, v18.2s
	ldr	x2, [sp, #64]
	usra	v26.2d, v25.2d, #25
	lsr	x9, x8, #32
	and	v25.16b, v25.16b, v15.16b
	ldr	x0, [sp, #56]
	umlal	v20.2d, v9.2s, v11.2s
	lsr	x7, x6, #32
	usra	v27.2d, v26.2d, #26
	lsr	x5, x4, #32
	and	v26.16b, v26.16b, v30.16b
	lsr	x3, x2, #32
	umlal	v21.2d, v5.2s, v16.2s
	lsr	x1, x0, #32
	umlal	v21.2d, v7.2s, v14.2s
	add	x21, x9, x9
	umlal	v21.2d, v9.2s, v12.2s
	add	x17, x8, x8
	usra	v28.2d, v27.2d, #25
	add	x16, x7, x7
	and	v27.16b, v27.16b, v15.16b
	add	x15, x6, x6
	shl	v20.2d, v20.2d, #1
	add	x14, x5, x5
	usra	v29.2d, v28.2d, #26
	add	x13, x4, x4
	and	v28.16b, v28.16b, v30.16b
	add	x12, x3, x3
	umlal	v20.2d, v0.2s, v10.2s
	add	x11, x2, x2
	umlal	v20.2d, v2.2s, v18.2s
	add	x10, x1, x1
	umlal	v20.2d, v4.2s, v16.2s
	umull	x28, w4, w4
	umlal	v20.2d, v6.2s, v14.2s
	umull	x19, w4, w14
	umlal	v20.2d, v8.2s, v12.2s
	mul	w9, w9, w30
	bic	v19.16b, v29.16b, v15.16b
	mul	w7, w7, w30
	and	v29.16b, v29.16b, v15.16b
	mul	w5, w5, w30
	usra	v20.2d, v19.2d, #25
	umaddl	x28, w9, w21, x28
	uzp1	v24.4s, v24.4s, v25.4s
	umaddl	x19, w0, w21, x19
	usra	v20.2d, v19.2d, #24
	umull	x20, w0, w0
	uzp1	v25.4s, v26.4s, v27.4s
	umull	x21, w0, w10
	usra	v20.2d, v19.2d, #21
	umull	x22, w0, w11
	ld1r	{v19.2d}, [sp]
	umull	x23, w0, w12
	uzp1	v26.4s, v24.4s, v25.4s
	umull	x24, w0, w13
	usra	v21.2d, v20.2d, #26
	umull	x25, w0, w14
	and	v20.16b, v20.16b, v30.16b
	umull	x26, w0, w15
	uzp2	v27.4s, v24.4s, v25.4s
	umull	x27, w0, w16
	usra	v22.2d, v21.2d, #25
	umaddl	x28, w0, w17, x28
	and	v21.16b, v21.16b, v15.16b
	mul	w0, w6, w30
	trn1	v28.4s, v28.4s, v29.4s
	umaddl	x22, w1, w10, x22
	usra	v23.2d, v22.2d, #26
	umaddl	x23, w1, w11, x23
	and	v22.16b, v22.16b, v30.16b
	umaddl	x24, w10, w12, x24
	ldr	b0, [sp, #8]
	umaddl	x25, w1, w13, x25
	uzp1	v20.4s, v20.4s, v21.4s
	umaddl	x26, w10, w14, x26
	uzp1	v21.4s, v22.4s, v23.4s
	umaddl	x27, w1, w15, x27
	mov	v29.d[0], v28.d[1]
	umaddl	x28, w10, w16, x28
	uzp1	v24.4s, v20.4s, v21.4s
	umaddl	x19, w1, w17, x19
	uzp2	v25.4s, v20.4s, v21.4s
	mul	w1, w8, w30
	add	v11.4s, v26.4s, v19.4s
	umaddl	x24, w2, w2, x24
	add	v12.2s, v28.2s, v19.2s
	umaddl	x25, w2, w12, x25
	mov	v19.b[0], v0.b[0]
	umaddl	x26, w2, w13, x26
	add	v20.4s, v24.4s, v25.4s
	umaddl	x27, w2, w14, x27
	add	v21.4s, v26.4s, v27.4s
	umaddl	x28, w2, w15, x28
	add	v22.2s, v28.2s, v29.2s
	umaddl	x19, w2, w16, x19
	add	v10.4s, v24.4s, v19.4s
	umaddl	x26, w3, w12, x26
	sub	v11.4s, v11.4s, v27.4s
	umaddl	x27, w3, w13, x27
	sub	v10.4s, v10.4s, v25.4s
	umaddl	x28, w12, w14, x28
	sub	v12.2s, v12.2s, v29.2s
	umaddl	x19, w3, w15, x19
	zip1	v0.4s, v10.4s, v20.4s
	umaddl	x26, w1, w8, x26
	zip2	v2.4s, v10.4s, v20.4s
	umaddl	x22, w0, w6, x22
	zip1	v4.4s, v11.4s, v21.4s
	add	x19, x19, x28, lsr #26
	zip2	v6.4s, v11.4s, v21.4s
	umaddl	x20, w5, w14, x20
	zip1	v8.2s, v12.2s, v22.2s
	add	x20, x20, x19, lsr #25
	zip2	v9.2s, v12.2s, v22.2s
	bic	x2, x19, #0x1ffffff
	mov	v1.d[0], v0.d[1]
	add	x20, x20, x2, lsr #24
	mov	v3.d[0], v2.d[1]
	and	x19, x19, #0x1ffffff
	mov	v5.d[0], v4.d[1]
	add	x20, x20, x2, lsr #21
	mov	v7.d[0], v6.d[1]
	umaddl	x24, w7, w16, x24
	shl	v19.2s, v9.2s, #1
	add	x2, x10, x10
	shl	v18.2s, v8.2s, #1
	add	x3, x12, x12
	shl	v17.2s, v7.2s, #1
	add	x4, x14, x14
	shl	v16.2s, v6.2s, #1
	add	x5, x16, x16
	shl	v10.2s, v5.2s, #1
	umaddl	x20, w0, w13, x20
	shl	v14.2s, v4.2s, #1
	umaddl	x21, w0, w14, x21
	shl	v13.2s, v3.2s, #1
	and	x28, x28, #0x3ffffff
	shl	v12.2s, v2.2s, #1
	umaddl	x20, w7, w3, x20
	shl	v11.2s, v1.2s, #1
	umaddl	x21, w7, w13, x21
	umull	v29.2d, v0.2s, v19.2s
	umaddl	x22, w7, w4, x22
	umlal	v29.2d, v1.2s, v18.2s
	umaddl	x23, w7, w15, x23
	umlal	v29.2d, v2.2s, v17.2s
	umaddl	x20, w1, w11, x20
	umlal	v29.2d, v3.2s, v16.2s
	umaddl	x21, w1, w12, x21
	umlal	v29.2d, v4.2s, v10.2s
	umaddl	x22, w1, w13, x22
	umull	v28.2d, v0.2s, v18.2s
	umaddl	x23, w1, w14, x23
	umlal	v28.2d, v11.2s, v17.2s
	umaddl	x24, w1, w15, x24
	umlal	v28.2d, v2.2s, v16.2s
	umaddl	x25, w1, w16, x25
	umlal	v28.2d, v13.2s, v10.2s
	umaddl	x20, w9, w2, x20
	umlal	v28.2d, v4.2s, v4.2s
	umaddl	x21, w9, w11, x21
	mul	v4.2s, v9.2s, v31.2s
	umaddl	x22, w9, w3, x22
	umull	v27.2d, v0.2s, v17.2s
	umaddl	x23, w9, w13, x23
	umlal	v27.2d, v1.2s, v16.2s
	umaddl	x24, w9, w4, x24
	umlal	v27.2d, v2.2s, v10.2s
	umaddl	x25, w9, w15, x25
	umlal	v27.2d, v3.2s, v14.2s
	umaddl	x26, w9, w5, x26
	umlal	v28.2d, v4.2s, v19.2s
	umaddl	x27, w9, w17, x27
	umull	v26.2d, v0.2s, v16.2s
	add	x1, x21, x20, lsr #26
	umlal	v26.2d, v11.2s, v10.2s
	and	x0, x20, #0x3ffffff
	umlal	v26.2d, v2.2s, v14.2s
	add	x2, x22, x1, lsr #25
	umlal	v26.2d, v13.2s, v3.2s
	bfi	x0, x1, #32, #25
	umull	v25.2d, v0.2s, v10.2s
	add	x3, x23, x2, lsr #26
	umlal	v25.2d, v1.2s, v14.2s
	and	x2, x2, #0x3ffffff
	umlal	v25.2d, v2.2s, v13.2s
	add	x4, x24, x3, lsr #25
	umull	v24.2d, v0.2s, v14.2s
	bfi	x2, x3, #32, #25
	umlal	v24.2d, v11.2s, v13.2s
	add	x5, x25, x4, lsr #26
	umlal	v24.2d, v2.2s, v2.2s
	and	x4, x4, #0x3ffffff
	umull	v23.2d, v0.2s, v13.2s
	add	x6, x26, x5, lsr #25
	umlal	v23.2d, v1.2s, v12.2s
	bfi	x4, x5, #32, #25
	umull	v22.2d, v0.2s, v12.2s
	add	x7, x27, x6, lsr #26
	umlal	v22.2d, v11.2s, v1.2s
	and	x6, x6, #0x3ffffff
	umull	v21.2d, v0.2s, v11.2s
	add	x8, x28, x7, lsr #25
	umull	v20.2d, v0.2s, v0.2s
	bfi	x6, x7, #32, #25
	usra	v29.2d, v28.2d, #26
	add	x9, x19, x8, lsr #26
	and	v28.16b, v28.16b, v30.16b
	and	x8, x8, #0x3ffffff
	mul	v3.2s, v8.2s, v31.2s
	bfi	x8, x9, #32, #26
	bic	v19.16b, v29.16b, v15.16b
	and	x1, x1, #0x1ffffff
	and	v9.16b, v29.16b, v15.16b
	and	x3, x3, #0x1ffffff
	usra	v20.2d, v19.2d, #25
	and	x5, x5, #0x1ffffff
	mul	v2.2s, v7.2s, v31.2s
	and	x7, x7, #0x1ffffff
	usra	v20.2d, v19.2d, #24
	stp	x0, x2, [sp, #56]
	mul	v1.2s, v6.2s, v31.2s
	stp	x4, x6, [sp, #56+16]
	usra	v20.2d, v19.2d, #21
	str	x8, [sp, #56+32]
	mul	v0.2s, v5.2s, v31.2s
	ldr	x21, =0x07fffffe07fffffc
	shl	v5.2s, v11.2s, #1
	ldr	x10, [sp, #16]
	shl	v7.2s, v13.2s, #1
	ldr	x12, [sp, #16+8]
	shl	v19.2s, v10.2s, #1
	ldr	x14, [sp, #16+16]
	shl	v11.2s, v17.2s, #1
	ldr	x16, [sp, #16+24]
	umlal	v20.2d, v0.2s, v10.2s
	ldr	x19, [sp, #16+32]
	umlal	v20.2d, v4.2s, v5.2s
	add	x12, x12, x21
	umlal	v20.2d, v3.2s, v12.2s
	add	x14, x14, x21
	umlal	v20.2d, v2.2s, v7.2s
	add	x16, x16, x21
	umlal	v20.2d, v1.2s, v14.2s
	add	x19, x19, x21
	umlal	v21.2d, v4.2s, v12.2s
	movk	x21, #0xffb4
	umlal	v21.2d, v3.2s, v13.2s
	add	x10, x10, x21
	umlal	v21.2d, v2.2s, v14.2s
	sub	x10, x10, x0
	umlal	v21.2d, v1.2s, v10.2s
	sub	x12, x12, x2
	umlal	v22.2d, v1.2s, v6.2s
	sub	x14, x14, x4
	umlal	v22.2d, v4.2s, v7.2s
	sub	x16, x16, x6
	umlal	v22.2d, v3.2s, v14.2s
	sub	x19, x19, x8
	umlal	v22.2d, v2.2s, v19.2s
	mov	w0, w0
	usra	v21.2d, v20.2d, #26
	mov	w2, w2
	umlal	v23.2d, v4.2s, v14.2s
	mov	w4, w4
	umlal	v23.2d, v3.2s, v10.2s
	mov	w6, w6
	umlal	v23.2d, v2.2s, v16.2s
	mov	w8, w8
	usra	v22.2d, v21.2d, #25
	lsr	x11, x10, #32
	umlal	v24.2d, v2.2s, v17.2s
	lsr	x13, x12, #32
	umlal	v24.2d, v4.2s, v19.2s
	lsr	x15, x14, #32
	umlal	v24.2d, v3.2s, v16.2s
	lsr	x17, x16, #32
	usra	v23.2d, v22.2d, #26
	lsr	x20, x19, #32
	umlal	v25.2d, v4.2s, v16.2s
	ldr	x21, =121666
	umlal	v25.2d, v3.2s, v17.2s
	umaddl	x9, w20, w21, x9
	usra	v24.2d, v23.2d, #25
	umaddl	x0, w10, w21, x0
	umlal	v26.2d, v3.2s, v8.2s
	umaddl	x1, w11, w21, x1
	umlal	v26.2d, v4.2s, v11.2s
	umaddl	x2, w12, w21, x2
	usra	v25.2d, v24.2d, #26
	lsr	x22, x9, #25
	umlal	v27.2d, v4.2s, v18.2s
	umaddl	x3, w13, w21, x3
	and	v4.16b, v24.16b, v30.16b
	and	x9, x9, #0x1ffffff
	usra	v26.2d, v25.2d, #25
	umaddl	x4, w14, w21, x4
	and	v5.16b, v25.16b, v15.16b
	add	x0, x0, x22
	and	v0.16b, v20.16b, v30.16b
	umaddl	x5, w15, w21, x5
	usra	v27.2d, v26.2d, #26
	add	x0, x0, x22, lsl #1
	and	v6.16b, v26.16b, v30.16b
	umaddl	x6, w16, w21, x6
	and	v1.16b, v21.16b, v15.16b
	add	x0, x0, x22, lsl #4
	usra	v28.2d, v27.2d, #25
	umaddl	x7, w17, w21, x7
	and	v7.16b, v27.16b, v15.16b
	umaddl	x8, w19, w21, x8
	and	v2.16b, v22.16b, v30.16b
	add	x26, sp, #136	// X1 for ASIMD part
	usra	v9.2d, v28.2d, #26
	add	x27, sp, #16	// AA
	and	v8.16b, v28.16b, v30.16b
	add	x28, sp, #56	// BB
	and	v3.16b, v23.16b, v15.16b
	add	x1, x1, x0, lsr #26
	ld2	{ v0.s, v1.s }[1], [x27], #8 // X1, AA, BB loaded from a64 part
	and	x0, x0, #0x3ffffff
	ld2	{ v10.s, v11.s }[1], [x28], #8
	add	x2, x2, x1, lsr #25
	ld2	{ v10.s, v11.s }[0], [x26], #8
	and	x1, x1, #0x1ffffff
	ld2	{ v2.s, v3.s }[1], [x27], #8
	add	x3, x3, x2, lsr #26
	ld2	{ v12.s, v13.s }[1], [x28], #8
	and	x2, x2, #0x3ffffff
	ld2	{ v12.s, v13.s }[0], [x26], #8
	add	x4, x4, x3, lsr #25
	ld2	{ v4.s, v5.s }[1], [x27], #8
	and	x3, x3, #0x1ffffff
	ld2	{ v14.s, v15.s }[1], [x28], #8
	add	x5, x5, x4, lsr #26
	ld2	{ v14.s, v15.s }[0], [x26], #8
	and	x4, x4, #0x3ffffff
	ld2	{ v6.s, v7.s }[1], [x27], #8
	add	x6, x6, x5, lsr #25
	ld2	{ v16.s, v17.s }[1], [x28], #8
	and	x5, x5, #0x1ffffff
	ld2	{ v16.s, v17.s }[0], [x26], #8
	add	x7, x7, x6, lsr #26
	ld2	{ v8.s, v9.s }[1], [x27], #8
	and	x6, x6, #0x3ffffff
	ld2	{ v18.s, v19.s }[1], [x28], #8
	add	x8, x8, x7, lsr #25
	ld2	{ v18.s, v19.s }[0], [x26], #8
	and	x7, x7, #0x1ffffff
	umull	v29.2d, v6.2s, v13.2s
	add	x9, x9, x8, lsr #26
	umlal	v29.2d, v4.2s, v15.2s
	and	x8, x8, #0x3ffffff
	umlal	v29.2d, v0.2s, v19.2s
	umull	x21, w1, w19
	umlal	v29.2d, v2.2s, v17.2s
	umull	x22, w1, w17
	umlal	v29.2d, v8.2s, v11.2s
	umull	x23, w1, w16
	mul	v19.2s, v19.2s, v31.2s
	umull	x24, w1, w15
	umull	v28.2d, v1.2s, v17.2s
	umaddl	x21, w3, w16, x21
	umlal	v28.2d, v3.2s, v15.2s
	umaddl	x22, w3, w15, x22
	umlal	v28.2d, v5.2s, v13.2s
	umaddl	x23, w3, w14, x23
	umlal	v28.2d, v7.2s, v11.2s
	umaddl	x24, w3, w13, x24
	umlal	v28.2d, v9.2s, v19.2s
	umaddl	x21, w5, w14, x21
	umlal	v29.2d, v1.2s, v18.2s
	umaddl	x22, w5, w13, x22
	umlal	v29.2d, v3.2s, v16.2s
	umaddl	x23, w5, w12, x23
	umlal	v29.2d, v5.2s, v14.2s
	umaddl	x24, w5, w11, x24
	umlal	v29.2d, v7.2s, v12.2s
	umaddl	x21, w7, w12, x21
	umlal	v29.2d, v9.2s, v10.2s
	umaddl	x22, w7, w11, x22
	shl	v28.2d, v28.2d, #1
	umaddl	x23, w7, w10, x23
	umull	v27.2d, v0.2s, v17.2s
	mul	w27, w7, w30
	umlal	v27.2d, v2.2s, v15.2s
	mul	w25, w9, w30
	umlal	v27.2d, v4.2s, v13.2s
	mul	w26, w8, w30
	umlal	v27.2d, v6.2s, v11.2s
	mul	w28, w6, w30
	umlal	v27.2d, v8.2s, v19.2s
	umaddl	x24, w27, w20, x24
	mul	v17.2s, v17.2s, v31.2s
	umaddl	x21, w9, w10, x21
	umlal	v28.2d, v0.2s, v18.2s
	umaddl	x22, w25, w20, x22
	umlal	v28.2d, v2.2s, v16.2s
	umaddl	x23, w25, w19, x23
	umlal	v28.2d, v4.2s, v14.2s
	umaddl	x24, w25, w17, x24
	umlal	v28.2d, v6.2s, v12.2s
	add	x22, x22, x22
	umlal	v28.2d, v8.2s, v10.2s
	umaddl	x21, w0, w20, x21
	mul	v18.2s, v18.2s, v31.2s
	add	x24, x24, x24
	umull	v26.2d, v1.2s, v15.2s
	umaddl	x22, w0, w19, x22
	umlal	v26.2d, v3.2s, v13.2s
	umaddl	x23, w0, w17, x23
	umlal	v26.2d, v5.2s, v11.2s
	umaddl	x24, w0, w16, x24
	umlal	v26.2d, v7.2s, v19.2s
	umaddl	x21, w2, w17, x21
	umlal	v26.2d, v9.2s, v17.2s
	umaddl	x22, w2, w16, x22
	umlal	v27.2d, v1.2s, v16.2s
	umaddl	x23, w2, w15, x23
	umlal	v27.2d, v3.2s, v14.2s
	umaddl	x24, w2, w14, x24
	umlal	v27.2d, v5.2s, v12.2s
	umaddl	x21, w4, w15, x21
	umlal	v27.2d, v7.2s, v10.2s
	umaddl	x22, w4, w14, x22
	umlal	v27.2d, v9.2s, v18.2s
	umaddl	x23, w4, w13, x23
	shl	v26.2d, v26.2d, #1
	umaddl	x24, w4, w12, x24
	umull	v25.2d, v0.2s, v15.2s
	umaddl	x21, w6, w13, x21
	umlal	v25.2d, v2.2s, v13.2s
	umaddl	x22, w6, w12, x22
	umlal	v25.2d, v4.2s, v11.2s
	umaddl	x23, w6, w11, x23
	umlal	v25.2d, v6.2s, v19.2s
	umaddl	x24, w6, w10, x24
	umlal	v25.2d, v8.2s, v17.2s
	umaddl	x21, w8, w11, x21
	mul	v15.2s, v15.2s, v31.2s
	umaddl	x22, w8, w10, x22
	umlal	v26.2d, v0.2s, v16.2s
	umaddl	x23, w26, w20, x23
	umlal	v26.2d, v2.2s, v14.2s
	umaddl	x24, w26, w19, x24
	umlal	v26.2d, v4.2s, v12.2s
	umull	x6, w25, w16
	umlal	v26.2d, v6.2s, v10.2s
	umull	x7, w25, w15
	umlal	v26.2d, v8.2s, v18.2s
	umull	x8, w25, w14
	mul	v16.2s, v16.2s, v31.2s
	umaddl	x6, w5, w10, x6
	umull	v24.2d, v1.2s, v13.2s
	mul	w5, w5, w30
	umlal	v24.2d, v3.2s, v11.2s
	umaddl	x7, w27, w17, x7
	umlal	v24.2d, v5.2s, v19.2s
	umaddl	x8, w27, w16, x8
	umlal	v24.2d, v7.2s, v17.2s
	umaddl	x6, w27, w19, x6
	umlal	v24.2d, v9.2s, v15.2s
	umaddl	x7, w5, w20, x7
	umlal	v25.2d, v1.2s, v14.2s
	umaddl	x8, w5, w19, x8
	umlal	v25.2d, v3.2s, v12.2s
	umaddl	x6, w3, w12, x6
	umlal	v25.2d, v5.2s, v10.2s
	umaddl	x7, w3, w11, x7
	umlal	v25.2d, v7.2s, v18.2s
	umaddl	x8, w3, w10, x8
	umlal	v25.2d, v9.2s, v16.2s
	umaddl	x6, w1, w14, x6
	shl	v24.2d, v24.2d, #1
	umaddl	x7, w1, w13, x7
	umull	v23.2d, v0.2s, v13.2s
	umaddl	x8, w1, w12, x8
	umlal	v23.2d, v2.2s, v11.2s
	mul	w9, w4, w30
	umlal	v23.2d, v4.2s, v19.2s
	add	x7, x7, x7
	umlal	v23.2d, v6.2s, v17.2s
	umaddl	x6, w26, w17, x6
	umlal	v23.2d, v8.2s, v15.2s
	umaddl	x7, w26, w16, x7
	mul	v13.2s, v13.2s, v31.2s
	umaddl	x8, w26, w15, x8
	umlal	v24.2d, v0.2s, v14.2s
	umaddl	x6, w28, w20, x6
	umlal	v24.2d, v2.2s, v12.2s
	umaddl	x7, w28, w19, x7
	umlal	v24.2d, v4.2s, v10.2s
	umaddl	x8, w28, w17, x8
	umlal	v24.2d, v6.2s, v18.2s
	umaddl	x6, w4, w11, x6
	umlal	v24.2d, v8.2s, v16.2s
	umaddl	x7, w4, w10, x7
	mul	v14.2s, v14.2s, v31.2s
	umaddl	x8, w9, w20, x8
	umull	v22.2d, v1.2s, v11.2s
	umaddl	x6, w2, w13, x6
	umlal	v22.2d, v3.2s, v19.2s
	umaddl	x7, w2, w12, x7
	umlal	v22.2d, v5.2s, v17.2s
	umaddl	x8, w2, w11, x8
	umlal	v22.2d, v7.2s, v15.2s
	umaddl	x6, w0, w15, x6
	umlal	v22.2d, v9.2s, v13.2s
	umaddl	x7, w0, w14, x7
	umlal	v23.2d, v1.2s, v12.2s
	umaddl	x8, w0, w13, x8
	umlal	v23.2d, v3.2s, v10.2s
	mul	w4, w3, w30
	umlal	v23.2d, v5.2s, v18.2s
	add	x6, x6, x7, lsr #26
	umlal	v23.2d, v7.2s, v16.2s
	and	x7, x7, #0x3ffffff
	umlal	v23.2d, v9.2s, v14.2s
	add	x24, x24, x6, lsr #25
	shl	v22.2d, v22.2d, #1
	and	x6, x6, #0x1ffffff
	umull	v21.2d, v0.2s, v11.2s
	add	x23, x23, x24, lsr #26
	umlal	v21.2d, v2.2s, v19.2s
	and	x24, x24, #0x3ffffff
	umlal	v21.2d, v4.2s, v17.2s
	add	x22, x22, x23, lsr #25
	umlal	v21.2d, v6.2s, v15.2s
	bfi	x24, x23, #32, #25
	umlal	v21.2d, v8.2s, v13.2s
	add	x21, x21, x22, lsr #26
	mul	v11.2s, v11.2s, v31.2s
	and	x22, x22, #0x3ffffff
	umlal	v22.2d, v0.2s, v12.2s
	bic	x3, x21, #0x3ffffff
	umlal	v22.2d, v2.2s, v10.2s
	lsr	x23, x3, #26
	umlal	v22.2d, v4.2s, v18.2s
	bfi	x22, x21, #32, #26
	umlal	v22.2d, v6.2s, v16.2s
	add	x23, x23, x3, lsr #25
	umlal	v22.2d, v8.2s, v14.2s
	umull	x21, w25, w13
	mul	v12.2s, v12.2s, v31.2s
	add	x23, x23, x3, lsr #22
	umull	v20.2d, v1.2s, v19.2s
	umull	x3, w25, w12
	umlal	v20.2d, v3.2s, v17.2s
	umaddl	x23, w25, w11, x23
	umlal	v20.2d, v5.2s, v15.2s
	umaddl	x21, w27, w15, x21
	ushr	v15.2d, v30.2d, #1
	umaddl	x3, w27, w14, x3
	usra	v23.2d, v22.2d, #26
	umaddl	x23, w27, w13, x23
	and	v22.16b, v22.16b, v30.16b
	mul	w27, w1, w30
	umlal	v21.2d, v1.2s, v10.2s
	umaddl	x3, w5, w16, x3
	usra	v24.2d, v23.2d, #25
	umaddl	x23, w5, w15, x23
	and	v23.16b, v23.16b, v15.16b
	umaddl	x21, w5, w17, x21
	umlal	v20.2d, v7.2s, v13.2s
	umaddl	x3, w4, w19, x3
	usra	v25.2d, v24.2d, #26
	umaddl	x23, w4, w17, x23
	and	v24.16b, v24.16b, v30.16b
	umaddl	x21, w4, w20, x21
	umlal	v21.2d, v3.2s, v18.2s
	umaddl	x3, w1, w10, x3
	usra	v26.2d, v25.2d, #25
	umaddl	x23, w27, w20, x23
	and	v25.16b, v25.16b, v15.16b
	umaddl	x21, w1, w11, x21
	umlal	v20.2d, v9.2s, v11.2s
	mul	w25, w2, w30
	usra	v27.2d, v26.2d, #26
	add	x23, x23, x23
	and	v26.16b, v26.16b, v30.16b
	add	x21, x21, x21
	umlal	v21.2d, v5.2s, v16.2s
	umaddl	x23, w26, w12, x23
	umlal	v21.2d, v7.2s, v14.2s
	umaddl	x3, w26, w13, x3
	umlal	v21.2d, v9.2s, v12.2s
	umaddl	x21, w26, w14, x21
	usra	v28.2d, v27.2d, #25
	umaddl	x23, w28, w14, x23
	and	v27.16b, v27.16b, v15.16b
	umaddl	x3, w28, w15, x3
	shl	v20.2d, v20.2d, #1
	umaddl	x21, w28, w16, x21
	usra	v29.2d, v28.2d, #26
	umaddl	x23, w9, w16, x23
	and	v28.16b, v28.16b, v30.16b
	umaddl	x3, w9, w17, x3
	umlal	v20.2d, v0.2s, v10.2s
	umaddl	x21, w9, w19, x21
	umlal	v20.2d, v2.2s, v18.2s
	umaddl	x23, w25, w19, x23
	umlal	v20.2d, v4.2s, v16.2s
	umaddl	x3, w25, w20, x3
	umlal	v20.2d, v6.2s, v14.2s
	umaddl	x21, w2, w10, x21
	umlal	v20.2d, v8.2s, v12.2s
	umaddl	x23, w0, w10, x23
	bic	v19.16b, v29.16b, v15.16b
	umaddl	x3, w0, w11, x3
	and	v29.16b, v29.16b, v15.16b
	umaddl	x21, w0, w12, x21
	usra	v20.2d, v19.2d, #25
	add	x3, x3, x23, lsr #26
		trn1	v0.4s, v0.4s, v1.4s
	and	x23, x23, #0x3ffffff
	usra	v20.2d, v19.2d, #24
	add	x21, x21, x3, lsr #25
		trn1	v1.4s, v2.4s, v3.4s
	bfi	x23, x3, #32, #25
	usra	v20.2d, v19.2d, #21
	add	x8, x8, x21, lsr #26
		trn1	v2.4s, v4.4s, v5.4s
	and	x21, x21, #0x3ffffff
		trn1	v3.4s, v6.4s, v7.4s
	add	x7, x7, x8, lsr #25
	usra	v21.2d, v20.2d, #26
	bfi	x21, x8, #32, #25
	and	v20.16b, v20.16b, v30.16b
	ldr	x2, [sp, #96]
		trn1	v4.4s, v8.4s, v9.4s
	lsr	x3, x2, #32
	usra	v22.2d, v21.2d, #25
	add	x4, sp, #104
	and	v21.16b, v21.16b, v15.16b
	subs	w0, w2, #1
		trn1	v19.4s, v28.4s, v29.4s
	asr	w1, w0, #5
	usra	v23.2d, v22.2d, #26
		add	x6, x6, x7, lsr #26
	and	v22.16b, v22.16b, v30.16b
	ldr	w1, [x4, w1, sxtw #2]
	trn1	v11.4s, v20.4s, v21.4s
	and	w4, w0, #0x1f
	trn1	v13.4s, v22.4s, v23.4s
		and	x7, x7, #0x3ffffff
	trn1	v15.4s, v24.4s, v25.4s
	lsr	w1, w1, w4
	trn1	v17.4s, v26.4s, v27.4s
		bfi	x7, x6, #32, #26
	mov	v10.d[0], v0.d[1]
	stp	w0, w1, [sp, #96]


	eor	w1, w1, w3

	
	// Make X4 and Z5 more compact
	mov	v12.d[0], v1.d[1]
	mov	v14.d[0], v2.d[1]
	mov	v16.d[0], v3.d[1]
	mov	v18.d[0], v4.d[1]

	// Z4 -> Z2
	mov	v1.d[0], x23
	mov	v3.d[0], x21
	mov	v5.d[0], x7
	mov	v7.d[0], x24
	mov	v9.d[0], x22


	// X4 -> X2
	ldr	d28, [sp, #8]
	mov	v0.d[0], v11.d[1]
	ldr	d29, [sp]
	mov	v2.d[0], v13.d[1]
	mov	v4.d[0], v15.d[1]
	mov	v6.d[0], v17.d[1]
	mov	v8.d[0], v19.d[1]

	// X4 -> X2 in v0, v2, ..., v8
	// Z4 -> Z2 in v1, v3, ..., v9
	// X5 -> X3 in v10, v12, ..., v18
	// Z5 -> Z3 in v11, v13, ..., v19

	bpl	.Lmainloop

	mov	w0, v1.s[0]
	mov	w1, v1.s[1]
	mov	w2, v3.s[0]
	mov	w3, v3.s[1]
	mov	w4, v5.s[0]
	mov	w5, v5.s[1]
	mov	w6, v7.s[0]
	mov	w7, v7.s[1]
	mov	w8, v9.s[0]
	mov	w9, v9.s[1]
	
	stp	w0, w1, [sp, #80]
	stp	w2, w3, [sp, #88]
	stp	w4, w5, [sp, #96]
	stp	w6, w7, [sp, #104]
	stp	w8, w9, [sp, #112]
	
	mov	x10, v0.d[0]
	mov	x11, v2.d[0]
	mov	x12, v4.d[0]
	mov	x13, v6.d[0]
	mov	x14, v8.d[0]
	
	stp	x10, x11, [sp]
	stp	x12, x13, [sp, #16]
	str	x14, [sp, #32]
	
	adr	x10, invtable
	str	x10, [sp, #160]
	
.Linvloopnext:
	ldrh	w11, [x10], #2
	mov	v20.s[0], w11
	str	x10, [sp, #160]
	
	and	w12, w11, #0x7f
	subs	w30, w12, #1 // square times
	bmi	.Lskipsquare
	
	mov	w23, w3
	mov	w24, w4
	mov	w25, w5
	mov	w26, w6
	mov	w27, w7
	mov	w14, w8
	add	w10, w0, w0
	add	w11, w1, w1
	add	w12, w2, w2

.Lsqrloop1:
	umull	x20, w0, w0
		add	x4, x24, x23, lsr #25
	umull	x21, w10, w1
		and	x3, x23, #0x1ffffff
	umull	x22, w10, w2
		add	w13, w3, w3
	umull	x23, w10, w3
		add	x5, x25, x4, lsr #26
	umull	x24, w11, w13
		and	x4, x4, #0x3ffffff
	umull	x28, w4, w4
		add	x6, x26, x5, lsr #25
	umull	x25, w12, w3
		and	x5, x5, #0x1ffffff
	umull	x26, w13, w3
		add	w15, w5, w5
	umaddl	x28, w13, w15, x28
		add	x7, x27, x6, lsr #26
	umull	x19, w4, w15
		and	x6, x6, #0x3ffffff
	umull	x27, w11, w6
		add	x8, x14, x7, lsr #25
	umaddl	x28, w12, w6, x28
		and	x7, x7, #0x1ffffff
	umaddl	x19, w13, w6, x19
		add	x9, x9, x8, lsr #26
	umaddl	x27, w10, w7, x27
		add	w17, w7, w7
	umaddl	x28, w11, w17, x28
		and	x8, x8, #0x3ffffff
	umaddl	x19, w10, w9, x19
		add	w14, w9, w9
	umaddl	x27, w12, w5, x27
		add	w16, w14, w14, lsl #1
	umaddl	x28, w10, w8, x28
		add	w3, w15, w15, lsl #1
	umaddl	x19, w12, w7, x19
		add	w16, w16, w14, lsl #4
	umaddl	x27, w13, w4, x27
		add	w3, w3, w15, lsl #4
	umaddl	x28, w16, w9, x28
		
	umaddl	x19, w11, w8, x19
		add	w9, w6, w6, lsl #1
	umaddl	x20, w3, w5, x20
		
	umaddl	x24, w10, w4, x24
		add	w9, w9, w6, lsl #4
	umaddl	x25, w10, w5, x25
		add	x19, x19, x28, lsr #26
	umaddl	x26, w10, w6, x26
		and	x14, x28, #0x3ffffff
	umaddl	x22, w11, w1, x22
		add	x20, x20, x19, lsr #25
	umaddl	x23, w11, w2, x23
		bic	x1, x19, #0x1ffffff
	umaddl	x26, w12, w4, x26
		add	x20, x20, x1, lsr #24
	umaddl	x24, w2, w2, x24
		add	w0, w4, w4
	umaddl	x25, w11, w4, x25
		add	x20, x20, x1, lsr #21
	umaddl	x26, w11, w15, x26
		add	w1, w17, w17, lsl #1
	umaddl	x20, w9, w0, x20
		
	umaddl	x21, w9, w15, x21
		add	w1, w1, w17, lsl #4
	umaddl	x22, w9, w6, x22
		add	w10, w8, w8, lsl #1
	umaddl	x20, w1, w13, x20
		and	x9, x19, #0x1ffffff
	umaddl	x21, w1, w4, x21
		add	w10, w10, w8, lsl #4
	umaddl	x22, w1, w15, x22
		subs	w30, w30, #1
	umaddl	x20, w10, w12, x20
		
	umaddl	x21, w10, w13, x21
		
	umaddl	x22, w10, w0, x22

	umaddl	x20, w16, w11, x20
		
	umaddl	x21, w16, w2, x21
		
	umaddl	x22, w16, w13, x22
		add	w11, w6, w6
	umaddl	x23, w1, w6, x23
		
	umaddl	x24, w1, w7, x24
		add	x21, x21, x20, lsr #26
	umaddl	x26, w10, w8, x26
		and	x0, x20, #0x3ffffff
	umaddl	x23, w10, w15, x23
		add	x22, x22, x21, lsr #25
	umaddl	x24, w10, w11, x24
		and	x1, x21, #0x1ffffff
	umaddl	x25, w10, w17, x25
		and	x2, x22, #0x3ffffff
	umaddl	x23, w16, w4, x23
		add	w10, w0, w0
	umaddl	x24, w16, w15, x24
		add	w11, w1, w1
	umaddl	x25, w16, w6, x25
		add	w12, w2, w2
	umaddl	x26, w16, w17, x26
		add	x23, x23, x22, lsr #26
	umaddl	x27, w16, w8, x27
		bpl	.Lsqrloop1
	
	mov	w11, v20.s[0]
	add	x4, x24, x23, lsr #25
	and	x3, x23, #0x1ffffff
	add	x5, x25, x4, lsr #26
	and	x4, x4, #0x3ffffff
	add	x6, x26, x5, lsr #25
	and	x5, x5, #0x1ffffff
	add	x7, x27, x6, lsr #26
	and	x6, x6, #0x3ffffff
	add	x8, x14, x7, lsr #25
	and	x7, x7, #0x1ffffff
	add	x9, x9, x8, lsr #26
	and	x8, x8, #0x3ffffff
.Lskipsquare:
	mov	w12, #40
	tst	w11, #1<<8
	ubfx	w13, w11, #9, #2
	bne	.Lskipmul
	mul	w20, w13, w12
	add	x20, sp, x20
	
	ldp	w10, w11, [x20]
	ldp	w12, w13, [x20, #8]
	ldp	w14, w15, [x20, #16]
	ldp	w16, w17, [x20, #24]
	ldp	w19, w20, [x20, #32]
	mov	w30, #19
	
	umull	x21, w1, w19
	umull	x22, w1, w17
	umull	x23, w1, w16
	umull	x24, w1, w15
	umaddl	x21, w3, w16, x21
	umaddl	x22, w3, w15, x22
	umaddl	x23, w3, w14, x23
	umaddl	x24, w3, w13, x24
	umaddl	x21, w5, w14, x21
	umaddl	x22, w5, w13, x22
	umaddl	x23, w5, w12, x23
	umaddl	x24, w5, w11, x24
	umaddl	x21, w7, w12, x21
	umaddl	x22, w7, w11, x22
	umaddl	x23, w7, w10, x23
	mul	w27, w7, w30
	mul	w25, w9, w30
	mul	w26, w8, w30
	mul	w28, w6, w30
	umaddl	x24, w27, w20, x24
	umaddl	x21, w9, w10, x21
	umaddl	x22, w25, w20, x22
	umaddl	x23, w25, w19, x23
	umaddl	x24, w25, w17, x24
	add	x22, x22, x22
	umaddl	x21, w0, w20, x21
	add	x24, x24, x24
	umaddl	x22, w0, w19, x22
	umaddl	x23, w0, w17, x23
	umaddl	x24, w0, w16, x24
	umaddl	x21, w2, w17, x21
	umaddl	x22, w2, w16, x22
	umaddl	x23, w2, w15, x23
	umaddl	x24, w2, w14, x24
	umaddl	x21, w4, w15, x21
	umaddl	x22, w4, w14, x22
	umaddl	x23, w4, w13, x23
	umaddl	x24, w4, w12, x24
	umaddl	x21, w6, w13, x21
	umaddl	x22, w6, w12, x22
	umaddl	x23, w6, w11, x23
	umaddl	x24, w6, w10, x24
	umaddl	x21, w8, w11, x21
	umaddl	x22, w8, w10, x22
	umaddl	x23, w26, w20, x23
	umaddl	x24, w26, w19, x24
	umull	x6, w25, w16
	umull	x7, w25, w15
	umull	x8, w25, w14
	umaddl	x6, w5, w10, x6
	mul	w5, w5, w30
	umaddl	x7, w27, w17, x7
	umaddl	x8, w27, w16, x8
	umaddl	x6, w27, w19, x6
	umaddl	x7, w5, w20, x7
	umaddl	x8, w5, w19, x8
	umaddl	x6, w3, w12, x6
	umaddl	x7, w3, w11, x7
	umaddl	x8, w3, w10, x8
	umaddl	x6, w1, w14, x6
	umaddl	x7, w1, w13, x7
	umaddl	x8, w1, w12, x8
	mul	w9, w4, w30
	add	x7, x7, x7
	umaddl	x6, w26, w17, x6
	umaddl	x7, w26, w16, x7
	umaddl	x8, w26, w15, x8
	umaddl	x6, w28, w20, x6
	umaddl	x7, w28, w19, x7
	umaddl	x8, w28, w17, x8
	umaddl	x6, w4, w11, x6
	umaddl	x7, w4, w10, x7
	umaddl	x8, w9, w20, x8
	umaddl	x6, w2, w13, x6
	umaddl	x7, w2, w12, x7
	umaddl	x8, w2, w11, x8
	umaddl	x6, w0, w15, x6
	umaddl	x7, w0, w14, x7
	umaddl	x8, w0, w13, x8
	mul	w4, w3, w30
	add	x6, x6, x7, lsr #26
	and	x7, x7, #0x3ffffff
	add	x24, x24, x6, lsr #25
	and	x6, x6, #0x1ffffff
	add	x23, x23, x24, lsr #26
	and	x24, x24, #0x3ffffff
	add	x22, x22, x23, lsr #25
	bfi	x24, x23, #32, #25
	add	x21, x21, x22, lsr #26
	and	x22, x22, #0x3ffffff
	bic	x3, x21, #0x3ffffff
	lsr	x23, x3, #26
	bfi	x22, x21, #32, #26
	add	x23, x23, x3, lsr #25
	umull	x21, w25, w13
	add	x23, x23, x3, lsr #22
	umull	x3, w25, w12
	umaddl	x23, w25, w11, x23
	umaddl	x21, w27, w15, x21
	umaddl	x3, w27, w14, x3
	umaddl	x23, w27, w13, x23
	mul	w27, w1, w30
	umaddl	x3, w5, w16, x3
	umaddl	x23, w5, w15, x23
	umaddl	x21, w5, w17, x21
	umaddl	x3, w4, w19, x3
	umaddl	x23, w4, w17, x23
	umaddl	x21, w4, w20, x21
	umaddl	x3, w1, w10, x3
	umaddl	x23, w27, w20, x23
	umaddl	x21, w1, w11, x21
	mul	w25, w2, w30
	add	x23, x23, x23
	add	x21, x21, x21
	umaddl	x23, w26, w12, x23
	umaddl	x3, w26, w13, x3
	umaddl	x21, w26, w14, x21
	umaddl	x23, w28, w14, x23
	umaddl	x3, w28, w15, x3
	umaddl	x21, w28, w16, x21
	umaddl	x23, w9, w16, x23
	umaddl	x3, w9, w17, x3
	umaddl	x21, w9, w19, x21
	umaddl	x23, w25, w19, x23
	umaddl	x3, w25, w20, x3
	umaddl	x21, w2, w10, x21
	umaddl	x23, w0, w10, x23
	umaddl	x3, w0, w11, x3
	umaddl	x21, w0, w12, x21
	add	x1, x3, x23, lsr #26
	and	x0, x23, #0x3ffffff
	add	x2, x21, x1, lsr #25
	and	x1, x1, #0x1ffffff
	add	x3, x8, x2, lsr #26
	and	x2, x2, #0x3ffffff
	add	x4, x7, x3, lsr #25
	and	x3, x3, #0x1ffffff
	add	x5, x6, x4, lsr #26
	and	x4, x4, #0x3ffffff
	and	x5, x5, #0x3ffffff
	
	mov	w11, v20.s[0]
	mov	w6, w24
	lsr	x7, x24, #32
	mov	w8, w22
	lsr	x9, x22, #32
.Lskipmul:
	ubfx	w12, w11, #11, #2
	cbz	w12, .Lskipstore
	mov	w13, #40
	mul	w12, w12, w13
	add	x12, sp, x12
	
	stp	w0, w1, [x12]
	stp	w2, w3, [x12, #8]
	stp	w4, w5, [x12, #16]
	stp	w6, w7, [x12, #24]
	stp	w8, w9, [x12, #32]
.Lskipstore:

	ldr	x10, [sp, #160]
	adr	x11, invtable+13*2
	cmp	x10, x11
	bne	.Linvloopnext

	// Final reduce
	// w5 and w9 are 26 bits instead of 25
	
	orr	x10, x0, x1, lsl #26
	orr	x10, x10, x2, lsl #51
	
	lsr	x11, x2, #13
	orr	x11, x11, x3, lsl #13
	orr	x11, x11, x4, lsl #38
	
	add	x12, x5, x6, lsl #25
	adds	x12, x12, x7, lsl #51
	
	lsr	x13, x7, #13
	orr	x13, x13, x8, lsl #12
	orr	x13, x13, x9, lsl #38

	adcs	x13, x13, xzr
	adc	x14, xzr, xzr
	
	extr	x17, x14, x13, #63
	mov	w19, #19
	mul	w15, w17, w19
	add	w15, w15, #19
	
	adds	x15, x10, x15
	adcs	x15, x11, xzr
	adcs	x15, x12, xzr
	adcs	x15, x13, xzr
	adc	x16, x14, xzr
	
	extr	x16, x16, x15, #63
	mul	w16, w16, w19
	
	adds	x10, x10, x16
	adcs	x11, x11, xzr
	adcs	x12, x12, xzr
	adc	x13, x13, xzr
	and	x13, x13, 0x7fffffffffffffff
	
	ldr	x17, [sp, #176]
	stp	x10, x11, [x17] // todo: fix for unaligned store
	stp	x12, x13, [x17, #16]

	add sp, sp, 192
	
	ldp	x19, x20, [sp, #16]
	ldp	x21, x22, [sp, #32]
	ldp	x23, x24, [sp, #48]
	ldp	x25, x26, [sp, #64]
	ldp	x27, x28, [sp, #80]
	ldp	d8, d9, [sp, #96]
	ldp	d10, d11, [sp, #112]
	ldp	d12, d13, [sp, #128]
	ldp	d14, d15, [sp, #144]
	ldp	x29, x30, [sp], #160

	RET
SYM_FUNC_END(crypto_scalarmult_curve25519_armv8)
	
	.type	invtable, %object
invtable:
	//    	square times,
	//    	    skip mul,
	//    	           mulsource,
	//    	                  dest
	.hword	  1|(1<<8)       |(1<<11)
	.hword	  2|       (2<<9)|(2<<11)
	.hword	  0|       (1<<9)|(1<<11)
	.hword	  1|       (2<<9)|(2<<11)
	.hword	  5|       (2<<9)|(2<<11)
	.hword	 10|       (2<<9)|(3<<11)
	.hword	 20|       (3<<9)
	.hword	 10|       (2<<9)|(2<<11)
	.hword	 50|       (2<<9)|(3<<11)
	.hword	100|       (3<<9)
	.hword	 50|       (2<<9)
	.hword	  5|       (1<<9)
	.hword	  0|       (0<<9)
	.size	invtable, .-invtable
