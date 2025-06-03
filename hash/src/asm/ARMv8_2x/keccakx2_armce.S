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
 * https://github.com/PQClean/PQClean

MIT License

Copyright (c) 2020 Bas Westerbaan
Copyright (c) 2023 - 2025: Hanno Becker, Vincent Hwang, Matthias J. Kannwischer, Bo-Yin Yang, and Shang-Yi Yang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "assembler_support.h"

.irp	b,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
.set	.Lv\b\().2d, \b
.set	.Lv\b\().16b, \b
.endr

// ARMv8.2 Crypto Extensions instructions
.macro	eor3, rd, rn, rm, ra
   .inst 0xce000000 | .L\rd | (.L\rn << 5) | (.L\ra << 10) | (.L\rm << 16)
.endm

.macro	rax1, rd, rn, rm
   .inst 0xce608c00 | .L\rd | (.L\rn << 5) | (.L\rm << 16)
.endm

.macro	bcax, rd, rn, rm, ra
   .inst 0xce200000 | .L\rd | (.L\rn << 5) | (.L\ra << 10) | (.L\rm << 16)
.endm

.macro	xar, rd, rn, rm, imm6
   .inst 0xce800000 | .L\rd | (.L\rn << 5) | ((\imm6) << 10) | (.L\rm << 16)
.endm

.macro round
    // Execute theta, but without xoring into the state yet.
    // Compute parities p[i] = a[i] ^ a[5+i] ^ ... ^ a[20+i].
    eor3 v25.16b, v0.16b, v5.16b, v10.16b
    eor3 v26.16b, v1.16b, v6.16b, v11.16b
    eor3 v27.16b, v2.16b, v7.16b, v12.16b
    eor3 v28.16b, v3.16b, v8.16b, v13.16b
    eor3 v29.16b, v4.16b, v9.16b, v14.16b

    eor3 v25.16b, v25.16b, v15.16b, v20.16b
    eor3 v26.16b, v26.16b, v16.16b, v21.16b
    eor3 v27.16b, v27.16b, v17.16b, v22.16b
    eor3 v28.16b, v28.16b, v18.16b, v23.16b
    eor3 v29.16b, v29.16b, v19.16b, v24.16b

    rax1 v30.2d, v29.2d, v26.2d // d[0] = rotl(p[1], 1) ^ p[4]
    rax1 v29.2d, v27.2d, v29.2d // d[3] = rotl(p[4], 1) ^ p[2]
    rax1 v27.2d, v25.2d, v27.2d // d[1] = rotl(p[2], 1) ^ p[0]
    rax1 v25.2d, v28.2d, v25.2d // d[4] = rotl(p[0], 1) ^ p[3]
    rax1 v28.2d, v26.2d, v28.2d // d[2] = rotl(p[3], 1) ^ p[1]

    // Xor parities from step theta into the state at the same time
    // as executing rho and pi.
    eor v0.16b, v0.16b, v30.16b
    mov v31.16b, v1.16b
    xar v1.2d,  v6.2d,  v27.2d, 20
    xar v6.2d,  v9.2d,  v25.2d, 44
    xar v9.2d,  v22.2d, v28.2d, 3
    xar v22.2d, v14.2d, v25.2d, 25
    xar v14.2d, v20.2d, v30.2d, 46
    xar v20.2d, v2.2d,  v28.2d, 2
    xar v2.2d,  v12.2d, v28.2d, 21
    xar v12.2d, v13.2d, v29.2d, 39
    xar v13.2d, v19.2d, v25.2d, 56
    xar v19.2d, v23.2d, v29.2d, 8
    xar v23.2d, v15.2d, v30.2d, 23
    xar v15.2d, v4.2d,  v25.2d, 37
    xar v4.2d,  v24.2d, v25.2d, 50
    xar v24.2d, v21.2d, v27.2d, 62
    xar v21.2d, v8.2d,  v29.2d, 9
    xar v8.2d,  v16.2d, v27.2d, 19
    xar v16.2d, v5.2d,  v30.2d, 28
    xar v5.2d,  v3.2d,  v29.2d, 36
    xar v3.2d,  v18.2d, v29.2d, 43
    xar v18.2d, v17.2d, v28.2d, 49
    xar v17.2d, v11.2d, v27.2d, 54
    xar v11.2d, v7.2d,  v28.2d, 58
    xar v7.2d,  v10.2d, v30.2d, 61
    xar v10.2d, v31.2d, v27.2d, 63

    // Chi
    bcax v25.16b, v0.16b,  v2.16b,  v1.16b
    bcax v26.16b, v1.16b,  v3.16b,  v2.16b
    bcax v2.16b,  v2.16b,  v4.16b,  v3.16b
    bcax v3.16b,  v3.16b,  v0.16b,  v4.16b
    bcax v4.16b,  v4.16b,  v1.16b,  v0.16b
    mov v0.16b, v25.16b
    mov v1.16b, v26.16b

    bcax v25.16b, v5.16b,  v7.16b,  v6.16b
    bcax v26.16b, v6.16b,  v8.16b,  v7.16b
    bcax v7.16b,  v7.16b,  v9.16b,  v8.16b
    bcax v8.16b,  v8.16b,  v5.16b,  v9.16b
    bcax v9.16b,  v9.16b,  v6.16b,  v5.16b
    mov v5.16b, v25.16b
    mov v6.16b, v26.16b

    bcax v25.16b, v10.16b,  v12.16b,  v11.16b
    bcax v26.16b, v11.16b,  v13.16b,  v12.16b
    bcax v12.16b, v12.16b,  v14.16b,  v13.16b
    bcax v13.16b, v13.16b,  v10.16b,  v14.16b
    bcax v14.16b, v14.16b,  v11.16b,  v10.16b
    mov v10.16b, v25.16b
    mov v11.16b, v26.16b

    bcax v25.16b, v15.16b,  v17.16b,  v16.16b
    bcax v26.16b, v16.16b,  v18.16b,  v17.16b
    bcax v17.16b, v17.16b,  v19.16b,  v18.16b
    bcax v18.16b, v18.16b,  v15.16b,  v19.16b
    bcax v19.16b, v19.16b,  v16.16b,  v15.16b
    mov v15.16b, v25.16b
    mov v16.16b, v26.16b

    bcax v25.16b, v20.16b,  v22.16b,  v21.16b
    bcax v26.16b, v21.16b,  v23.16b,  v22.16b
    bcax v22.16b, v22.16b,  v24.16b,  v23.16b
    bcax v23.16b, v23.16b,  v20.16b,  v24.16b
    bcax v24.16b, v24.16b,  v21.16b,  v20.16b
    mov v20.16b, v25.16b
    mov v21.16b, v26.16b

    // iota
    ld1r {v25.2d}, [x1], #8
    eor v0.16b, v0.16b, v25.16b
.endm

SYM_FUNC_START(keccak_f1600x2_armce)
SYM_FUNC_ENTER(keccak_f1600x2_armce)
.align 4
    stp d8,  d9,  [sp,#-16]!
    stp d10, d11, [sp,#-16]!
    stp d12, d13, [sp,#-16]!
    stp d14, d15, [sp,#-16]!

    mov x2, x0
    mov x3, #24

    ld1 {v0.2d,  v1.2d,  v2.2d,  v3.2d},  [x0], #64
    ld1 {v4.2d,  v5.2d,  v6.2d,  v7.2d},  [x0], #64
    ld1 {v8.2d,  v9.2d,  v10.2d, v11.2d}, [x0], #64
    ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [x0], #64
    ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [x0], #64
    ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [x0], #64
    ld1 {v24.2d}, [x0]

loop:
    round

    subs x3, x3, #1
    cbnz x3, loop

    mov x0, x2
    st1 {v0.2d,  v1.2d,  v2.2d,  v3.2d},  [x0], #64
    st1 {v4.2d,  v5.2d,  v6.2d,  v7.2d},  [x0], #64
    st1 {v8.2d,  v9.2d,  v10.2d, v11.2d}, [x0], #64
    st1 {v12.2d, v13.2d, v14.2d, v15.2d}, [x0], #64
    st1 {v16.2d, v17.2d, v18.2d, v19.2d}, [x0], #64
    st1 {v20.2d, v21.2d, v22.2d, v23.2d}, [x0], #64
    st1 {v24.2d}, [x0]

    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8,  d9,  [sp], #16

    RET lr

SYM_FUNC_END(keccak_f1600x2_armce)

LC_ASM_END
