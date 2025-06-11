/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from
+-----------------------------------------------------------------------------+
| This code corresponds to the the paper "Efficient 4-way Vectorizations of   |
| the Montgomery Ladder" authored by   			       	       	      |
| Kaushik Nath,  Indian Statistical Institute, Kolkata, India, and            |
| Palash Sarkar, Indian Statistical Institute, Kolkata, India.	              |
+-----------------------------------------------------------------------------+
| Copyright (c) 2020, Kaushik Nath and Palash Sarkar.                         |
|                                                                             |
| Permission to use this code is granted.                          	      |
|                                                                             |
| Redistribution and use in source and binary forms, with or without          |
| modification, are permitted provided that the following conditions are      |
| met:                                                                        |
|                                                                             |
| * Redistributions of source code must retain the above copyright notice,    |
|   this list of conditions and the following disclaimer.                     |
|                                                                             |
| * Redistributions in binary form must reproduce the above copyright         |
|   notice, this list of conditions and the following disclaimer in the       |
|   documentation and/or other materials provided with the distribution.      |
|                                                                             |
| * The names of the contributors may not be used to endorse or promote       |
|   products derived from this software without specific prior written        |
|   permission.                                                               |
+-----------------------------------------------------------------------------+
| THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY EXPRESS OR       |
| IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES   |
| OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.     |
| IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,      |
| INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT    |
| NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   |
| DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY       |
| THEORY LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING |
| NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,| 
| EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                          |
+-----------------------------------------------------------------------------+
*/

#include "assembler_support.h"
#include "curve448_const.S"

.p2align 5

SYM_FUNC_START(curve448_mladder_avx2)
SYM_FUNC_ENTER(curve448_mladder_avx2)

movq 	  %rsp,%r11
andq 	  $-32,%rsp
subq 	  $2176,%rsp

movq 	  %r11,0(%rsp)
movq 	  %r12,8(%rsp)
movq 	  %r13,16(%rsp)
movq 	  %r14,24(%rsp)
movq 	  %r15,32(%rsp)
movq 	  %rbx,40(%rsp)
movq 	  %rbp,48(%rsp) 

// load (0,0,1,X1)
vmovdqa   0(%rsi),  %ymm8
vmovdqa   32(%rsi), %ymm9
vmovdqa   64(%rsi), %ymm10
vmovdqa   96(%rsi), %ymm11
vmovdqa   128(%rsi),%ymm12
vmovdqa   160(%rsi),%ymm13
vmovdqa   192(%rsi),%ymm14
vmovdqa   224(%rsi),%ymm15
vmovdqa   256(%rsi),%ymm0
vmovdqa   288(%rsi),%ymm1
vmovdqa   320(%rsi),%ymm2
vmovdqa   352(%rsi),%ymm3
vmovdqa   384(%rsi),%ymm4
vmovdqa   416(%rsi),%ymm5
vmovdqa   448(%rsi),%ymm6
vmovdqa   480(%rsi),%ymm7

// <0',0',1',X1'> ← Pack-N2D(<0,0,1,X1>)
vpsllq    $32,%ymm0,%ymm0
vpor      %ymm0,%ymm8,%ymm8
vpsllq    $32,%ymm1,%ymm1
vpor      %ymm1,%ymm9,%ymm9
vpsllq    $32,%ymm2,%ymm2
vpor      %ymm2,%ymm10,%ymm10
vpsllq    $32,%ymm3,%ymm3
vpor      %ymm3,%ymm11,%ymm11
vpsllq    $32,%ymm4,%ymm4
vpor      %ymm4,%ymm12,%ymm12
vpsllq    $32,%ymm5,%ymm5
vpor      %ymm5,%ymm13,%ymm13
vpsllq    $32,%ymm6,%ymm6
vpor      %ymm6,%ymm14,%ymm14
vpsllq    $32,%ymm7,%ymm7
vpor      %ymm7,%ymm15,%ymm15

vmovdqa   %ymm8, 0(%rsi)
vmovdqa   %ymm9, 32(%rsi)
vmovdqa   %ymm10,64(%rsi)
vmovdqa   %ymm11,96(%rsi)
vmovdqa   %ymm12,128(%rsi)
vmovdqa   %ymm13,160(%rsi)
vmovdqa   %ymm14,192(%rsi)
vmovdqa   %ymm15,224(%rsi)

// load <X2,Z2,X3,Z3>
vmovdqa   0(%rdi),  %ymm8
vmovdqa   32(%rdi), %ymm9
vmovdqa   64(%rdi), %ymm10
vmovdqa   96(%rdi), %ymm11
vmovdqa   128(%rdi),%ymm12
vmovdqa   160(%rdi),%ymm13
vmovdqa   192(%rdi),%ymm14
vmovdqa   224(%rdi),%ymm15
vmovdqa   256(%rdi),%ymm0
vmovdqa   288(%rdi),%ymm1
vmovdqa   320(%rdi),%ymm2
vmovdqa   352(%rdi),%ymm3
vmovdqa   384(%rdi),%ymm4
vmovdqa   416(%rdi),%ymm5
vmovdqa   448(%rdi),%ymm6
vmovdqa   480(%rdi),%ymm7

// <X2',Z2',X3',Z3'> ← Pack-N2D(<X2,Z2,X3,Z3>)
vpsllq    $32,%ymm0,%ymm0
vpor      %ymm0,%ymm8,%ymm8
vpsllq    $32,%ymm1,%ymm1
vpor      %ymm1,%ymm9,%ymm9
vpsllq    $32,%ymm2,%ymm2
vpor      %ymm2,%ymm10,%ymm10
vpsllq    $32,%ymm3,%ymm3
vpor      %ymm3,%ymm11,%ymm11
vpsllq    $32,%ymm4,%ymm4
vpor      %ymm4,%ymm12,%ymm12
vpsllq    $32,%ymm5,%ymm5
vpor      %ymm5,%ymm13,%ymm13
vpsllq    $32,%ymm6,%ymm6
vpor      %ymm6,%ymm14,%ymm14
vpsllq    $32,%ymm7,%ymm7
vpor      %ymm7,%ymm15,%ymm15

movq      $55,%r15
movq	  $7,%rcx

movb      $0, %r8b 
movq      %rdx,%rax

.L1:
addq      %r15,%rax
movb      0(%rax),%r14b
movq      %rdx,%rax

.L2:
movb	  %r14b,%bl
shrb      %cl,%bl
andb      $1,%bl

movb      %bl,%r9b
xorb      %r8b,%bl
movb      %r9b,%r8b

// <X2',Z2',X3',Z3'> ← Dense-Swap(<X2',Z2',X3',Z3'>,b)
movzbl    %bl,%ebx
imul	  $4,%ebx,%ebx
movl      %ebx,56(%rsp)
vpbroadcastd 56(%rsp),%ymm1
vpaddd	  swap_c(%rip),%ymm1,%ymm1
vpand     swap_mask(%rip),%ymm1,%ymm1

vpermd	  %ymm8,%ymm1,%ymm8
vpermd	  %ymm9,%ymm1,%ymm9
vpermd	  %ymm10,%ymm1,%ymm10
vpermd	  %ymm11,%ymm1,%ymm11
vpermd	  %ymm12,%ymm1,%ymm12
vpermd	  %ymm13,%ymm1,%ymm13
vpermd	  %ymm14,%ymm1,%ymm14
vpermd	  %ymm15,%ymm1,%ymm15

// <T1',T2',T4',T3'> ← Dense-H-H1(<X2',Z2',X3',Z3'>)
vpshufd	  $68,%ymm8,%ymm1
vpshufd	  $238,%ymm8,%ymm3
vpaddd    hh1_p1(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm8

vpshufd	  $68,%ymm9,%ymm1
vpshufd	  $238,%ymm9,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm9

vpshufd	  $68,%ymm10,%ymm1
vpshufd	  $238,%ymm10,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm10

vpshufd	  $68,%ymm11,%ymm1
vpshufd	  $238,%ymm11,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm11

vpshufd	  $68,%ymm12,%ymm1
vpshufd	  $238,%ymm12,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm12

vpshufd	  $68,%ymm13,%ymm1
vpshufd	  $238,%ymm13,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm13

vpshufd	  $68,%ymm14,%ymm1
vpshufd	  $238,%ymm14,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm14

vpshufd	  $68,%ymm15,%ymm1
vpshufd	  $238,%ymm15,%ymm3
vpaddd    hh1_p2(%rip),%ymm1,%ymm1
vpxor     hh1_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm15

vpsrld    $28,%ymm8,%ymm1
vpaddd    %ymm1,%ymm9,%ymm9
vpand     vecmask28d(%rip),%ymm8,%ymm8

vpsrld    $28,%ymm9,%ymm1
vpaddd    %ymm1,%ymm10,%ymm10
vpand     vecmask28d(%rip),%ymm9,%ymm9

vpsrld    $28,%ymm10,%ymm1
vpaddd    %ymm1,%ymm11,%ymm11
vpand     vecmask28d(%rip),%ymm10,%ymm10

vpsrld    $28,%ymm11,%ymm1
vpaddd    %ymm1,%ymm12,%ymm12
vpand     vecmask28d(%rip),%ymm11,%ymm11

vpsrld    $28,%ymm12,%ymm1
vpaddd    %ymm1,%ymm13,%ymm13
vpand     vecmask28d(%rip),%ymm12,%ymm12

vpsrld    $28,%ymm13,%ymm1
vpaddd    %ymm1,%ymm14,%ymm14
vpand     vecmask28d(%rip),%ymm13,%ymm13

vpsrld    $28,%ymm14,%ymm1
vpaddd    %ymm1,%ymm15,%ymm15
vpand     vecmask28d(%rip),%ymm14,%ymm14

// <T1',T2',T1',T2'> ← Dense-Dup(<T1',T2',T4',T3'>)
vpermq	  $68,%ymm8,%ymm0
vpermq	  $68,%ymm9,%ymm1
vpermq	  $68,%ymm10,%ymm2
vpermq	  $68,%ymm11,%ymm3
vpermq	  $68,%ymm12,%ymm4
vpermq	  $68,%ymm13,%ymm5
vpermq	  $68,%ymm14,%ymm6
vpermq	  $68,%ymm15,%ymm7

// <T1,T2,T1,T2> ← Pack-D2N(<T1',T2',T1',T2'>)
vmovdqa   %ymm8,64(%rsp)

vmovdqa   %ymm0,192(%rsp)
vpsrlq    $32,%ymm0,%ymm8
vmovdqa   %ymm8,448(%rsp)

vmovdqa   %ymm1,224(%rsp)
vpsrlq    $32,%ymm1,%ymm8
vmovdqa   %ymm8,480(%rsp)

vmovdqa   %ymm2,256(%rsp)
vpsrlq    $32,%ymm2,%ymm8
vmovdqa   %ymm8,512(%rsp)

vmovdqa   %ymm3,288(%rsp)
vpsrlq    $32,%ymm3,%ymm8
vmovdqa   %ymm8,544(%rsp)

vmovdqa   %ymm4,320(%rsp)
vpsrlq    $32,%ymm4,%ymm8
vmovdqa   %ymm8,576(%rsp)

vmovdqa   %ymm5,352(%rsp)
vpsrlq    $32,%ymm5,%ymm8
vmovdqa   %ymm8,608(%rsp)

vmovdqa   %ymm6,384(%rsp)
vpsrlq    $32,%ymm6,%ymm8
vmovdqa   %ymm8,640(%rsp)

vmovdqa   %ymm7,416(%rsp)
vpsrlq    $32,%ymm7,%ymm8
vmovdqa   %ymm8,672(%rsp)

vmovdqa   64(%rsp),%ymm8

// <T1,T2,T4,T3> ← Pack-D2N(<T1',T2',T4',T3'>)
vpsrlq    $32,%ymm8,%ymm0
vpsrlq    $32,%ymm9,%ymm1
vpsrlq    $32,%ymm10,%ymm2
vpsrlq    $32,%ymm11,%ymm3
vpsrlq    $32,%ymm12,%ymm4
vpsrlq    $32,%ymm13,%ymm5
vpsrlq    $32,%ymm14,%ymm6
vpsrlq    $32,%ymm15,%ymm7

// <T5,T6,T7,T8> ← Mul(<T1,T2,T4,T3>,<T1,T2,T1,T2>)
vmovdqa   %ymm14,64(%rsp)
vmovdqa   %ymm15,96(%rsp)
vmovdqa   %ymm0,128(%rsp)
vmovdqa   %ymm1,160(%rsp)

vpmuludq  448(%rsp),%ymm0,%ymm15
vmovdqa   %ymm15,704(%rsp)

vpmuludq  480(%rsp),%ymm0,%ymm15
vpmuludq  448(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,736(%rsp)

vpmuludq  512(%rsp),%ymm0,%ymm15
vpmuludq  480(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,768(%rsp)

vpmuludq  544(%rsp),%ymm0,%ymm15
vpmuludq  512(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,800(%rsp)

vpmuludq  576(%rsp),%ymm0,%ymm15
vpmuludq  544(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,832(%rsp)

vpmuludq  608(%rsp),%ymm0,%ymm15
vpmuludq  576(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,864(%rsp)

vpmuludq  640(%rsp),%ymm0,%ymm15
vpmuludq  608(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,896(%rsp)

vpmuludq  672(%rsp),%ymm0,%ymm15
vpmuludq  640(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,928(%rsp)

vpmuludq  672(%rsp),%ymm1,%ymm15
vpmuludq  640(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,960(%rsp)

vpmuludq  672(%rsp),%ymm2,%ymm15
vpmuludq  640(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,992(%rsp)

vpmuludq  672(%rsp),%ymm3,%ymm15
vpmuludq  640(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1024(%rsp)

vpmuludq  672(%rsp),%ymm4,%ymm15
vpmuludq  640(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1056(%rsp)

vpmuludq  672(%rsp),%ymm5,%ymm15
vpmuludq  640(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1088(%rsp)

vpmuludq  672(%rsp),%ymm6,%ymm15
vpmuludq  640(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1120(%rsp)

vpmuludq  672(%rsp),%ymm7,%ymm15
vmovdqa   %ymm15,1152(%rsp)

vmovdqa   64(%rsp),%ymm14
vmovdqa   96(%rsp),%ymm15

vpmuludq  192(%rsp),%ymm8,%ymm1
vmovdqa   %ymm1,1184(%rsp)
vpaddq    704(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,704(%rsp)

vpmuludq  224(%rsp),%ymm8,%ymm1
vpmuludq  192(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1216(%rsp)
vpaddq    736(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,736(%rsp)

vpmuludq  256(%rsp),%ymm8,%ymm1
vpmuludq  224(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1248(%rsp)
vpaddq    768(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,768(%rsp)

vpmuludq  288(%rsp),%ymm8,%ymm1
vpmuludq  256(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1280(%rsp)
vpaddq    800(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,800(%rsp)

vpmuludq  320(%rsp),%ymm8,%ymm1
vpmuludq  288(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1312(%rsp)
vpaddq    832(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,832(%rsp)

vpmuludq  352(%rsp),%ymm8,%ymm1
vpmuludq  320(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1344(%rsp)
vpaddq    864(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,864(%rsp)

vpmuludq  384(%rsp),%ymm8,%ymm1
vpmuludq  352(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1376(%rsp)
vpaddq    896(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,896(%rsp)

vpmuludq  416(%rsp),%ymm8,%ymm1
vpmuludq  384(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1408(%rsp)
vpaddq    928(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,928(%rsp)

vpmuludq  416(%rsp),%ymm9,%ymm1
vpmuludq  384(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1440(%rsp)
vpaddq    960(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,960(%rsp)

vpmuludq  416(%rsp),%ymm10,%ymm1
vpmuludq  384(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1472(%rsp)
vpaddq    992(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,992(%rsp)

vpmuludq  416(%rsp),%ymm11,%ymm1
vpmuludq  384(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1504(%rsp)
vpaddq    1024(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1024(%rsp)

vpmuludq  416(%rsp),%ymm12,%ymm1
vpmuludq  384(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1536(%rsp)
vpaddq    1056(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1056(%rsp)

vpmuludq  416(%rsp),%ymm13,%ymm1
vpmuludq  384(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1568(%rsp)
vpaddq    1088(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1088(%rsp)

vpmuludq  416(%rsp),%ymm14,%ymm1
vpmuludq  384(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1600(%rsp)
vpaddq    1120(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1120(%rsp)

vpmuludq  416(%rsp),%ymm15,%ymm1
vmovdqa   %ymm1,1632(%rsp)
vpaddq    1152(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1152(%rsp)

vpaddq    128(%rsp),%ymm8,%ymm8
vpaddq    160(%rsp),%ymm9,%ymm9
vpaddq    %ymm2,%ymm10,%ymm10
vpaddq    %ymm3,%ymm11,%ymm11
vpaddq    %ymm4,%ymm12,%ymm12
vpaddq    %ymm5,%ymm13,%ymm13
vpaddq    %ymm6,%ymm14,%ymm14
vpaddq    %ymm7,%ymm15,%ymm15

vmovdqa   %ymm14,1664(%rsp)
vmovdqa   %ymm15,1696(%rsp)

vmovdqa   192(%rsp),%ymm0
vmovdqa   224(%rsp),%ymm1
vmovdqa   256(%rsp),%ymm2
vmovdqa   288(%rsp),%ymm3
vmovdqa   320(%rsp),%ymm4
vmovdqa   352(%rsp),%ymm5
vmovdqa   384(%rsp),%ymm6
vmovdqa   416(%rsp),%ymm7

vpaddq    448(%rsp),%ymm0,%ymm0
vpaddq    480(%rsp),%ymm1,%ymm1
vpaddq    512(%rsp),%ymm2,%ymm2
vpaddq    544(%rsp),%ymm3,%ymm3
vpaddq    576(%rsp),%ymm4,%ymm4
vpaddq    608(%rsp),%ymm5,%ymm5
vpaddq    640(%rsp),%ymm6,%ymm6
vpaddq    672(%rsp),%ymm7,%ymm7

vpmuludq  %ymm8,%ymm0,%ymm15
vmovdqa   %ymm15,1728(%rsp)

vpmuludq  %ymm9,%ymm0,%ymm15
vpmuludq  %ymm8,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1760(%rsp)

vpmuludq  %ymm10,%ymm0,%ymm15
vpmuludq  %ymm9,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1792(%rsp)

vpmuludq  %ymm11,%ymm0,%ymm15
vpmuludq  %ymm10,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1824(%rsp)

vpmuludq  %ymm12,%ymm0,%ymm15
vpmuludq  %ymm11,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1856(%rsp)

vpmuludq  %ymm13,%ymm0,%ymm15
vpmuludq  %ymm12,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1888(%rsp)

vpmuludq  1664(%rsp),%ymm0,%ymm15
vpmuludq  %ymm13,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1920(%rsp)

vpmuludq  1696(%rsp),%ymm0,%ymm15
vpmuludq  1664(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm8

vpmuludq  1696(%rsp),%ymm1,%ymm15
vpmuludq  1664(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm9

vpmuludq  1696(%rsp),%ymm2,%ymm15
vpmuludq  1664(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm10

vpmuludq  1696(%rsp),%ymm3,%ymm15
vpmuludq  1664(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm11

vpmuludq  1696(%rsp),%ymm4,%ymm15
vpmuludq  1664(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm12

vpmuludq  1696(%rsp),%ymm5,%ymm15
vpmuludq  1664(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm13

vpmuludq  1696(%rsp),%ymm6,%ymm15
vpmuludq  1664(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm14

vpmuludq  1696(%rsp),%ymm7,%ymm15

vmovdqa   1728(%rsp),%ymm0
vmovdqa   1760(%rsp),%ymm1
vmovdqa   1792(%rsp),%ymm2
vmovdqa   1824(%rsp),%ymm3
vmovdqa   1856(%rsp),%ymm4
vmovdqa   1888(%rsp),%ymm5
vmovdqa   1920(%rsp),%ymm6

vpsubq    1184(%rsp),%ymm0,%ymm0
vpsubq    1216(%rsp),%ymm1,%ymm1
vpsubq    1248(%rsp),%ymm2,%ymm2
vpsubq    1280(%rsp),%ymm3,%ymm3
vpsubq    1312(%rsp),%ymm4,%ymm4
vpsubq    1344(%rsp),%ymm5,%ymm5
vpsubq    1376(%rsp),%ymm6,%ymm6
vpsubq    1408(%rsp),%ymm8,%ymm8
vpsubq    1440(%rsp),%ymm9,%ymm9
vpsubq    1472(%rsp),%ymm10,%ymm10
vpsubq    1504(%rsp),%ymm11,%ymm11
vpsubq    1536(%rsp),%ymm12,%ymm12
vpsubq    1568(%rsp),%ymm13,%ymm13
vpsubq    1600(%rsp),%ymm14,%ymm14
vpsubq    1632(%rsp),%ymm15,%ymm15

vpaddq    960(%rsp),%ymm0,%ymm0
vpaddq    992(%rsp),%ymm1,%ymm1
vpaddq    1024(%rsp),%ymm2,%ymm2
vpaddq    1056(%rsp),%ymm3,%ymm3
vpaddq    1088(%rsp),%ymm4,%ymm4
vpaddq    1120(%rsp),%ymm5,%ymm5
vpaddq    1152(%rsp),%ymm6,%ymm6

vpaddq    %ymm9,%ymm0,%ymm0
vpaddq    %ymm10,%ymm1,%ymm1
vpaddq    %ymm11,%ymm2,%ymm2
vpaddq    %ymm12,%ymm3,%ymm3
vpaddq    %ymm13,%ymm4,%ymm4
vpaddq    %ymm14,%ymm5,%ymm5
vpaddq    %ymm15,%ymm6,%ymm6

vpaddq    704(%rsp),%ymm9,%ymm9
vpaddq    736(%rsp),%ymm10,%ymm10
vpaddq    768(%rsp),%ymm11,%ymm11
vpaddq    800(%rsp),%ymm12,%ymm12
vpaddq    832(%rsp),%ymm13,%ymm13
vpaddq    864(%rsp),%ymm14,%ymm14
vpaddq    896(%rsp),%ymm15,%ymm15

vmovdqa   %ymm8,64(%rsp)

vpsrlq    $28,%ymm9,%ymm7
vpaddq    %ymm7,%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm9,%ymm8

vpsrlq    $28,%ymm0,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vpsrlq    $28,%ymm10,%ymm7
vpaddq    %ymm7,%ymm11,%ymm11
vpand     vecmask28(%rip),%ymm10,%ymm9

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1

vpsrlq    $28,%ymm11,%ymm7
vpaddq    %ymm7,%ymm12,%ymm12
vpand     vecmask28(%rip),%ymm11,%ymm10

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm3,%ymm3
vpand     vecmask28(%rip),%ymm2,%ymm2

vpsrlq    $28,%ymm12,%ymm7
vpaddq    %ymm7,%ymm13,%ymm13
vpand     vecmask28(%rip),%ymm12,%ymm11

vpsrlq    $28,%ymm3,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm3,%ymm3

vpsrlq    $28,%ymm13,%ymm7
vpaddq    %ymm7,%ymm14,%ymm14
vpand     vecmask28(%rip),%ymm13,%ymm12

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4

vpsrlq    $28,%ymm14,%ymm7
vpaddq    %ymm7,%ymm15,%ymm15
vpand     vecmask28(%rip),%ymm14,%ymm13

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm6,%ymm6
vpand     vecmask28(%rip),%ymm5,%ymm5

vmovdqa   %ymm10,768(%rsp)
vpsrlq    $28,%ymm15,%ymm10
vpaddq    928(%rsp),%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm15,%ymm14

vpsrlq    $28,%ymm6,%ymm7
vpaddq    64(%rsp),%ymm7,%ymm7
vpand     vecmask28(%rip),%ymm6,%ymm6

vmovdqa   %ymm11,800(%rsp)
vpsrlq    $28,%ymm10,%ymm11
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm10,%ymm15

vpsrlq    $28,%ymm7,%ymm11
vpaddq    %ymm11,%ymm8,%ymm8
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm7,%ymm7

vpsrlq    $28,%ymm8,%ymm11
vpaddq    %ymm11,%ymm9,%ymm9
vpand     vecmask28(%rip),%ymm8,%ymm8

vpsrlq    $28,%ymm0,%ymm11
vpaddq    %ymm11,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vmovdqa   768(%rsp),%ymm10
vmovdqa   800(%rsp),%ymm11

vmovdqa   %ymm8, 704(%rsp)
vmovdqa   %ymm9, 736(%rsp)
vmovdqa   %ymm12,832(%rsp)
vmovdqa   %ymm13,864(%rsp)
vmovdqa   %ymm14,896(%rsp)
vmovdqa   %ymm15,928(%rsp)
vmovdqa   %ymm0, 960(%rsp)
vmovdqa   %ymm1, 992(%rsp)
vmovdqa   %ymm2, 1024(%rsp)
vmovdqa   %ymm3, 1056(%rsp)
vmovdqa   %ymm4, 1088(%rsp)
vmovdqa   %ymm5, 1120(%rsp)
vmovdqa   %ymm6, 1152(%rsp)
vmovdqa   %ymm7, 1184(%rsp)

// <T5',T6',T7',T8'> ← Pack-N2D(<T5,T6,T7,T8>)
vpsllq    $32,%ymm0,%ymm0
vpor      %ymm0,%ymm8,%ymm8
vpsllq    $32,%ymm1,%ymm1
vpor      %ymm1,%ymm9,%ymm9
vpsllq    $32,%ymm2,%ymm2
vpor      %ymm2,%ymm10,%ymm10
vpsllq    $32,%ymm3,%ymm3
vpor      %ymm3,%ymm11,%ymm11
vpsllq    $32,%ymm4,%ymm4
vpor      %ymm4,%ymm12,%ymm12
vpsllq    $32,%ymm5,%ymm5
vpor      %ymm5,%ymm13,%ymm13
vpsllq    $32,%ymm6,%ymm6
vpor      %ymm6,%ymm14,%ymm14
vpsllq    $32,%ymm7,%ymm7
vpor      %ymm7,%ymm15,%ymm15

// <T9',T10',T11',T12'> ← Dense-H2-H(<T5',T6',T7',T8'>)
vpshufd	  $68,%ymm8,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm8,%ymm3
vpaddd    h2h_p1(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm8

vpshufd	  $68,%ymm9,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm9,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm9

vpshufd	  $68,%ymm10,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm10,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm10

vpshufd	  $68,%ymm11,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm11,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm11

vpshufd	  $68,%ymm12,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm12,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm12

vpshufd	  $68,%ymm13,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm13,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm13

vpshufd	  $68,%ymm14,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm14,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm14

vpshufd	  $68,%ymm15,%ymm1
vpand     h2h_mask(%rip),%ymm1,%ymm1
vpshufd	  $238,%ymm15,%ymm3
vpaddd    h2h_p2(%rip),%ymm1,%ymm1
vpxor     h2h_xor(%rip),%ymm3,%ymm3
vpaddd    %ymm1,%ymm3,%ymm15

vpsrld    $28,%ymm8,%ymm1
vpaddd    %ymm1,%ymm9,%ymm9
vpand     vecmask28d(%rip),%ymm8,%ymm8

vpsrld    $28,%ymm9,%ymm1
vpaddd    %ymm1,%ymm10,%ymm10
vpand     vecmask28d(%rip),%ymm9,%ymm9

vpsrld    $28,%ymm10,%ymm1
vpaddd    %ymm1,%ymm11,%ymm11
vpand     vecmask28d(%rip),%ymm10,%ymm10

vpsrld    $28,%ymm11,%ymm1
vpaddd    %ymm1,%ymm12,%ymm12
vpand     vecmask28d(%rip),%ymm11,%ymm11

vpsrld    $28,%ymm12,%ymm1
vpaddd    %ymm1,%ymm13,%ymm13
vpand     vecmask28d(%rip),%ymm12,%ymm12

vpsrld    $28,%ymm13,%ymm1
vpaddd    %ymm1,%ymm14,%ymm14
vpand     vecmask28d(%rip),%ymm13,%ymm13

vpsrld    $28,%ymm14,%ymm1
vpaddd    %ymm1,%ymm15,%ymm15
vpand     vecmask28d(%rip),%ymm14,%ymm14

// <T9',T10',1',X1'> ← Blend(<0',0',1',X1'>,<T9',T10',T11',T12'>,1100)
vpblendd  $240,0(%rsi),%ymm8,%ymm0
vpblendd  $240,32(%rsi),%ymm9,%ymm1
vpblendd  $240,64(%rsi),%ymm10,%ymm2
vpblendd  $240,96(%rsi),%ymm11,%ymm3
vpblendd  $240,128(%rsi),%ymm12,%ymm4
vpblendd  $240,160(%rsi),%ymm13,%ymm5
vpblendd  $240,192(%rsi),%ymm14,%ymm6
vpblendd  $240,224(%rsi),%ymm15,%ymm7

// <T9,T10,1,X1> ← Pack-D2N(<T9',T10',1',X1'>)
vmovdqa   %ymm0,192(%rsp)
vpsrlq    $32,%ymm0,%ymm0
vmovdqa   %ymm0,448(%rsp)

vmovdqa   %ymm1,224(%rsp)
vpsrlq    $32,%ymm1,%ymm1
vmovdqa   %ymm1,480(%rsp)

vmovdqa   %ymm2,256(%rsp)
vpsrlq    $32,%ymm2,%ymm2
vmovdqa   %ymm2,512(%rsp)

vmovdqa   %ymm3,288(%rsp)
vpsrlq    $32,%ymm3,%ymm3
vmovdqa   %ymm3,544(%rsp)

vmovdqa   %ymm4,320(%rsp)
vpsrlq    $32,%ymm4,%ymm4
vmovdqa   %ymm4,576(%rsp)

vmovdqa   %ymm5,352(%rsp)
vpsrlq    $32,%ymm5,%ymm5
vmovdqa   %ymm5,608(%rsp)

vmovdqa   %ymm6,384(%rsp)
vpsrlq    $32,%ymm6,%ymm6
vmovdqa   %ymm6,640(%rsp)

vmovdqa   %ymm7,416(%rsp)
vpsrlq    $32,%ymm7,%ymm7
vmovdqa   %ymm7,672(%rsp)

// <0,T13,0,0> ← Unreduced-Mulc(<T9,T10,T11,T12>,<0,a24(%rip),0,0>)
// <T5,T14,T7,T8> ← Add(<0,T13,0,0>,<T5,T6,T7,T8>)
vpmuludq  a24(%rip),%ymm8,%ymm0
vpaddq    704(%rsp),%ymm0,%ymm0
vpmuludq  a24(%rip),%ymm9,%ymm1
vpaddq    736(%rsp),%ymm1,%ymm1

vpsrlq    $28,%ymm0,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vpsrlq    $32,%ymm8,%ymm3
vpsrlq    $32,%ymm9,%ymm4

vpmuludq  a24(%rip),%ymm3,%ymm3
vpaddq    960(%rsp),%ymm3,%ymm3
vpmuludq  a24(%rip),%ymm4,%ymm4
vpaddq    992(%rsp),%ymm4,%ymm4

vpsrlq    $28,%ymm3,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm3,%ymm3

vpsrlq    $32,%ymm10,%ymm5
vpmuludq  a24(%rip),%ymm10,%ymm2
vpaddq    768(%rsp),%ymm2,%ymm2
vpmuludq  a24(%rip),%ymm5,%ymm5
vpaddq    1024(%rsp),%ymm5,%ymm5

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1
vmovdqa   %ymm1,736(%rsp)

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4
vmovdqa   %ymm4,992(%rsp)

vpsrlq    $32,%ymm11,%ymm4
vpmuludq  a24(%rip),%ymm11,%ymm1
vpaddq    800(%rsp),%ymm1,%ymm1
vpmuludq  a24(%rip),%ymm4,%ymm4
vpaddq    1056(%rsp),%ymm4,%ymm4

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm2,%ymm2
vmovdqa   %ymm2,768(%rsp)

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm5,%ymm5
vmovdqa   %ymm5,1024(%rsp)

vpsrlq    $32,%ymm12,%ymm5
vpmuludq  a24(%rip),%ymm12,%ymm2
vpaddq    832(%rsp),%ymm2,%ymm2
vpmuludq  a24(%rip),%ymm5,%ymm5
vpaddq    1088(%rsp),%ymm5,%ymm5

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1
vmovdqa   %ymm1,800(%rsp)

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4
vmovdqa   %ymm4,1056(%rsp)

vpsrlq    $32,%ymm13,%ymm4
vpmuludq  a24(%rip),%ymm13,%ymm1
vpaddq    864(%rsp),%ymm1,%ymm1
vpmuludq  a24(%rip),%ymm4,%ymm4
vpaddq    1120(%rsp),%ymm4,%ymm4

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm2,%ymm2
vmovdqa   %ymm2,832(%rsp)

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm5,%ymm5
vmovdqa   %ymm5,1088(%rsp)

vpsrlq    $32,%ymm14,%ymm5
vpmuludq  a24(%rip),%ymm14,%ymm2
vpaddq    896(%rsp),%ymm2,%ymm2
vpmuludq  a24(%rip),%ymm5,%ymm5
vpaddq    1152(%rsp),%ymm5,%ymm5

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1
vmovdqa   %ymm1,864(%rsp)

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4
vmovdqa   %ymm4,1120(%rsp)

vpsrlq    $32,%ymm15,%ymm7
vpmuludq  a24(%rip),%ymm15,%ymm1
vpaddq    928(%rsp),%ymm1,%ymm1
vpmuludq  a24(%rip),%ymm7,%ymm4
vpaddq    1184(%rsp),%ymm4,%ymm4

vpsrlq    $28,%ymm2,%ymm6
vpaddq    %ymm6,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm2,%ymm2
vmovdqa   %ymm2,896(%rsp)

vpsrlq    $28,%ymm5,%ymm6
vpaddq    %ymm6,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm5,%ymm5
vmovdqa   %ymm5,1152(%rsp)

vpsrlq    $28,%ymm1,%ymm6
vpaddq    %ymm6,%ymm3,%ymm3
vpand     vecmask28(%rip),%ymm1,%ymm1
vmovdqa   %ymm1,928(%rsp)

vpsrlq    $28,%ymm4,%ymm6
vpaddq    %ymm6,%ymm0,%ymm0
vmovdqa   %ymm0,704(%rsp)
vpaddq    %ymm6,%ymm3,%ymm3
vmovdqa   %ymm3,960(%rsp)
vpand     vecmask28(%rip),%ymm4,%ymm4
vmovdqa   %ymm4,1184(%rsp)

vpsrlq    $32,%ymm8,%ymm0
vpsrlq    $32,%ymm9,%ymm1
vpsrlq    $32,%ymm10,%ymm2
vpsrlq    $32,%ymm11,%ymm3
vpsrlq    $32,%ymm12,%ymm4
vpsrlq    $32,%ymm13,%ymm5
vpsrlq    $32,%ymm14,%ymm6

// <*,*,T15,T16> ← Sqr(<T9,T10,T11,T12>)
vmovdqa    %ymm0,64(%rsp)
vmovdqa    %ymm1,96(%rsp)

vpermq	  $238,%ymm0,%ymm0
vpblendd  $15,%ymm0,%ymm8,%ymm8
vpermq	  $238,%ymm1,%ymm0
vpblendd  $15,%ymm0,%ymm9,%ymm9
vpermq	  $238,%ymm2,%ymm0
vpblendd  $15,%ymm0,%ymm10,%ymm10
vpermq	  $238,%ymm3,%ymm0
vpblendd  $15,%ymm0,%ymm11,%ymm11
vpermq	  $238,%ymm4,%ymm0
vpblendd  $15,%ymm0,%ymm12,%ymm12
vpermq	  $238,%ymm5,%ymm0
vpblendd  $15,%ymm0,%ymm13,%ymm13
vpermq	  $238,%ymm6,%ymm0
vpblendd  $15,%ymm0,%ymm14,%ymm14
vpermq	  $238,%ymm7,%ymm0
vpblendd  $15,%ymm0,%ymm15,%ymm15

vpmuludq  %ymm8,%ymm8,%ymm1
vmovdqa   %ymm1,1696(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1216(%rsp)

vpmuludq  %ymm9,%ymm8,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,1728(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1248(%rsp)

vpmuludq  %ymm10,%ymm8,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm9,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1760(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1280(%rsp)

vpmuludq  %ymm11,%ymm8,%ymm1
vpmuludq  %ymm10,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,1792(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1312(%rsp)

vpmuludq  %ymm12,%ymm8,%ymm1
vpmuludq  %ymm11,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm10,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1824(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1344(%rsp)

vpmuludq  %ymm13,%ymm8,%ymm1
vpmuludq  %ymm12,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm11,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,1856(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1376(%rsp)

vpmuludq  %ymm14,%ymm8,%ymm1
vpmuludq  %ymm13,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm12,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm11,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1888(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1408(%rsp)

vpmuludq  %ymm15,%ymm8,%ymm1
vpmuludq  %ymm14,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm12,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,1920(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1440(%rsp)

vpmuludq  %ymm15,%ymm9,%ymm1
vpmuludq  %ymm14,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm12,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1952(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1472(%rsp)

vpmuludq  %ymm15,%ymm10,%ymm1
vpmuludq  %ymm14,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,1984(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1504(%rsp)

vpmuludq  %ymm15,%ymm11,%ymm1
vpmuludq  %ymm14,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,2016(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1536(%rsp)

vpmuludq  %ymm15,%ymm12,%ymm1
vpmuludq  %ymm14,%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,2048(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1568(%rsp)

vpmuludq  %ymm15,%ymm13,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm14,%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,2080(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1600(%rsp)

vpmuludq  %ymm15,%ymm14,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vmovdqa   %ymm1,2112(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1632(%rsp)

vpmuludq  %ymm15,%ymm15,%ymm1
vmovdqa   %ymm1,2144(%rsp)
vpermq	  $68,%ymm1,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1664(%rsp)

vpaddq    64(%rsp),%ymm8,%ymm8
vpaddq    96(%rsp),%ymm9,%ymm9
vpaddq    %ymm2,%ymm10,%ymm10
vpaddq    %ymm3,%ymm11,%ymm11
vpaddq    %ymm4,%ymm12,%ymm12
vpaddq    %ymm5,%ymm13,%ymm13
vpaddq    %ymm6,%ymm14,%ymm14
vpaddq    %ymm7,%ymm15,%ymm15

vpermq	  $238,%ymm8,%ymm7
vpblendd  $15,%ymm7,%ymm15,%ymm15
vpermq	  $238,%ymm9,%ymm7
vpblendd  $15,%ymm7,%ymm14,%ymm14
vpermq	  $238,%ymm10,%ymm7
vpblendd  $15,%ymm7,%ymm13,%ymm13
vpermq	  $238,%ymm11,%ymm7
vpblendd  $15,%ymm7,%ymm12,%ymm12
vpermq	  $238,%ymm12,%ymm7
vpblendd  $15,%ymm7,%ymm11,%ymm11
vpermq	  $238,%ymm13,%ymm7
vpblendd  $15,%ymm7,%ymm10,%ymm10
vpermq	  $238,%ymm14,%ymm7
vpblendd  $15,%ymm7,%ymm9,%ymm9
vpermq	  $238,%ymm15,%ymm7
vpblendd  $15,%ymm7,%ymm8,%ymm8

vpmuludq  %ymm15,%ymm8,%ymm1
vpmuludq  %ymm14,%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm12,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm8

vpmuludq  %ymm15,%ymm9,%ymm1
vpmuludq  %ymm14,%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm12,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm9
vpermq	  $68,%ymm9,%ymm6

vpmuludq  %ymm15,%ymm10,%ymm1
vpmuludq  %ymm14,%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm10
vpermq	  $68,%ymm10,%ymm5

vpmuludq  %ymm15,%ymm11,%ymm1
vpmuludq  %ymm14,%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm13,%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm11
vpermq	  $68,%ymm11,%ymm4

vpmuludq  %ymm15,%ymm12,%ymm1
vpmuludq  %ymm14,%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpaddq    %ymm1,%ymm1,%ymm12
vpermq	  $68,%ymm12,%ymm3

vpmuludq  %ymm15,%ymm13,%ymm1
vpaddq    %ymm1,%ymm1,%ymm1
vpmuludq  %ymm14,%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm13
vpermq	  $68,%ymm13,%ymm2

vpmuludq  %ymm15,%ymm14,%ymm1
vpaddq    %ymm1,%ymm1,%ymm14
vpermq	  $68,%ymm14,%ymm1

vpmuludq  %ymm15,%ymm15,%ymm15
vpermq	  $68,%ymm15,%ymm0

vpsubq    1696(%rsp),%ymm0,%ymm0
vpsubq    1728(%rsp),%ymm1,%ymm1
vpsubq    1760(%rsp),%ymm2,%ymm2
vpsubq    1792(%rsp),%ymm3,%ymm3
vpsubq    1824(%rsp),%ymm4,%ymm4
vpsubq    1856(%rsp),%ymm5,%ymm5
vpsubq    1888(%rsp),%ymm6,%ymm6
vpsubq    1920(%rsp),%ymm8,%ymm8
vpsubq    1952(%rsp),%ymm9,%ymm9
vpsubq    1984(%rsp),%ymm10,%ymm10
vpsubq    2016(%rsp),%ymm11,%ymm11
vpsubq    2048(%rsp),%ymm12,%ymm12
vpsubq    2080(%rsp),%ymm13,%ymm13
vpsubq    2112(%rsp),%ymm14,%ymm14
vpsubq    2144(%rsp),%ymm15,%ymm15

vpaddq    1472(%rsp),%ymm0,%ymm0
vpaddq    1504(%rsp),%ymm1,%ymm1
vpaddq    1536(%rsp),%ymm2,%ymm2
vpaddq    1568(%rsp),%ymm3,%ymm3
vpaddq    1600(%rsp),%ymm4,%ymm4
vpaddq    1632(%rsp),%ymm5,%ymm5
vpaddq    1664(%rsp),%ymm6,%ymm6

vpaddq    %ymm9,%ymm0,%ymm0
vpaddq    %ymm10,%ymm1,%ymm1
vpaddq    %ymm11,%ymm2,%ymm2
vpaddq    %ymm12,%ymm3,%ymm3
vpaddq    %ymm13,%ymm4,%ymm4
vpaddq    %ymm14,%ymm5,%ymm5
vpaddq    %ymm15,%ymm6,%ymm6

vpaddq    1216(%rsp),%ymm9,%ymm9
vpaddq    1248(%rsp),%ymm10,%ymm10
vpaddq    1280(%rsp),%ymm11,%ymm11
vpaddq    1312(%rsp),%ymm12,%ymm12
vpaddq    1344(%rsp),%ymm13,%ymm13
vpaddq    1376(%rsp),%ymm14,%ymm14
vpaddq    1408(%rsp),%ymm15,%ymm15

vmovdqa   %ymm8,64(%rsp)

vpsrlq    $28,%ymm9,%ymm7
vpaddq    %ymm7,%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm9,%ymm8

vpsrlq    $28,%ymm0,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vpsrlq    $28,%ymm10,%ymm7
vpaddq    %ymm7,%ymm11,%ymm11
vpand     vecmask28(%rip),%ymm10,%ymm9

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1

vpsrlq    $28,%ymm11,%ymm7
vpaddq    %ymm7,%ymm12,%ymm12
vpand     vecmask28(%rip),%ymm11,%ymm10

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm3,%ymm3
vpand     vecmask28(%rip),%ymm2,%ymm2

vpsrlq    $28,%ymm12,%ymm7
vpaddq    %ymm7,%ymm13,%ymm13
vpand     vecmask28(%rip),%ymm12,%ymm11

vpsrlq    $28,%ymm3,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm3,%ymm3

vpsrlq    $28,%ymm13,%ymm7
vpaddq    %ymm7,%ymm14,%ymm14
vpand     vecmask28(%rip),%ymm13,%ymm12

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4

vpsrlq    $28,%ymm14,%ymm7
vpaddq    %ymm7,%ymm15,%ymm15
vpand     vecmask28(%rip),%ymm14,%ymm13

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm6,%ymm6
vpand     vecmask28(%rip),%ymm5,%ymm5

vmovdqa   %ymm10,96(%rsp)
vpsrlq    $28,%ymm15,%ymm10
vpaddq    1440(%rsp),%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm15,%ymm14

vpsrlq    $28,%ymm6,%ymm7
vpaddq    64(%rsp),%ymm7,%ymm7
vpand     vecmask28(%rip),%ymm6,%ymm6

vmovdqa   %ymm11,128(%rsp)
vpsrlq    $28,%ymm10,%ymm11
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm10,%ymm15

vpsrlq    $28,%ymm7,%ymm11
vpaddq    %ymm11,%ymm8,%ymm8
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm7,%ymm7

vpsrlq    $28,%ymm8,%ymm11
vpaddq    %ymm11,%ymm9,%ymm9
vpand     vecmask28(%rip),%ymm8,%ymm8

vpsrlq    $28,%ymm0,%ymm11
vpaddq    %ymm11,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vmovdqa   96(%rsp),%ymm10
vmovdqa   128(%rsp),%ymm11

// <T5,T14,T15,T16> ← Blend(<T5,T14,T7,T8>,<*,*,T15,T16>,0011)
vpblendd  $15,704(%rsp),%ymm8,%ymm8
vpblendd  $15,736(%rsp),%ymm9,%ymm9
vpblendd  $15,768(%rsp),%ymm10,%ymm10
vpblendd  $15,800(%rsp),%ymm11,%ymm11
vpblendd  $15,832(%rsp),%ymm12,%ymm12
vpblendd  $15,864(%rsp),%ymm13,%ymm13
vpblendd  $15,896(%rsp),%ymm14,%ymm14
vpblendd  $15,928(%rsp),%ymm15,%ymm15
vpblendd  $15,960(%rsp),%ymm0,%ymm0
vpblendd  $15,992(%rsp),%ymm1,%ymm1
vpblendd  $15,1024(%rsp),%ymm2,%ymm2
vpblendd  $15,1056(%rsp),%ymm3,%ymm3
vpblendd  $15,1088(%rsp),%ymm4,%ymm4
vpblendd  $15,1120(%rsp),%ymm5,%ymm5
vpblendd  $15,1152(%rsp),%ymm6,%ymm6
vpblendd  $15,1184(%rsp),%ymm7,%ymm7

// <X2,Z2,X3,Z3> ← Mul(<T5,T14,T15,T16>,<T6,T10,1,X1>)
vmovdqa   %ymm14,64(%rsp)
vmovdqa   %ymm15,96(%rsp)
vmovdqa   %ymm0,128(%rsp)
vmovdqa   %ymm1,160(%rsp)

vpmuludq  448(%rsp),%ymm0,%ymm15
vmovdqa   %ymm15,704(%rsp)

vpmuludq  480(%rsp),%ymm0,%ymm15
vpmuludq  448(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,736(%rsp)

vpmuludq  512(%rsp),%ymm0,%ymm15
vpmuludq  480(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,768(%rsp)

vpmuludq  544(%rsp),%ymm0,%ymm15
vpmuludq  512(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,800(%rsp)

vpmuludq  576(%rsp),%ymm0,%ymm15
vpmuludq  544(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,832(%rsp)

vpmuludq  608(%rsp),%ymm0,%ymm15
vpmuludq  576(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,864(%rsp)

vpmuludq  640(%rsp),%ymm0,%ymm15
vpmuludq  608(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,896(%rsp)

vpmuludq  672(%rsp),%ymm0,%ymm15
vpmuludq  640(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  448(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,928(%rsp)

vpmuludq  672(%rsp),%ymm1,%ymm15
vpmuludq  640(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  480(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,960(%rsp)

vpmuludq  672(%rsp),%ymm2,%ymm15
vpmuludq  640(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  512(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,992(%rsp)

vpmuludq  672(%rsp),%ymm3,%ymm15
vpmuludq  640(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  544(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1024(%rsp)

vpmuludq  672(%rsp),%ymm4,%ymm15
vpmuludq  640(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  576(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1056(%rsp)

vpmuludq  672(%rsp),%ymm5,%ymm15
vpmuludq  640(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  608(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1088(%rsp)

vpmuludq  672(%rsp),%ymm6,%ymm15
vpmuludq  640(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1120(%rsp)

vpmuludq  672(%rsp),%ymm7,%ymm15
vmovdqa   %ymm15,1152(%rsp)

vmovdqa   64(%rsp),%ymm14
vmovdqa   96(%rsp),%ymm15

vpmuludq  192(%rsp),%ymm8,%ymm1
vmovdqa   %ymm1,1184(%rsp)
vpaddq    704(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,704(%rsp)

vpmuludq  224(%rsp),%ymm8,%ymm1
vpmuludq  192(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1216(%rsp)
vpaddq    736(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,736(%rsp)

vpmuludq  256(%rsp),%ymm8,%ymm1
vpmuludq  224(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1248(%rsp)
vpaddq    768(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,768(%rsp)

vpmuludq  288(%rsp),%ymm8,%ymm1
vpmuludq  256(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1280(%rsp)
vpaddq    800(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,800(%rsp)

vpmuludq  320(%rsp),%ymm8,%ymm1
vpmuludq  288(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1312(%rsp)
vpaddq    832(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,832(%rsp)

vpmuludq  352(%rsp),%ymm8,%ymm1
vpmuludq  320(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1344(%rsp)
vpaddq    864(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,864(%rsp)

vpmuludq  384(%rsp),%ymm8,%ymm1
vpmuludq  352(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1376(%rsp)
vpaddq    896(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,896(%rsp)

vpmuludq  416(%rsp),%ymm8,%ymm1
vpmuludq  384(%rsp),%ymm9,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  192(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1408(%rsp)
vpaddq    928(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,928(%rsp)

vpmuludq  416(%rsp),%ymm9,%ymm1
vpmuludq  384(%rsp),%ymm10,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  224(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1440(%rsp)
vpaddq    960(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,960(%rsp)

vpmuludq  416(%rsp),%ymm10,%ymm1
vpmuludq  384(%rsp),%ymm11,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  256(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1472(%rsp)
vpaddq    992(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,992(%rsp)

vpmuludq  416(%rsp),%ymm11,%ymm1
vpmuludq  384(%rsp),%ymm12,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  288(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1504(%rsp)
vpaddq    1024(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1024(%rsp)

vpmuludq  416(%rsp),%ymm12,%ymm1
vpmuludq  384(%rsp),%ymm13,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  320(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1536(%rsp)
vpaddq    1056(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1056(%rsp)

vpmuludq  416(%rsp),%ymm13,%ymm1
vpmuludq  384(%rsp),%ymm14,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vpmuludq  352(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1568(%rsp)
vpaddq    1088(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1088(%rsp)

vpmuludq  416(%rsp),%ymm14,%ymm1
vpmuludq  384(%rsp),%ymm15,%ymm0
vpaddq    %ymm0,%ymm1,%ymm1
vmovdqa   %ymm1,1600(%rsp)
vpaddq    1120(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1120(%rsp)

vpmuludq  416(%rsp),%ymm15,%ymm1
vmovdqa   %ymm1,1632(%rsp)
vpaddq    1152(%rsp),%ymm1,%ymm1
vmovdqa   %ymm1,1152(%rsp)

vpaddq    128(%rsp),%ymm8,%ymm8
vpaddq    160(%rsp),%ymm9,%ymm9
vpaddq    %ymm2,%ymm10,%ymm10
vpaddq    %ymm3,%ymm11,%ymm11
vpaddq    %ymm4,%ymm12,%ymm12
vpaddq    %ymm5,%ymm13,%ymm13
vpaddq    %ymm6,%ymm14,%ymm14
vpaddq    %ymm7,%ymm15,%ymm15

vmovdqa   %ymm14,1664(%rsp)
vmovdqa   %ymm15,1696(%rsp)

vmovdqa   192(%rsp),%ymm0
vmovdqa   224(%rsp),%ymm1
vmovdqa   256(%rsp),%ymm2
vmovdqa   288(%rsp),%ymm3
vmovdqa   320(%rsp),%ymm4
vmovdqa   352(%rsp),%ymm5
vmovdqa   384(%rsp),%ymm6
vmovdqa   416(%rsp),%ymm7

vpaddq    448(%rsp),%ymm0,%ymm0
vpaddq    480(%rsp),%ymm1,%ymm1
vpaddq    512(%rsp),%ymm2,%ymm2
vpaddq    544(%rsp),%ymm3,%ymm3
vpaddq    576(%rsp),%ymm4,%ymm4
vpaddq    608(%rsp),%ymm5,%ymm5
vpaddq    640(%rsp),%ymm6,%ymm6
vpaddq    672(%rsp),%ymm7,%ymm7

vpmuludq  %ymm8,%ymm0,%ymm15
vmovdqa   %ymm15,1728(%rsp)

vpmuludq  %ymm9,%ymm0,%ymm15
vpmuludq  %ymm8,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1760(%rsp)

vpmuludq  %ymm10,%ymm0,%ymm15
vpmuludq  %ymm9,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1792(%rsp)

vpmuludq  %ymm11,%ymm0,%ymm15
vpmuludq  %ymm10,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1824(%rsp)

vpmuludq  %ymm12,%ymm0,%ymm15
vpmuludq  %ymm11,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1856(%rsp)

vpmuludq  %ymm13,%ymm0,%ymm15
vpmuludq  %ymm12,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1888(%rsp)

vpmuludq  1664(%rsp),%ymm0,%ymm15
vpmuludq  %ymm13,%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vmovdqa   %ymm15,1920(%rsp)

vpmuludq  1696(%rsp),%ymm0,%ymm15
vpmuludq  1664(%rsp),%ymm1,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm8,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm8

vpmuludq  1696(%rsp),%ymm1,%ymm15
vpmuludq  1664(%rsp),%ymm2,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm9,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm9

vpmuludq  1696(%rsp),%ymm2,%ymm15
vpmuludq  1664(%rsp),%ymm3,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm10,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm10

vpmuludq  1696(%rsp),%ymm3,%ymm15
vpmuludq  1664(%rsp),%ymm4,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm11,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm11

vpmuludq  1696(%rsp),%ymm4,%ymm15
vpmuludq  1664(%rsp),%ymm5,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm12,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm12

vpmuludq  1696(%rsp),%ymm5,%ymm15
vpmuludq  1664(%rsp),%ymm6,%ymm14
vpaddq    %ymm14,%ymm15,%ymm15
vpmuludq  %ymm13,%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm13

vpmuludq  1696(%rsp),%ymm6,%ymm15
vpmuludq  1664(%rsp),%ymm7,%ymm14
vpaddq    %ymm14,%ymm15,%ymm14

vpmuludq  1696(%rsp),%ymm7,%ymm15

vmovdqa   1728(%rsp),%ymm0
vmovdqa   1760(%rsp),%ymm1
vmovdqa   1792(%rsp),%ymm2
vmovdqa   1824(%rsp),%ymm3
vmovdqa   1856(%rsp),%ymm4
vmovdqa   1888(%rsp),%ymm5
vmovdqa   1920(%rsp),%ymm6

vpsubq    1184(%rsp),%ymm0,%ymm0
vpsubq    1216(%rsp),%ymm1,%ymm1
vpsubq    1248(%rsp),%ymm2,%ymm2
vpsubq    1280(%rsp),%ymm3,%ymm3
vpsubq    1312(%rsp),%ymm4,%ymm4
vpsubq    1344(%rsp),%ymm5,%ymm5
vpsubq    1376(%rsp),%ymm6,%ymm6
vpsubq    1408(%rsp),%ymm8,%ymm8
vpsubq    1440(%rsp),%ymm9,%ymm9
vpsubq    1472(%rsp),%ymm10,%ymm10
vpsubq    1504(%rsp),%ymm11,%ymm11
vpsubq    1536(%rsp),%ymm12,%ymm12
vpsubq    1568(%rsp),%ymm13,%ymm13
vpsubq    1600(%rsp),%ymm14,%ymm14
vpsubq    1632(%rsp),%ymm15,%ymm15

vpaddq    960(%rsp),%ymm0,%ymm0
vpaddq    992(%rsp),%ymm1,%ymm1
vpaddq    1024(%rsp),%ymm2,%ymm2
vpaddq    1056(%rsp),%ymm3,%ymm3
vpaddq    1088(%rsp),%ymm4,%ymm4
vpaddq    1120(%rsp),%ymm5,%ymm5
vpaddq    1152(%rsp),%ymm6,%ymm6

vpaddq    %ymm9,%ymm0,%ymm0
vpaddq    %ymm10,%ymm1,%ymm1
vpaddq    %ymm11,%ymm2,%ymm2
vpaddq    %ymm12,%ymm3,%ymm3
vpaddq    %ymm13,%ymm4,%ymm4
vpaddq    %ymm14,%ymm5,%ymm5
vpaddq    %ymm15,%ymm6,%ymm6

vpaddq    704(%rsp),%ymm9,%ymm9
vpaddq    736(%rsp),%ymm10,%ymm10
vpaddq    768(%rsp),%ymm11,%ymm11
vpaddq    800(%rsp),%ymm12,%ymm12
vpaddq    832(%rsp),%ymm13,%ymm13
vpaddq    864(%rsp),%ymm14,%ymm14
vpaddq    896(%rsp),%ymm15,%ymm15

vmovdqa   %ymm8,64(%rsp)

vpsrlq    $28,%ymm9,%ymm7
vpaddq    %ymm7,%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm9,%ymm8

vpsrlq    $28,%ymm0,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vpsrlq    $28,%ymm10,%ymm7
vpaddq    %ymm7,%ymm11,%ymm11
vpand     vecmask28(%rip),%ymm10,%ymm9

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1

vpsrlq    $28,%ymm11,%ymm7
vpaddq    %ymm7,%ymm12,%ymm12
vpand     vecmask28(%rip),%ymm11,%ymm10

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm3,%ymm3
vpand     vecmask28(%rip),%ymm2,%ymm2

vpsrlq    $28,%ymm12,%ymm7
vpaddq    %ymm7,%ymm13,%ymm13
vpand     vecmask28(%rip),%ymm12,%ymm11

vpsrlq    $28,%ymm3,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm3,%ymm3

vpsrlq    $28,%ymm13,%ymm7
vpaddq    %ymm7,%ymm14,%ymm14
vpand     vecmask28(%rip),%ymm13,%ymm12

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4

vpsrlq    $28,%ymm14,%ymm7
vpaddq    %ymm7,%ymm15,%ymm15
vpand     vecmask28(%rip),%ymm14,%ymm13

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm6,%ymm6
vpand     vecmask28(%rip),%ymm5,%ymm5

vmovdqa   %ymm10,96(%rsp)
vpsrlq    $28,%ymm15,%ymm10
vpaddq    928(%rsp),%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm15,%ymm14

vpsrlq    $28,%ymm6,%ymm7
vpaddq    64(%rsp),%ymm7,%ymm7
vpand     vecmask28(%rip),%ymm6,%ymm6

vmovdqa   %ymm11,128(%rsp)
vpsrlq    $28,%ymm10,%ymm11
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm10,%ymm15

vpsrlq    $28,%ymm7,%ymm11
vpaddq    %ymm11,%ymm8,%ymm8
vpaddq    %ymm11,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm7,%ymm7

vpsrlq    $28,%ymm8,%ymm11
vpaddq    %ymm11,%ymm9,%ymm9
vpand     vecmask28(%rip),%ymm8,%ymm8

vpsrlq    $28,%ymm0,%ymm11
vpaddq    %ymm11,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vmovdqa   96(%rsp),%ymm10
vmovdqa   128(%rsp),%ymm11

// <X2',Z2',X3',Z3'> ← Pack-N2D(<X2,Z2,X3,Z3>)
vpsllq    $32,%ymm0,%ymm0
vpor      %ymm0,%ymm8,%ymm8
vpsllq    $32,%ymm1,%ymm1
vpor      %ymm1,%ymm9,%ymm9
vpsllq    $32,%ymm2,%ymm2
vpor      %ymm2,%ymm10,%ymm10
vpsllq    $32,%ymm3,%ymm3
vpor      %ymm3,%ymm11,%ymm11
vpsllq    $32,%ymm4,%ymm4
vpor      %ymm4,%ymm12,%ymm12
vpsllq    $32,%ymm5,%ymm5
vpor      %ymm5,%ymm13,%ymm13
vpsllq    $32,%ymm6,%ymm6
vpor      %ymm6,%ymm14,%ymm14
vpsllq    $32,%ymm7,%ymm7
vpor      %ymm7,%ymm15,%ymm15

subb      $1,%cl
cmpb	  $0,%cl
jge       .L2

movb	  $7,%cl
subq      $1,%r15
cmpq	  $0,%r15
jge       .L1

// <X2,Z2,X3,Z3> ← Pack-D2N(<X2',Z2',X3',Z3'>)
vpsrlq    $32,%ymm8,%ymm0
vpand     vecmask32(%rip),%ymm8,%ymm8
vpsrlq    $32,%ymm9,%ymm1
vpand     vecmask32(%rip),%ymm9,%ymm9
vpsrlq    $32,%ymm10,%ymm2
vpand     vecmask32(%rip),%ymm10,%ymm10
vpsrlq    $32,%ymm11,%ymm3
vpand     vecmask32(%rip),%ymm11,%ymm11
vpsrlq    $32,%ymm12,%ymm4
vpand     vecmask32(%rip),%ymm12,%ymm12
vpsrlq    $32,%ymm13,%ymm5
vpand     vecmask32(%rip),%ymm13,%ymm13
vpsrlq    $32,%ymm14,%ymm6
vpand     vecmask32(%rip),%ymm14,%ymm14
vpsrlq    $32,%ymm15,%ymm7
vpand     vecmask32(%rip),%ymm15,%ymm15

// <X2,Z2,X3,Z3> ← Reduce(<X2,Z2,X3,Z3>)
vmovdqa   %ymm7,64(%rsp)

vpsrlq    $28,%ymm8,%ymm7
vpaddq    %ymm7,%ymm9,%ymm9
vpand     vecmask28(%rip),%ymm8,%ymm8

vmovdqa   %ymm8,96(%rsp)

vpsrlq    $28,%ymm9,%ymm7
vpaddq    %ymm7,%ymm10,%ymm10
vpand     vecmask28(%rip),%ymm9,%ymm9

vmovdqa   %ymm9,128(%rsp)

vpsrlq    $28,%ymm10,%ymm7
vpaddq    %ymm7,%ymm11,%ymm11
vpand     vecmask28(%rip),%ymm10,%ymm10

vmovdqa   %ymm10,160(%rsp)

vpsrlq    $28,%ymm11,%ymm7
vpaddq    %ymm7,%ymm12,%ymm12
vpand     vecmask28(%rip),%ymm11,%ymm11

vpsrlq    $28,%ymm12,%ymm7
vpaddq    %ymm7,%ymm13,%ymm13
vpand     vecmask28(%rip),%ymm12,%ymm12

vpsrlq    $28,%ymm13,%ymm7
vpaddq    %ymm7,%ymm14,%ymm14
vpand     vecmask28(%rip),%ymm13,%ymm13

vpsrlq    $28,%ymm14,%ymm7
vpaddq    %ymm7,%ymm15,%ymm15
vpand     vecmask28(%rip),%ymm14,%ymm14

vpsrlq    $28,%ymm15,%ymm7
vpaddq    %ymm7,%ymm0,%ymm0
vpand     vecmask28(%rip),%ymm15,%ymm15

vpsrlq    $28,%ymm0,%ymm7
vpaddq    %ymm7,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vpsrlq    $28,%ymm1,%ymm7
vpaddq    %ymm7,%ymm2,%ymm2
vpand     vecmask28(%rip),%ymm1,%ymm1

vpsrlq    $28,%ymm2,%ymm7
vpaddq    %ymm7,%ymm3,%ymm3
vpand     vecmask28(%rip),%ymm2,%ymm2

vpsrlq    $28,%ymm3,%ymm7
vpaddq    %ymm7,%ymm4,%ymm4
vpand     vecmask28(%rip),%ymm3,%ymm3

vpsrlq    $28,%ymm4,%ymm7
vpaddq    %ymm7,%ymm5,%ymm5
vpand     vecmask28(%rip),%ymm4,%ymm4

vpsrlq    $28,%ymm5,%ymm7
vpaddq    %ymm7,%ymm6,%ymm6
vpand     vecmask28(%rip),%ymm5,%ymm5

vpsrlq    $28,%ymm6,%ymm7
vpaddq    64(%rsp),%ymm7,%ymm7
vpand     vecmask28(%rip),%ymm6,%ymm6

vpsrlq    $28,%ymm7,%ymm8
vpaddq    %ymm8,%ymm0,%ymm0
vpaddq    96(%rsp),%ymm8,%ymm8
vpand     vecmask28(%rip),%ymm7,%ymm7

vpsrlq    $28,%ymm8,%ymm9
vpaddq    128(%rsp),%ymm9,%ymm9
vpand     vecmask28(%rip),%ymm8,%ymm8

vpsrlq    $28,%ymm0,%ymm10
vpaddq    %ymm10,%ymm1,%ymm1
vpand     vecmask28(%rip),%ymm0,%ymm0

vmovdqa   160(%rsp),%ymm10

// store <X2,Z2,X3,Z3>
vmovdqa   %ymm8, 0(%rdi)
vmovdqa   %ymm9, 32(%rdi)
vmovdqa   %ymm10,64(%rdi)
vmovdqa   %ymm11,96(%rdi)
vmovdqa   %ymm12,128(%rdi)
vmovdqa   %ymm13,160(%rdi)
vmovdqa   %ymm14,192(%rdi)
vmovdqa   %ymm15,224(%rdi)
vmovdqa   %ymm0, 256(%rdi)
vmovdqa   %ymm1, 288(%rdi)
vmovdqa   %ymm2, 320(%rdi)
vmovdqa   %ymm3, 352(%rdi)
vmovdqa   %ymm4, 384(%rdi)
vmovdqa   %ymm5, 416(%rdi)
vmovdqa   %ymm6, 448(%rdi)
vmovdqa   %ymm7, 480(%rdi)

movq 	  0(%rsp),%r11
movq 	  8(%rsp),%r12
movq 	  16(%rsp),%r13
movq 	  24(%rsp),%r14
movq 	  32(%rsp),%r15
movq 	  40(%rsp),%rbx
movq 	  48(%rsp),%rbp

movq 	  %r11,%rsp

RET
SYM_FUNC_END(curve448_mladder_avx2)

LC_ASM_END
