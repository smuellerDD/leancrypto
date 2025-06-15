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

.p2align 5

SYM_FUNC_START(gfp4482241mul)
SYM_FUNC_ENTER(gfp4482241mul)

movq	%rsp,%r11
subq	$112,%rsp

movq 	%r11,  0(%rsp)
movq 	%r12,  8(%rsp)
movq 	%r13, 16(%rsp)
movq 	%r14, 24(%rsp)
movq 	%r15, 32(%rsp)
movq 	%rbx, 40(%rsp)
movq 	%rbp, 48(%rsp)
movq 	%rdi, 56(%rsp)

movq  	%rdx, %rcx

movq    0(%rsi), %rax
mulq    0(%rcx)
movq    %rax, %r8
movq    %rdx, %r9

movq    8(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

movq    %rax, %r10
movq    %rdx, %r11

movq    0(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    16(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    24(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    32(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    40(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    48(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    48(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r10
adcq    %rdx, %r11

movq    56(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    56(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r10
adcq    %rdx, %r11

movq    40(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

movq  	%r8, 64(%rsp)
movq  	%r9, 72(%rsp)

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r10
adcq    %rdx, %r11

movq    8(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    16(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    24(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    32(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq  	%r10, 80(%rsp)
movq  	%r11, 88(%rsp)

movq    0(%rsi), %rax
mulq    8(%rcx)
movq    %rax, %r12
movq    %rdx, %r13

movq    8(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    16(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    %rax, %r14
movq    %rdx, %r15

movq    24(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %r14
adcq    %rdx, %r15

movq    32(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %r14
adcq    %rdx, %r15

movq    40(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %r14
adcq    %rdx, %r15

movq    48(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %r14
adcq    %rdx, %r15

movq    48(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r14
adcq    %rdx, %r15

movq    56(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %r14
adcq    %rdx, %r15

movq    56(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq	%r12, 96(%rsp)
movq	%r13, 104(%rsp)

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r14
adcq    %rdx, %r15

movq    40(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

movq    32(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

movq    24(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

movq    16(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

movq    8(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

movq    0(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r14
adcq    %rdx, %r15

shld 	$8, %r14, %r15

movq    0(%rsi), %rax
mulq    16(%rcx)
movq    %rax, %r8
movq    %rdx, %r9

movq    8(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

movq    16(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

movq    24(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

movq    %rax, %r10
movq    %rdx, %r11

movq    32(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    40(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    48(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    56(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    56(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$8, %r8, %r9

shld 	$1, %rax, %rdx
shlq	$1, %rax

addq    %rax, %r10
adcq    %rdx, %r11

movq    48(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    40(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    32(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    24(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    16(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    8(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

movq    0(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r10
adcq    %rdx, %r11

shld 	$8, %r10, %r11

movq    0(%rsi), %rax
mulq    24(%rcx)
movq    %rax, %r12
movq    %rdx, %r13

movq    8(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    16(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    24(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    32(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

movq    %rax, %rbp
movq    %rdx, %rbx

movq    40(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %rbp
adcq    %rdx, %rbx

movq    48(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

addq    %rax, %rbp
adcq    %rdx, %rbx

movq    56(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %r12
adcq    %rdx, %r13

shld 	$8, %r12, %r13

addq    %rax, %rbp
adcq    %rdx, %rbx

movq    56(%rsi), %rax
mulq    0(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    48(%rsi), %rax
mulq    8(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    40(%rsi), %rax
mulq    16(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    32(%rsi), %rax
mulq    24(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    24(%rsi), %rax
mulq    32(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    16(%rsi), %rax
mulq    40(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    8(%rsi), %rax
mulq    48(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    0(%rsi), %rax
mulq    56(%rcx)
addq    %rax, %rbp
adcq    %rdx, %rbx

shld 	$8, %rbp, %rbx

movq	64(%rsp), %rsi
movq	72(%rsp), %rdi

movq	96(%rsp), %rax
movq	104(%rsp), %rdx

movq    mask56(%rip), %rcx

shld 	$8, %rsi, %rdi 
shld 	$8, %rax, %rdx

andq  	%rcx, %rsi
andq  	%rcx, %rax
andq  	%rcx, %r8
andq  	%rcx, %r12

addq  	%rdi, %rax
addq  	%rdx, %r8
addq  	%r9, %r12

movq    80(%rsp), %r9
movq    88(%rsp), %rdi
shld 	$8, %r9, %rdi

andq  	%rcx, %r9
andq  	%rcx, %r14
andq  	%rcx, %r10
andq  	%rcx, %rbp

addq  	%r13, %r9
addq  	%rdi, %r14
addq  	%r15, %r10
addq  	%r11, %rbp
addq  	%rbx, %rsi
addq  	%rbx, %r9

movq	%rsi, %r11
shrq	$56, %r11
addq	%rax, %r11
andq	%rcx, %rsi

movq	%r11, %rax
shrq	$56, %r11
addq	%r8, %r11
andq	%rcx, %rax

movq	%r11, %r8
shrq	$56, %r11
addq	%r12, %r11
andq	%rcx, %r8

movq	%r11, %r12
shrq	$56, %r11
addq	%r9, %r11
andq	%rcx, %r12

movq	%r11, %r9
shrq	$56, %r11
addq	%r14, %r11
andq	%rcx, %r9

movq	%r11, %r14
shrq	$56, %r11
addq	%r10, %r11
andq	%rcx, %r14

movq	%r11, %r10
shrq	$56, %r11
addq	%rbp, %r11
andq	%rcx, %r10

movq	%r11, %rbp
shrq	$56, %r11
addq	%r11, %rsi
addq	%r11, %r9
andq	%rcx, %rbp

movq 	56(%rsp), %rdi

movq   	%rsi,  0(%rdi)
movq   	%rax,  8(%rdi)
movq   	%r8,  16(%rdi)
movq   	%r12, 24(%rdi)
movq   	%r9,  32(%rdi)
movq   	%r14, 40(%rdi)
movq   	%r10, 48(%rdi)
movq   	%rbp, 56(%rdi)

movq 	0(%rsp),  %r11
movq 	8(%rsp),  %r12
movq 	16(%rsp), %r13
movq 	24(%rsp), %r14
movq 	32(%rsp), %r15
movq 	40(%rsp), %rbx
movq 	48(%rsp), %rbp

movq	%r11, %rsp

RET
SYM_FUNC_END(gfp4482241mul)

.p2align 5
STACK_FRAME_NON_STANDARD(gfp4482241reduce)
SYM_FUNC_START(gfp4482241reduce)
SYM_FUNC_ENTER(gfp4482241reduce)

movq 	%rsp, %r11
subq 	$16,%rsp

movq 	%r11, 0(%rsp)
movq 	%rdi, 8(%rsp)

movq    0(%rdi), %r8
movq    8(%rdi), %r9
movq    16(%rdi), %r10
movq    24(%rdi), %r11
movq    32(%rdi), %rax
movq    40(%rdi), %rcx
movq    48(%rdi), %rdx
movq    56(%rdi), %rsi

movq    mask56(%rip), %r15

movq	%r8, %rdi
andq	%r15, %r8
shrq	$56, %rdi
addq	%rdi, %r9

movq	%r9, %rdi
andq	%r15, %r9
shrq	$56, %rdi
addq	%rdi, %r10

movq	%r10, %rdi
andq	%r15, %r10
shrq	$56, %rdi
addq	%rdi, %r11

movq	%r11, %rdi
andq	%r15, %r11
shrq	$56, %rdi
addq	%rdi, %rax

movq	%rax, %rdi
andq	%r15, %rax
shrq	$56, %rdi
addq	%rdi, %rcx

movq	%rcx, %rdi
andq	%r15, %rcx
shrq	$56, %rdi
addq	%rdi, %rdx

movq	%rdx, %rdi
andq	%r15, %rdx
shrq	$56, %rdi
addq	%rdi, %rsi

movq	%rsi, %rdi
andq	%r15, %rsi
shrq	$56, %rdi
addq	%rdi, %r8
addq	%rdi, %rax

movq	%r8, %rdi
andq	%r15, %r8
shrq	$56, %rdi
addq	%rdi, %r9

movq	%rax, %rdi
andq	%r15, %rax
shrq	$56, %rdi
addq	%rdi, %rcx

movq 	8(%rsp), %rdi

movq   	%r8,  0(%rdi)
movq   	%r9,  8(%rdi)
movq   	%r10, 16(%rdi)
movq   	%r11, 24(%rdi)
movq   	%rax, 32(%rdi)
movq   	%rcx, 40(%rdi)
movq   	%rdx, 48(%rdi)
movq   	%rsi, 56(%rdi)

movq 	 0(%rsp), %rsp

RET
SYM_FUNC_END(gfp4482241reduce)
