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

SYM_FUNC_START(gfp4482241nsqr)
SYM_FUNC_ENTER(gfp4482241nsqr)

movq 	%rsp,%r11
subq 	$112,%rsp

movq 	%r11,  0(%rsp)
movq 	%r12,  8(%rsp)
movq 	%r13, 16(%rsp)
movq 	%r14, 24(%rsp)
movq 	%r15, 32(%rsp)
movq 	%rbx, 40(%rsp)
movq 	%rbp, 48(%rsp)
movq 	%rdi, 56(%rsp)

movq 	 0(%rsi), %r8
movq 	 8(%rsi), %r9
movq 	16(%rsi), %r10
movq 	24(%rsi), %r11
movq 	32(%rsi), %r12
movq 	40(%rsi), %r13
movq 	48(%rsi), %r14
movq 	56(%rsi), %r15

movq 	%r8,   0(%rdi)
movq 	%r9,   8(%rdi)
movq 	%r10, 16(%rdi)
movq 	%r11, 24(%rdi)
movq 	%r12, 32(%rdi)
movq 	%r13, 40(%rdi)
movq 	%r14, 48(%rdi)
movq 	%r15, 56(%rdi)

movq  	%rdx, %rcx

.START:

subq  	$1, %rcx
movq	%rcx, 64(%rsp)

movq    8(%rdi), %rax
mulq    56(%rdi)
movq    %rax, %r8
movq    %rdx, %r9

movq    16(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

movq    24(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

movq    %r8, %rcx
movq    %r9, %r11

movq    40(%rdi), %rax
mulq    56(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$1, %r8, %r9	
shlq    $1, %r8

shld 	$1, %rax, %rdx	
shlq    $1, %rax

addq    %rax, %rcx
adcq    %rdx, %r11

movq    0(%rdi), %rax
mulq    32(%rdi)
addq    %rax, %rcx
adcq    %rdx, %r11

movq    8(%rdi), %rax
mulq    24(%rdi)
addq    %rax, %rcx
adcq    %rdx, %r11

movq    48(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %rcx
adcq    %rdx, %r11

shld 	$1, %rcx, %r11	
shlq    $1, %rcx

movq    32(%rdi), %rax
mulq    32(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %rcx
adcq    %rdx, %r11

movq    0(%rdi), %rax
mulq    0(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

movq    16(%rdi), %rax
mulq    16(%rdi)
addq    %rax, %rcx
adcq    %rdx, %r11

movq  	%r8,  72(%rsp)
movq  	%r9,  80(%rsp)

movq  	%r11, 88(%rsp)

movq    16(%rdi), %rax
mulq    56(%rdi)
movq    %rax, %r12
movq    %rdx, %r13

movq    24(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

movq    32(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

movq    %r12, %r14
movq    %r13, %r15

movq    48(%rdi), %rax
mulq    56(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

shld 	$1, %rax, %rdx
shlq    $1, %rax	

addq    %rax, %r14
adcq    %rdx, %r15

movq    0(%rdi), %rax
mulq    8(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

shld 	$1, %r12, %r13
shlq    $1, %r12

movq	%r12, 96(%rsp)
movq	%r13, 104(%rsp)

movq    16(%rdi), %rax
mulq    24(%rdi)
addq    %rax, %r14
adcq    %rdx, %r15

movq    8(%rdi), %rax
mulq    32(%rdi)
addq    %rax, %r14
adcq    %rdx, %r15

movq    0(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %r14
adcq    %rdx, %r15

shld 	$1, %r14, %r15
shlq    $1, %r14

shld 	$8, %r14, %r15

movq    24(%rdi), %rax
mulq    56(%rdi)
movq    %rax, %r8
movq    %rdx, %r9

movq    32(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

movq    %r8, %r10
movq    %r9, %r11

movq    0(%rdi), %rax
mulq    16(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$1, %r8, %r9
shlq    $1, %r8

movq    0(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r10
adcq    %rdx, %r11

movq    8(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %r10
adcq    %rdx, %r11

movq    16(%rdi), %rax
mulq    32(%rdi)
addq    %rax, %r10
adcq    %rdx, %r11

movq    56(%rdi), %rax
mulq    56(%rdi)
addq    %rax, %r10
adcq    %rdx, %r11

shld 	$1, %r10, %r11
shlq    $1, %r10

addq    %rax, %r8
adcq    %rdx, %r9

movq    40(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

addq    %rax, %r10
adcq    %rdx, %r11

movq    8(%rdi), %rax
mulq    8(%rdi)
addq    %rax, %r8
adcq    %rdx, %r9

shld 	$8, %r8, %r9

movq    24(%rdi), %rax
mulq    24(%rdi)
addq    %rax, %r10
adcq    %rdx, %r11

shld 	$8, %r10, %r11

movq    32(%rdi), %rax
mulq    56(%rdi)
movq    %rax, %r12
movq    %rdx, %r13

movq    40(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

movq    %r12, %rbp
movq    %r13, %rbx

movq    8(%rdi), %rax
mulq    16(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

movq    0(%rdi), %rax
mulq    24(%rdi)
addq    %rax, %r12
adcq    %rdx, %r13

shld 	$1, %r12, %r13
shlq    $1, %r12

shld 	$8, %r12, %r13

movq    24(%rdi), %rax
mulq    32(%rdi)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    16(%rdi), %rax
mulq    40(%rdi)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    8(%rdi), %rax
mulq    48(%rdi)
addq    %rax, %rbp
adcq    %rdx, %rbx

movq    0(%rdi), %rax
mulq    56(%rdi)
addq    %rax, %rbp
adcq    %rdx, %rbx

shld 	$1, %rbp, %rbx
shlq    $1, %rbp

shld 	$8, %rbp, %rbx

movq	72(%rsp), %rsi
movq	80(%rsp), %rdi

movq	96(%rsp), %rax
movq	104(%rsp), %rdx

shld 	$8, %rsi, %rdi 
shld 	$8, %rax, %rdx

andq  	mask56(%rip), %rax
addq  	%rdi, %rax

movq    mask56(%rip), %rdi
andq  	%rdi, %rsi
andq  	%rdi, %r8
andq  	%rdi, %r12

addq  	%rdx, %r8
addq  	%r9, %r12

movq	88(%rsp), %r9
shld 	$8, %rcx, %r9

andq  	%rdi, %rcx
andq  	%rdi, %r14
andq  	%rdi, %r10
andq  	%rdi, %rbp

addq  	%r13, %rcx
addq  	%r9, %r14
addq  	%r15, %r10
addq  	%r11, %rbp
addq  	%rbx, %rsi
addq  	%rbx, %rcx

movq	%rsi, %r11
shrq	$56, %r11
addq	%rax, %r11
andq	mask56(%rip), %rsi

movq	%r11, %rax
shrq	$56, %r11
addq	%r8, %r11
andq	mask56(%rip), %rax

movq	%r11, %r8
shrq	$56, %r11
addq	%r12, %r11
andq	mask56(%rip), %r8

movq	%r11, %r12
shrq	$56, %r11
addq	%rcx, %r11
andq	mask56(%rip), %r12

movq	%r11, %rcx
shrq	$56, %r11
addq	%r14, %r11
andq	mask56(%rip), %rcx

movq	%r11, %r14
shrq	$56, %r11
addq	%r10, %r11
andq	mask56(%rip), %r14

movq	%r11, %r10
shrq	$56, %r11
addq	%rbp, %r11
andq	mask56(%rip), %r10

movq	%r11, %rbp
shrq	$56, %r11
addq	%r11, %rsi
addq	%r11, %rcx
andq	mask56(%rip), %rbp

movq 	56(%rsp), %rdi

movq   	%rsi,  0(%rdi)
movq   	%rax,  8(%rdi)
movq   	%r8,  16(%rdi)
movq   	%r12, 24(%rdi)
movq   	%rcx, 32(%rdi)
movq   	%r14, 40(%rdi)
movq   	%r10, 48(%rdi)
movq   	%rbp, 56(%rdi)

movq	64(%rsp), %rcx
cmpq    $0, %rcx

jne     .START

movq 	0(%rsp),  %r11
movq 	8(%rsp),  %r12
movq 	16(%rsp), %r13
movq 	24(%rsp), %r14
movq 	32(%rsp), %r15
movq 	40(%rsp), %rbx
movq 	48(%rsp), %rbp

movq 	%r11, %rsp

RET
SYM_FUNC_END(gfp4482241nsqr)

LC_ASM_END
