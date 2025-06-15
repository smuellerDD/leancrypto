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

SYM_FUNC_START(gfp4482241nsqrx)
SYM_FUNC_ENTER(gfp4482241nsqrx)

movq    %rsp, %r11
subq    $104, %rsp

movq    %r11,  0(%rsp)
movq    %r12,  8(%rsp)
movq    %r13, 16(%rsp)
movq    %r14, 24(%rsp)
movq    %r15, 32(%rsp)
movq    %rbp, 40(%rsp)
movq    %rbx, 48(%rsp)
movq    %rdi, 56(%rsp)

movq    0(%rsi),  %r8
movq    8(%rsi),  %r9  
movq    16(%rsi), %r10
movq    24(%rsi), %r11
movq    32(%rsi), %r12
movq    40(%rsi), %r13
movq    48(%rsi), %r14

movq    %r8,   0(%rdi)	
movq    %r9,   8(%rdi)	
movq    %r10, 16(%rdi)	
movq    %r11, 24(%rdi)
movq    %r12, 32(%rdi)
movq    %r13, 40(%rdi)
movq    %r14, 48(%rdi)

movq    %rdx, %rbx

.START_nsqrx:

decq    %rbx
movq    %rbx, 96(%rsp)

movq    0(%rdi), %rdx
xorq    %r8, %r8
    
mulx    8(%rdi), %r9, %r10

mulx    16(%rdi), %rcx, %r11
adcx    %rcx, %r10

mulx    24(%rdi), %rcx, %r12
adcx    %rcx, %r11

mulx    32(%rdi), %rcx, %r13
adcx    %rcx, %r12

mulx    40(%rdi), %rcx, %r14
adcx    %rcx, %r13

mulx    48(%rdi), %rcx, %r15
adcx    %rcx, %r14
adcx    %r8, %r15
    
movq    %r9, 64(%rsp)

movq    8(%rdi), %rdx
xorq    %r9, %r9
    
mulx    16(%rdi), %rcx, %rbp
adcx    %rcx, %r11
adox    %rbp, %r12

mulx    24(%rdi), %rcx, %rbp
adcx    %rcx, %r12
adox    %rbp, %r13

mulx    32(%rdi), %rcx, %rbp
adcx    %rcx, %r13
adox    %rbp, %r14

mulx    40(%rdi), %rcx, %rbp
adcx    %rcx, %r14
adox    %rbp, %r15

mulx    48(%rdi), %rcx, %rbp
adcx    %rcx, %r15
adox    %rbp, %r8
adcx    %r9, %r8
    
movq    %r10, 72(%rsp)

movq    16(%rdi), %rdx
xorq    %r10, %r10

mulx    24(%rdi), %rcx, %rbp
adcx    %rcx, %r13
adox    %rbp, %r14

mulx    32(%rdi), %rcx, %rbp
adcx    %rcx, %r14
adox    %rbp, %r15

mulx    40(%rdi), %rcx, %rbp
adcx    %rcx, %r15
adox    %rbp, %r8

mulx    48(%rdi), %rcx, %rbp
adcx    %rcx, %r8
adox    %rbp, %r9
adcx    %r10, %r9

movq    %r11, 80(%rsp)

movq    24(%rdi), %rdx
xorq    %r11, %r11

mulx    32(%rdi), %rcx, %rbp
adcx    %rcx, %r15
adox    %rbp, %r8

mulx    40(%rdi), %rcx, %rbp
adcx    %rcx, %r8
adox    %rbp, %r9

mulx    48(%rdi), %rcx, %rbp
adcx    %rcx, %r9
adox    %rbp, %r10
adcx    %r11, %r10

movq    32(%rdi), %rdx
xorq    %rax, %rax

mulx    40(%rdi), %rcx, %rbp
adcx    %rcx, %r9
adox    %rbp, %r10

mulx    48(%rdi), %rcx, %rbp
adcx    %rcx, %r10
adox    %rbp, %r11
adcx    %rax, %r11

movq    40(%rdi), %rdx

mulx    48(%rdi), %rcx, %rsi
adcx    %rcx, %r11
adcx    %rax, %rsi

movq    64(%rsp), %rax
movq    72(%rsp), %rcx
movq    80(%rsp), %rdx

movq    $0, %rbp
shld    $1, %rsi, %rbp
shld    $1, %r11, %rsi
shld    $1, %r10, %r11
shld    $1, %r9,  %r10
shld    $1, %r8,  %r9
shld    $1, %r15, %r8
shld    $1, %r14, %r15
shld    $1, %r13, %r14
shld    $1, %r12, %r13
shld    $1, %rdx, %r12
shld    $1, %rcx, %rdx
shld    $1, %rax, %rcx
shlq    $1, %rax

movq    %rax, 64(%rsp)
movq    %rcx, 72(%rsp)		
movq    %rdx, 80(%rsp)		
movq    %r12, 88(%rsp)
	  
xorq    %rdx, %rdx
movq    0(%rdi), %rdx
mulx    %rdx, %r12, %rax
adcx    64(%rsp), %rax
movq    %rax, 64(%rsp)

movq    8(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    72(%rsp), %rcx
adcx    80(%rsp), %rax
movq    %rcx, 72(%rsp)
movq    %rax, 80(%rsp)

movq    16(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    88(%rsp), %rcx
adcx    %rax, %r13
movq    %rcx, 88(%rsp)

movq    24(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    %rcx, %r14
adcx    %rax, %r15

movq    32(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    %rcx, %r8
adcx    %rax, %r9

movq    40(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    %rcx, %r10
adcx    %rax, %r11

movq    48(%rdi), %rdx
mulx    %rdx, %rcx, %rax
adcx    %rcx, %rsi
adcx    %rax, %rbp

movq    64(%rsp), %rax
movq    72(%rsp), %rbx
movq    80(%rsp), %rcx
movq    88(%rsp), %rdx
  
xorq    %rdi, %rdi
adcx    %r15, %r12
adcx    %r8,  %rax
adcx    %r9,  %rbx
adcx    %r10, %rcx
adcx    %r11, %rdx
adcx    %rsi, %r13
adcx    %rbp, %r14
adcx    %rdi, %rdi
    
movq    %r12, 64(%rsp)

movq    $0,  %r12
shld    $32, %rbp, %r12
shld    $32, %rsi, %rbp
shld    $32, %r11, %rsi
shld    $32, %r10, %r11
shld    $32, %r9,  %r10
shld    $32, %r8,  %r9
shld    $32, %r15, %r8
shlq    $32, %r15

addq    %r15, %rcx
adcq    %r8,  %rdx
adcq    %r9,  %r13
adcq    %r10, %r14
adcq    %rdi, %r11
adcq    $0, %rsi
adcq    $0, %rbp
adcq    $0, %r12

movq    64(%rsp), %r15
    
xorq    %r8, %r8
adcx    %r11, %r15
adcx    %rsi, %rax
adcx    %rbp, %rbx
adcx    %r12, %rcx
adcx    %r8, %rdx
adcx    %r8, %r13
adcx    %r8, %r14
adcx    %r8, %r8

movq    $0,  %rdi
shld    $32, %r12, %rdi
shld    $32, %rbp, %r12
shld    $32, %rsi, %rbp
shld    $32, %r11, %rsi
shlq    $32, %r11

xorq    %r9, %r9
adcx    %r11, %rcx
adcx    %rsi, %rdx
adcx    %rbp, %r13
adcx    %r12, %r14
adcx    %rdi, %r8

movq    %r8, %r10
shlq    $32, %r10

xorq    %r9, %r9
addq    %r8, %r15
adcq    $0, %rax
adcq    $0, %rbx
adcq    %r10, %rcx
adcq    $0, %rdx
adcq    $0, %r13
adcq    $0, %r14
adcq    $0, %r9

movq    %r9, %r10
shlq    $32, %r10

addq    %r9, %r15
adcq    $0, %rax
adcq    $0, %rbx
adcq    %r10, %rcx
adcq    $0, %rdx
    
movq    56(%rsp), %rdi

movq    %r15,  0(%rdi)
movq    %rax,  8(%rdi)
movq    %rbx, 16(%rdi)
movq    %rcx, 24(%rdi)
movq    %rdx, 32(%rdi)
movq    %r13, 40(%rdi)
movq    %r14, 48(%rdi)

movq    96(%rsp), %rbx
cmp     $0, %rbx

jne     .START_nsqrx

movq    0(%rsp), %r11
movq    8(%rsp), %r12
movq    16(%rsp), %r13
movq    24(%rsp), %r14
movq    32(%rsp), %r15
movq    40(%rsp), %rbp
movq    48(%rsp), %rbx

movq    %r11, %rsp

RET

SYM_FUNC_END(gfp4482241nsqrx)
