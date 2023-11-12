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
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023
 * Frank Denis <j at pureftpd dot org>
 */

/*
   This file is adapted from amd64-51/fe25519_square.s:
   Adding loop to perform n squares.
*/
.p2align 5

SYM_FUNC_START(curve25519_fe51_nsquare_avx)
SYM_FUNC_ENTER(curve25519_fe51_nsquare_avx)

mov %rsp,%r11
and $31,%r11
add $64,%r11
sub %r11,%rsp
movq %r11,0(%rsp)
movq %r12,8(%rsp)
movq %r13,16(%rsp)
movq %r14,24(%rsp)
movq %r15,32(%rsp)
movq %rbx,40(%rsp)
movq %rbp,48(%rsp)
movq   0(%rsi),%rcx
movq   8(%rsi),%r8
movq   16(%rsi),%r9
movq   24(%rsi),%rax
movq   32(%rsi),%rsi
movq   %r9,16(%rdi)
movq   %rax,24(%rdi)
movq   %rsi,32(%rdi)
mov  %rdx,%rsi

.p2align 4
._loop:
sub  $1,%rsi
mov  %rcx,%rax
mul  %rcx
add  %rcx,%rcx
mov  %rax,%r9
mov  %rdx,%r10
mov  %rcx,%rax
mul  %r8
mov  %rax,%r11
mov  %rdx,%r12
mov  %rcx,%rax
mulq  16(%rdi)
mov  %rax,%r13
mov  %rdx,%r14
mov  %rcx,%rax
mulq  24(%rdi)
mov  %rax,%r15
mov  %rdx,%rbx
mov  %rcx,%rax
mulq  32(%rdi)
mov  %rax,%rcx
mov  %rdx,%rbp
mov  %r8,%rax
mul  %r8
add  %r8,%r8
add  %rax,%r13
adc %rdx,%r14
mov  %r8,%rax
mulq  16(%rdi)
add  %rax,%r15
adc %rdx,%rbx
mov  %r8,%rax
imulq  $19, %r8,%r8
mulq  24(%rdi)
add  %rax,%rcx
adc %rdx,%rbp
mov  %r8,%rax
mulq  32(%rdi)
add  %rax,%r9
adc %rdx,%r10
movq   16(%rdi),%rax
mulq  16(%rdi)
add  %rax,%rcx
adc %rdx,%rbp
shld $13,%rcx,%rbp
movq   16(%rdi),%rax
imulq  $38, %rax,%rax
mulq  24(%rdi)
add  %rax,%r9
adc %rdx,%r10
shld $13,%r9,%r10
movq   16(%rdi),%rax
imulq  $38, %rax,%rax
mulq  32(%rdi)
add  %rax,%r11
adc %rdx,%r12
movq   24(%rdi),%rax
imulq  $19, %rax,%rax
mulq  24(%rdi)
add  %rax,%r11
adc %rdx,%r12
shld $13,%r11,%r12
movq   24(%rdi),%rax
imulq  $38, %rax,%rax
mulq  32(%rdi)
add  %rax,%r13
adc %rdx,%r14
shld $13,%r13,%r14
movq   32(%rdi),%rax
imulq  $19, %rax,%rax
mulq  32(%rdi)
add  %rax,%r15
adc %rdx,%rbx
shld $13,%r15,%rbx
movq REDMASK51(%rip),%rdx
and  %rdx,%rcx
add  %rbx,%rcx
and  %rdx,%r9
and  %rdx,%r11
add  %r10,%r11
and  %rdx,%r13
add  %r12,%r13
and  %rdx,%r15
add  %r14,%r15
imulq  $19, %rbp,%rbp
lea  (%r9,%rbp),%r9
mov  %r9,%rax
shr  $51,%r9
add  %r11,%r9
and  %rdx,%rax
mov  %r9,%r8
shr  $51,%r9
add  %r13,%r9
and  %rdx,%r8
mov  %r9,%r10
shr  $51,%r9
add  %r15,%r9
and  %rdx,%r10
movq   %r10,16(%rdi)
mov  %r9,%r10
shr  $51,%r9
add  %rcx,%r9
and  %rdx,%r10
movq   %r10,24(%rdi)
mov  %r9,%r10
shr  $51,%r9
imulq  $19, %r9,%r9
lea  (%rax,%r9),%rcx
and  %rdx,%r10
movq   %r10,32(%rdi)
cmp  $0,%rsi
jne ._loop

movq   %rcx,0(%rdi)
movq   %r8,8(%rdi)
movq 0(%rsp),%r11
movq 8(%rsp),%r12
movq 16(%rsp),%r13
movq 24(%rsp),%r14
movq 32(%rsp),%r15
movq 40(%rsp),%rbx
movq 48(%rsp),%rbp
add %r11,%rsp

RET
SYM_FUNC_END(curve25519_fe51_nsquare_avx)
