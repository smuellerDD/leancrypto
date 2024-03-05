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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023 - 2024
 * Frank Denis <j at pureftpd dot org>
 */

/*
   This file is basically amd64-51/fe25519_mul.s.
*/

.text
.p2align 5

SYM_FUNC_START(curve25519_fe51_mul_avx)
SYM_FUNC_ENTER(curve25519_fe51_mul_avx)

mov %rsp,%r11
and $31,%r11
add $96,%r11
sub %r11,%rsp
movq %r11,0(%rsp)
movq %r12,8(%rsp)
movq %r13,16(%rsp)
movq %r14,24(%rsp)
movq %r15,32(%rsp)
movq %rbx,40(%rsp)
movq %rbp,48(%rsp)
mov  %rdx,%rcx
movq   24(%rsi),%rdx
imulq  $19,%rdx,%rax
movq %rax,64(%rsp)
mulq  16(%rcx)
mov  %rax,%r8
mov  %rdx,%r9
movq   32(%rsi),%rdx
imulq  $19,%rdx,%rax
movq %rax,72(%rsp)
mulq  8(%rcx)
add  %rax,%r8
adc %rdx,%r9
movq   0(%rsi),%rax
mulq  0(%rcx)
add  %rax,%r8
adc %rdx,%r9
movq   0(%rsi),%rax
mulq  8(%rcx)
mov  %rax,%r10
mov  %rdx,%r11
movq   0(%rsi),%rax
mulq  16(%rcx)
mov  %rax,%r12
mov  %rdx,%r13
movq   0(%rsi),%rax
mulq  24(%rcx)
mov  %rax,%r14
mov  %rdx,%r15
movq   0(%rsi),%rax
mulq  32(%rcx)
mov  %rax,%rbx
mov  %rdx,%rbp
movq   8(%rsi),%rax
mulq  0(%rcx)
add  %rax,%r10
adc %rdx,%r11
movq   8(%rsi),%rax
mulq  8(%rcx)
add  %rax,%r12
adc %rdx,%r13
movq   8(%rsi),%rax
mulq  16(%rcx)
add  %rax,%r14
adc %rdx,%r15
movq   8(%rsi),%rax
mulq  24(%rcx)
add  %rax,%rbx
adc %rdx,%rbp
movq   8(%rsi),%rdx
imulq  $19,%rdx,%rax
mulq  32(%rcx)
add  %rax,%r8
adc %rdx,%r9
movq   16(%rsi),%rax
mulq  0(%rcx)
add  %rax,%r12
adc %rdx,%r13
movq   16(%rsi),%rax
mulq  8(%rcx)
add  %rax,%r14
adc %rdx,%r15
movq   16(%rsi),%rax
mulq  16(%rcx)
add  %rax,%rbx
adc %rdx,%rbp
movq   16(%rsi),%rdx
imulq  $19,%rdx,%rax
mulq  24(%rcx)
add  %rax,%r8
adc %rdx,%r9
movq   16(%rsi),%rdx
imulq  $19,%rdx,%rax
mulq  32(%rcx)
add  %rax,%r10
adc %rdx,%r11
movq   24(%rsi),%rax
mulq  0(%rcx)
add  %rax,%r14
adc %rdx,%r15
movq   24(%rsi),%rax
mulq  8(%rcx)
add  %rax,%rbx
adc %rdx,%rbp
movq 64(%rsp),%rax
mulq  24(%rcx)
add  %rax,%r10
adc %rdx,%r11
movq 64(%rsp),%rax
mulq  32(%rcx)
add  %rax,%r12
adc %rdx,%r13
movq   32(%rsi),%rax
mulq  0(%rcx)
add  %rax,%rbx
adc %rdx,%rbp
movq 72(%rsp),%rax
mulq  16(%rcx)
add  %rax,%r10
adc %rdx,%r11
movq 72(%rsp),%rax
mulq  24(%rcx)
add  %rax,%r12
adc %rdx,%r13
movq 72(%rsp),%rax
mulq  32(%rcx)
add  %rax,%r14
adc %rdx,%r15
movq REDMASK51(%rip),%rsi
shld $13,%r8,%r9
and  %rsi,%r8
shld $13,%r10,%r11
and  %rsi,%r10
add  %r9,%r10
shld $13,%r12,%r13
and  %rsi,%r12
add  %r11,%r12
shld $13,%r14,%r15
and  %rsi,%r14
add  %r13,%r14
shld $13,%rbx,%rbp
and  %rsi,%rbx
add  %r15,%rbx
imulq  $19,%rbp,%rdx
add  %rdx,%r8
mov  %r8,%rdx
shr  $51,%rdx
add  %r10,%rdx
mov  %rdx,%rcx
shr  $51,%rdx
and  %rsi,%r8
add  %r12,%rdx
mov  %rdx,%r9
shr  $51,%rdx
and  %rsi,%rcx
add  %r14,%rdx
mov  %rdx,%rax
shr  $51,%rdx
and  %rsi,%r9
add  %rbx,%rdx
mov  %rdx,%r10
shr  $51,%rdx
and  %rsi,%rax
imulq  $19,%rdx,%rdx
add  %rdx,%r8
and  %rsi,%r10
movq   %r8,0(%rdi)
movq   %rcx,8(%rdi)
movq   %r9,16(%rdi)
movq   %rax,24(%rdi)
movq   %r10,32(%rdi)
movq 0(%rsp),%r11
movq 8(%rsp),%r12
movq 16(%rsp),%r13
movq 24(%rsp),%r14
movq 32(%rsp),%r15
movq 40(%rsp),%rbx
movq 48(%rsp),%rbp
add %r11,%rsp
mov %rdi,%rax
mov %rsi,%rdx

RET

SYM_FUNC_END(curve25519_fe51_mul_avx)
