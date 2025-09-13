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
 * This file is derived from https://github.com/dot-asm/cryptogams which uses
 * the following license.
 *
 * Copyright (c) 2006-2017, CRYPTOGAMS by <appro@openssl.org>
 * All rights reserved.
 *
 * The source code in this file is licensed under the CRYPTOGAMS license.
 * For further details see http://www.openssl.org/~appro/cryptogams/.
 */

#include "assembler_support.h"

#if __riscv_xlen == 32
# if __SIZEOF_POINTER__ == 8
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sw
#  define POP	lw
# endif
# define sllw	sll
# define srlw	srl
# define rorw	ror
#elif __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif

#define FRAMESIZE		(16*4+16*__SIZEOF_POINTER__)

.text
.option	pic

#ifdef	__riscv_zbb
SYM_FUNC_START(sha256_block_data_order_riscv_zbb)
SYM_FUNC_ENTER(sha256_block_data_order_riscv_zbb)
#else
SYM_FUNC_START(sha256_block_data_order_riscv)
SYM_FUNC_ENTER(sha256_block_data_order_riscv)
#endif
	add	x2,x2,-FRAMESIZE
	PUSH	x8,FRAMESIZE-1*__SIZEOF_POINTER__(x2)
	PUSH	x9,FRAMESIZE-2*__SIZEOF_POINTER__(x2)
	PUSH	x18,FRAMESIZE-3*__SIZEOF_POINTER__(x2)
	PUSH	x19,FRAMESIZE-4*__SIZEOF_POINTER__(x2)
	PUSH	x20,FRAMESIZE-5*__SIZEOF_POINTER__(x2)
	PUSH	x21,FRAMESIZE-6*__SIZEOF_POINTER__(x2)
	PUSH	x22,FRAMESIZE-7*__SIZEOF_POINTER__(x2)
	PUSH	x23,FRAMESIZE-8*__SIZEOF_POINTER__(x2)
	PUSH	x24,FRAMESIZE-9*__SIZEOF_POINTER__(x2)
	PUSH	x25,FRAMESIZE-10*__SIZEOF_POINTER__(x2)
	PUSH	x26,FRAMESIZE-11*__SIZEOF_POINTER__(x2)
	PUSH	x27,FRAMESIZE-12*__SIZEOF_POINTER__(x2)

	lw	x5,0*4(x10)		# load context
	lw	x6,1*4(x10)
	lw	x7,2*4(x10)
	lw	x8,3*4(x10)
	lw	x9,4*4(x10)
	lw	x13,5*4(x10)
	lw	x14,6*4(x10)
	lw	x15,7*4(x10)

	sll	x31,x12,6
	lla	x12,K256
	add	x31,x11,x31	# pointer to the end of input
	PUSH	x31,16*4(x2)

.Loop:
	lbu	x16,0(x11)
	lbu	x17,1(x11)
	lbu	x18,2(x11)
	sll	x16,x16,24
	lbu	x19,3(x11)
	sll	x17,x17,16
	or	x16,x16,x17
	sll	x18,x18,8
	or	x16,x16,x18
	or	x16,x16,x19
	lbu	x17,4(x11)
	lbu	x21,5(x11)
	lbu	x22,6(x11)
	sll	x17,x17,24
	lbu	x23,7(x11)
	sll	x21,x21,16
	or	x17,x17,x21
	sll	x22,x22,8
	or	x17,x17,x22
	or	x17,x17,x23
#ifdef	__riscv_zbb
	xor	x23,x13,x14			# 0
	rorw	x21,x9,6
	add	x20,x16,x15
	rorw	x22,x9,11
	and	x23,x23,x9
	rorw	x15,x9,25
	xor	x21,x21,x22
	rorw	x22,x5,2
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x21,x15			# Sigma1(e)

	rorw	x15,x5,13
	add	x20,x20,x23
	lw	x23,0(x12)		# K[0]
	xor	x15,x15,x22
	rorw	x22,x5,22
	add	x20,x20,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#else
	add	x20,x16,x15			# 0
	srlw	x15,x9,6
	xor	x23,x13,x14
	sllw	x22,x9,7
	and	x23,x23,x9
	srlw	x21,x9,11
	xor	x15,x15,x22
	sllw	x22,x9,21
	xor	x15,x15,x21
	srlw	x21,x9,25
	xor	x15,x15,x22
	sllw	x22,x9,26
	xor	x15,x15,x21
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x22,x15			# Sigma1(e)

	srlw	x15,x5,2
	add	x20,x20,x23
	lw	x23,0(x12)		# K[0]
	sllw	x22,x5,10
	add	x20,x20,x21
	srlw	x21,x5,13
	xor	x15,x15,x22
	sllw	x22,x5,19
	xor	x15,x15,x21
	srlw	x21,x5,22
	xor	x15,x15,x22
	sllw	x22,x5,30
	xor	x15,x15,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#endif
	sw	x16,0(x2)	# offload to ring buffer
	add	x15,x15,x21
	and	x22,x22,x5
	add	x20,x20,x23			# +=K[0]
	add	x15,x15,x22			# +=Maj(a,b,c)
	add	x8,x8,x20
	add	x15,x15,x20
	lbu	x18,8(x11)
	lbu	x22,9(x11)
	lbu	x23,10(x11)
	sll	x18,x18,24
	lbu	x24,11(x11)
	sll	x22,x22,16
	or	x18,x18,x22
	sll	x23,x23,8
	or	x18,x18,x23
	or	x18,x18,x24
#ifdef	__riscv_zbb
	xor	x24,x9,x13			# 1
	rorw	x22,x8,6
	add	x21,x17,x14
	rorw	x23,x8,11
	and	x24,x24,x8
	rorw	x14,x8,25
	xor	x22,x22,x23
	rorw	x23,x15,2
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x22,x14			# Sigma1(e)

	rorw	x14,x15,13
	add	x21,x21,x24
	lw	x24,4(x12)		# K[1]
	xor	x14,x14,x23
	rorw	x23,x15,22
	add	x21,x21,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#else
	add	x21,x17,x14			# 1
	srlw	x14,x8,6
	xor	x24,x9,x13
	sllw	x23,x8,7
	and	x24,x24,x8
	srlw	x22,x8,11
	xor	x14,x14,x23
	sllw	x23,x8,21
	xor	x14,x14,x22
	srlw	x22,x8,25
	xor	x14,x14,x23
	sllw	x23,x8,26
	xor	x14,x14,x22
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x23,x14			# Sigma1(e)

	srlw	x14,x15,2
	add	x21,x21,x24
	lw	x24,4(x12)		# K[1]
	sllw	x23,x15,10
	add	x21,x21,x22
	srlw	x22,x15,13
	xor	x14,x14,x23
	sllw	x23,x15,19
	xor	x14,x14,x22
	srlw	x22,x15,22
	xor	x14,x14,x23
	sllw	x23,x15,30
	xor	x14,x14,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#endif
	sw	x17,4(x2)	# offload to ring buffer
	add	x14,x14,x22
	and	x23,x23,x15
	add	x21,x21,x24			# +=K[1]
	add	x14,x14,x23			# +=Maj(a,b,c)
	add	x7,x7,x21
	add	x14,x14,x21
	lbu	x19,12(x11)
	lbu	x23,13(x11)
	lbu	x24,14(x11)
	sll	x19,x19,24
	lbu	x25,15(x11)
	sll	x23,x23,16
	or	x19,x19,x23
	sll	x24,x24,8
	or	x19,x19,x24
	or	x19,x19,x25
#ifdef	__riscv_zbb
	xor	x25,x8,x9			# 2
	rorw	x23,x7,6
	add	x22,x18,x13
	rorw	x24,x7,11
	and	x25,x25,x7
	rorw	x13,x7,25
	xor	x23,x23,x24
	rorw	x24,x14,2
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x23,x13			# Sigma1(e)

	rorw	x13,x14,13
	add	x22,x22,x25
	lw	x25,8(x12)		# K[2]
	xor	x13,x13,x24
	rorw	x24,x14,22
	add	x22,x22,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#else
	add	x22,x18,x13			# 2
	srlw	x13,x7,6
	xor	x25,x8,x9
	sllw	x24,x7,7
	and	x25,x25,x7
	srlw	x23,x7,11
	xor	x13,x13,x24
	sllw	x24,x7,21
	xor	x13,x13,x23
	srlw	x23,x7,25
	xor	x13,x13,x24
	sllw	x24,x7,26
	xor	x13,x13,x23
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x24,x13			# Sigma1(e)

	srlw	x13,x14,2
	add	x22,x22,x25
	lw	x25,8(x12)		# K[2]
	sllw	x24,x14,10
	add	x22,x22,x23
	srlw	x23,x14,13
	xor	x13,x13,x24
	sllw	x24,x14,19
	xor	x13,x13,x23
	srlw	x23,x14,22
	xor	x13,x13,x24
	sllw	x24,x14,30
	xor	x13,x13,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#endif
	sw	x18,8(x2)	# offload to ring buffer
	add	x13,x13,x23
	and	x24,x24,x14
	add	x22,x22,x25			# +=K[2]
	add	x13,x13,x24			# +=Maj(a,b,c)
	add	x6,x6,x22
	add	x13,x13,x22
	lbu	x20,16(x11)
	lbu	x24,17(x11)
	lbu	x25,18(x11)
	sll	x20,x20,24
	lbu	x26,19(x11)
	sll	x24,x24,16
	or	x20,x20,x24
	sll	x25,x25,8
	or	x20,x20,x25
	or	x20,x20,x26
#ifdef	__riscv_zbb
	xor	x26,x7,x8			# 3
	rorw	x24,x6,6
	add	x23,x19,x9
	rorw	x25,x6,11
	and	x26,x26,x6
	rorw	x9,x6,25
	xor	x24,x24,x25
	rorw	x25,x13,2
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x24,x9			# Sigma1(e)

	rorw	x9,x13,13
	add	x23,x23,x26
	lw	x26,12(x12)		# K[3]
	xor	x9,x9,x25
	rorw	x25,x13,22
	add	x23,x23,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#else
	add	x23,x19,x9			# 3
	srlw	x9,x6,6
	xor	x26,x7,x8
	sllw	x25,x6,7
	and	x26,x26,x6
	srlw	x24,x6,11
	xor	x9,x9,x25
	sllw	x25,x6,21
	xor	x9,x9,x24
	srlw	x24,x6,25
	xor	x9,x9,x25
	sllw	x25,x6,26
	xor	x9,x9,x24
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x25,x9			# Sigma1(e)

	srlw	x9,x13,2
	add	x23,x23,x26
	lw	x26,12(x12)		# K[3]
	sllw	x25,x13,10
	add	x23,x23,x24
	srlw	x24,x13,13
	xor	x9,x9,x25
	sllw	x25,x13,19
	xor	x9,x9,x24
	srlw	x24,x13,22
	xor	x9,x9,x25
	sllw	x25,x13,30
	xor	x9,x9,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#endif
	sw	x19,12(x2)	# offload to ring buffer
	add	x9,x9,x24
	and	x25,x25,x13
	add	x23,x23,x26			# +=K[3]
	add	x9,x9,x25			# +=Maj(a,b,c)
	add	x5,x5,x23
	add	x9,x9,x23
	lbu	x21,20(x11)
	lbu	x25,21(x11)
	lbu	x26,22(x11)
	sll	x21,x21,24
	lbu	x27,23(x11)
	sll	x25,x25,16
	or	x21,x21,x25
	sll	x26,x26,8
	or	x21,x21,x26
	or	x21,x21,x27
#ifdef	__riscv_zbb
	xor	x27,x6,x7			# 4
	rorw	x25,x5,6
	add	x24,x20,x8
	rorw	x26,x5,11
	and	x27,x27,x5
	rorw	x8,x5,25
	xor	x25,x25,x26
	rorw	x26,x9,2
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x25,x8			# Sigma1(e)

	rorw	x8,x9,13
	add	x24,x24,x27
	lw	x27,16(x12)		# K[4]
	xor	x8,x8,x26
	rorw	x26,x9,22
	add	x24,x24,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#else
	add	x24,x20,x8			# 4
	srlw	x8,x5,6
	xor	x27,x6,x7
	sllw	x26,x5,7
	and	x27,x27,x5
	srlw	x25,x5,11
	xor	x8,x8,x26
	sllw	x26,x5,21
	xor	x8,x8,x25
	srlw	x25,x5,25
	xor	x8,x8,x26
	sllw	x26,x5,26
	xor	x8,x8,x25
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x26,x8			# Sigma1(e)

	srlw	x8,x9,2
	add	x24,x24,x27
	lw	x27,16(x12)		# K[4]
	sllw	x26,x9,10
	add	x24,x24,x25
	srlw	x25,x9,13
	xor	x8,x8,x26
	sllw	x26,x9,19
	xor	x8,x8,x25
	srlw	x25,x9,22
	xor	x8,x8,x26
	sllw	x26,x9,30
	xor	x8,x8,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#endif
	sw	x20,16(x2)	# offload to ring buffer
	add	x8,x8,x25
	and	x26,x26,x9
	add	x24,x24,x27			# +=K[4]
	add	x8,x8,x26			# +=Maj(a,b,c)
	add	x15,x15,x24
	add	x8,x8,x24
	lbu	x22,24(x11)
	lbu	x26,25(x11)
	lbu	x27,26(x11)
	sll	x22,x22,24
	lbu	x28,27(x11)
	sll	x26,x26,16
	or	x22,x22,x26
	sll	x27,x27,8
	or	x22,x22,x27
	or	x22,x22,x28
#ifdef	__riscv_zbb
	xor	x28,x5,x6			# 5
	rorw	x26,x15,6
	add	x25,x21,x7
	rorw	x27,x15,11
	and	x28,x28,x15
	rorw	x7,x15,25
	xor	x26,x26,x27
	rorw	x27,x8,2
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x26,x7			# Sigma1(e)

	rorw	x7,x8,13
	add	x25,x25,x28
	lw	x28,20(x12)		# K[5]
	xor	x7,x7,x27
	rorw	x27,x8,22
	add	x25,x25,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#else
	add	x25,x21,x7			# 5
	srlw	x7,x15,6
	xor	x28,x5,x6
	sllw	x27,x15,7
	and	x28,x28,x15
	srlw	x26,x15,11
	xor	x7,x7,x27
	sllw	x27,x15,21
	xor	x7,x7,x26
	srlw	x26,x15,25
	xor	x7,x7,x27
	sllw	x27,x15,26
	xor	x7,x7,x26
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x27,x7			# Sigma1(e)

	srlw	x7,x8,2
	add	x25,x25,x28
	lw	x28,20(x12)		# K[5]
	sllw	x27,x8,10
	add	x25,x25,x26
	srlw	x26,x8,13
	xor	x7,x7,x27
	sllw	x27,x8,19
	xor	x7,x7,x26
	srlw	x26,x8,22
	xor	x7,x7,x27
	sllw	x27,x8,30
	xor	x7,x7,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#endif
	sw	x21,20(x2)	# offload to ring buffer
	add	x7,x7,x26
	and	x27,x27,x8
	add	x25,x25,x28			# +=K[5]
	add	x7,x7,x27			# +=Maj(a,b,c)
	add	x14,x14,x25
	add	x7,x7,x25
	lbu	x23,28(x11)
	lbu	x27,29(x11)
	lbu	x28,30(x11)
	sll	x23,x23,24
	lbu	x29,31(x11)
	sll	x27,x27,16
	or	x23,x23,x27
	sll	x28,x28,8
	or	x23,x23,x28
	or	x23,x23,x29
#ifdef	__riscv_zbb
	xor	x29,x15,x5			# 6
	rorw	x27,x14,6
	add	x26,x22,x6
	rorw	x28,x14,11
	and	x29,x29,x14
	rorw	x6,x14,25
	xor	x27,x27,x28
	rorw	x28,x7,2
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x27,x6			# Sigma1(e)

	rorw	x6,x7,13
	add	x26,x26,x29
	lw	x29,24(x12)		# K[6]
	xor	x6,x6,x28
	rorw	x28,x7,22
	add	x26,x26,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#else
	add	x26,x22,x6			# 6
	srlw	x6,x14,6
	xor	x29,x15,x5
	sllw	x28,x14,7
	and	x29,x29,x14
	srlw	x27,x14,11
	xor	x6,x6,x28
	sllw	x28,x14,21
	xor	x6,x6,x27
	srlw	x27,x14,25
	xor	x6,x6,x28
	sllw	x28,x14,26
	xor	x6,x6,x27
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x28,x6			# Sigma1(e)

	srlw	x6,x7,2
	add	x26,x26,x29
	lw	x29,24(x12)		# K[6]
	sllw	x28,x7,10
	add	x26,x26,x27
	srlw	x27,x7,13
	xor	x6,x6,x28
	sllw	x28,x7,19
	xor	x6,x6,x27
	srlw	x27,x7,22
	xor	x6,x6,x28
	sllw	x28,x7,30
	xor	x6,x6,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#endif
	sw	x22,24(x2)	# offload to ring buffer
	add	x6,x6,x27
	and	x28,x28,x7
	add	x26,x26,x29			# +=K[6]
	add	x6,x6,x28			# +=Maj(a,b,c)
	add	x13,x13,x26
	add	x6,x6,x26
	lbu	x24,32(x11)
	lbu	x28,33(x11)
	lbu	x29,34(x11)
	sll	x24,x24,24
	lbu	x30,35(x11)
	sll	x28,x28,16
	or	x24,x24,x28
	sll	x29,x29,8
	or	x24,x24,x29
	or	x24,x24,x30
#ifdef	__riscv_zbb
	xor	x30,x14,x15			# 7
	rorw	x28,x13,6
	add	x27,x23,x5
	rorw	x29,x13,11
	and	x30,x30,x13
	rorw	x5,x13,25
	xor	x28,x28,x29
	rorw	x29,x6,2
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x28,x5			# Sigma1(e)

	rorw	x5,x6,13
	add	x27,x27,x30
	lw	x30,28(x12)		# K[7]
	xor	x5,x5,x29
	rorw	x29,x6,22
	add	x27,x27,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#else
	add	x27,x23,x5			# 7
	srlw	x5,x13,6
	xor	x30,x14,x15
	sllw	x29,x13,7
	and	x30,x30,x13
	srlw	x28,x13,11
	xor	x5,x5,x29
	sllw	x29,x13,21
	xor	x5,x5,x28
	srlw	x28,x13,25
	xor	x5,x5,x29
	sllw	x29,x13,26
	xor	x5,x5,x28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x29,x5			# Sigma1(e)

	srlw	x5,x6,2
	add	x27,x27,x30
	lw	x30,28(x12)		# K[7]
	sllw	x29,x6,10
	add	x27,x27,x28
	srlw	x28,x6,13
	xor	x5,x5,x29
	sllw	x29,x6,19
	xor	x5,x5,x28
	srlw	x28,x6,22
	xor	x5,x5,x29
	sllw	x29,x6,30
	xor	x5,x5,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#endif
	sw	x23,28(x2)	# offload to ring buffer
	add	x5,x5,x28
	and	x29,x29,x6
	add	x27,x27,x30			# +=K[7]
	add	x5,x5,x29			# +=Maj(a,b,c)
	add	x9,x9,x27
	add	x5,x5,x27
	lbu	x25,36(x11)
	lbu	x29,37(x11)
	lbu	x30,38(x11)
	sll	x25,x25,24
	lbu	x31,39(x11)
	sll	x29,x29,16
	or	x25,x25,x29
	sll	x30,x30,8
	or	x25,x25,x30
	or	x25,x25,x31
#ifdef	__riscv_zbb
	xor	x31,x13,x14			# 8
	rorw	x29,x9,6
	add	x28,x24,x15
	rorw	x30,x9,11
	and	x31,x31,x9
	rorw	x15,x9,25
	xor	x29,x29,x30
	rorw	x30,x5,2
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x29,x15			# Sigma1(e)

	rorw	x15,x5,13
	add	x28,x28,x31
	lw	x31,32(x12)		# K[8]
	xor	x15,x15,x30
	rorw	x30,x5,22
	add	x28,x28,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#else
	add	x28,x24,x15			# 8
	srlw	x15,x9,6
	xor	x31,x13,x14
	sllw	x30,x9,7
	and	x31,x31,x9
	srlw	x29,x9,11
	xor	x15,x15,x30
	sllw	x30,x9,21
	xor	x15,x15,x29
	srlw	x29,x9,25
	xor	x15,x15,x30
	sllw	x30,x9,26
	xor	x15,x15,x29
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x30,x15			# Sigma1(e)

	srlw	x15,x5,2
	add	x28,x28,x31
	lw	x31,32(x12)		# K[8]
	sllw	x30,x5,10
	add	x28,x28,x29
	srlw	x29,x5,13
	xor	x15,x15,x30
	sllw	x30,x5,19
	xor	x15,x15,x29
	srlw	x29,x5,22
	xor	x15,x15,x30
	sllw	x30,x5,30
	xor	x15,x15,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#endif
	sw	x24,32(x2)	# offload to ring buffer
	add	x15,x15,x29
	and	x30,x30,x5
	add	x28,x28,x31			# +=K[8]
	add	x15,x15,x30			# +=Maj(a,b,c)
	add	x8,x8,x28
	add	x15,x15,x28
	lbu	x26,40(x11)
	lbu	x30,41(x11)
	lbu	x31,42(x11)
	sll	x26,x26,24
	lbu	x16,43(x11)
	sll	x30,x30,16
	or	x26,x26,x30
	sll	x31,x31,8
	or	x26,x26,x31
	or	x26,x26,x16
#ifdef	__riscv_zbb
	xor	x16,x9,x13			# 9
	rorw	x30,x8,6
	add	x29,x25,x14
	rorw	x31,x8,11
	and	x16,x16,x8
	rorw	x14,x8,25
	xor	x30,x30,x31
	rorw	x31,x15,2
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x30,x14			# Sigma1(e)

	rorw	x14,x15,13
	add	x29,x29,x16
	lw	x16,36(x12)		# K[9]
	xor	x14,x14,x31
	rorw	x31,x15,22
	add	x29,x29,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#else
	add	x29,x25,x14			# 9
	srlw	x14,x8,6
	xor	x16,x9,x13
	sllw	x31,x8,7
	and	x16,x16,x8
	srlw	x30,x8,11
	xor	x14,x14,x31
	sllw	x31,x8,21
	xor	x14,x14,x30
	srlw	x30,x8,25
	xor	x14,x14,x31
	sllw	x31,x8,26
	xor	x14,x14,x30
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x31,x14			# Sigma1(e)

	srlw	x14,x15,2
	add	x29,x29,x16
	lw	x16,36(x12)		# K[9]
	sllw	x31,x15,10
	add	x29,x29,x30
	srlw	x30,x15,13
	xor	x14,x14,x31
	sllw	x31,x15,19
	xor	x14,x14,x30
	srlw	x30,x15,22
	xor	x14,x14,x31
	sllw	x31,x15,30
	xor	x14,x14,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#endif
	sw	x25,36(x2)	# offload to ring buffer
	add	x14,x14,x30
	and	x31,x31,x15
	add	x29,x29,x16			# +=K[9]
	add	x14,x14,x31			# +=Maj(a,b,c)
	add	x7,x7,x29
	add	x14,x14,x29
	lbu	x27,44(x11)
	lbu	x31,45(x11)
	lbu	x16,46(x11)
	sll	x27,x27,24
	lbu	x17,47(x11)
	sll	x31,x31,16
	or	x27,x27,x31
	sll	x16,x16,8
	or	x27,x27,x16
	or	x27,x27,x17
#ifdef	__riscv_zbb
	xor	x17,x8,x9			# 10
	rorw	x31,x7,6
	add	x30,x26,x13
	rorw	x16,x7,11
	and	x17,x17,x7
	rorw	x13,x7,25
	xor	x31,x31,x16
	rorw	x16,x14,2
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x31,x13			# Sigma1(e)

	rorw	x13,x14,13
	add	x30,x30,x17
	lw	x17,40(x12)		# K[10]
	xor	x13,x13,x16
	rorw	x16,x14,22
	add	x30,x30,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#else
	add	x30,x26,x13			# 10
	srlw	x13,x7,6
	xor	x17,x8,x9
	sllw	x16,x7,7
	and	x17,x17,x7
	srlw	x31,x7,11
	xor	x13,x13,x16
	sllw	x16,x7,21
	xor	x13,x13,x31
	srlw	x31,x7,25
	xor	x13,x13,x16
	sllw	x16,x7,26
	xor	x13,x13,x31
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x16,x13			# Sigma1(e)

	srlw	x13,x14,2
	add	x30,x30,x17
	lw	x17,40(x12)		# K[10]
	sllw	x16,x14,10
	add	x30,x30,x31
	srlw	x31,x14,13
	xor	x13,x13,x16
	sllw	x16,x14,19
	xor	x13,x13,x31
	srlw	x31,x14,22
	xor	x13,x13,x16
	sllw	x16,x14,30
	xor	x13,x13,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#endif
	sw	x26,40(x2)	# offload to ring buffer
	add	x13,x13,x31
	and	x16,x16,x14
	add	x30,x30,x17			# +=K[10]
	add	x13,x13,x16			# +=Maj(a,b,c)
	add	x6,x6,x30
	add	x13,x13,x30
	lbu	x28,48(x11)
	lbu	x16,49(x11)
	lbu	x17,50(x11)
	sll	x28,x28,24
	lbu	x18,51(x11)
	sll	x16,x16,16
	or	x28,x28,x16
	sll	x17,x17,8
	or	x28,x28,x17
	or	x28,x28,x18
#ifdef	__riscv_zbb
	xor	x18,x7,x8			# 11
	rorw	x16,x6,6
	add	x31,x27,x9
	rorw	x17,x6,11
	and	x18,x18,x6
	rorw	x9,x6,25
	xor	x16,x16,x17
	rorw	x17,x13,2
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x16,x9			# Sigma1(e)

	rorw	x9,x13,13
	add	x31,x31,x18
	lw	x18,44(x12)		# K[11]
	xor	x9,x9,x17
	rorw	x17,x13,22
	add	x31,x31,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#else
	add	x31,x27,x9			# 11
	srlw	x9,x6,6
	xor	x18,x7,x8
	sllw	x17,x6,7
	and	x18,x18,x6
	srlw	x16,x6,11
	xor	x9,x9,x17
	sllw	x17,x6,21
	xor	x9,x9,x16
	srlw	x16,x6,25
	xor	x9,x9,x17
	sllw	x17,x6,26
	xor	x9,x9,x16
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x17,x9			# Sigma1(e)

	srlw	x9,x13,2
	add	x31,x31,x18
	lw	x18,44(x12)		# K[11]
	sllw	x17,x13,10
	add	x31,x31,x16
	srlw	x16,x13,13
	xor	x9,x9,x17
	sllw	x17,x13,19
	xor	x9,x9,x16
	srlw	x16,x13,22
	xor	x9,x9,x17
	sllw	x17,x13,30
	xor	x9,x9,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#endif
	sw	x27,44(x2)	# offload to ring buffer
	add	x9,x9,x16
	and	x17,x17,x13
	add	x31,x31,x18			# +=K[11]
	add	x9,x9,x17			# +=Maj(a,b,c)
	add	x5,x5,x31
	add	x9,x9,x31
	lbu	x29,52(x11)
	lbu	x17,53(x11)
	lbu	x18,54(x11)
	sll	x29,x29,24
	lbu	x19,55(x11)
	sll	x17,x17,16
	or	x29,x29,x17
	sll	x18,x18,8
	or	x29,x29,x18
	or	x29,x29,x19
#ifdef	__riscv_zbb
	xor	x19,x6,x7			# 12
	rorw	x17,x5,6
	add	x16,x28,x8
	rorw	x18,x5,11
	and	x19,x19,x5
	rorw	x8,x5,25
	xor	x17,x17,x18
	rorw	x18,x9,2
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x17,x8			# Sigma1(e)

	rorw	x8,x9,13
	add	x16,x16,x19
	lw	x19,48(x12)		# K[12]
	xor	x8,x8,x18
	rorw	x18,x9,22
	add	x16,x16,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#else
	add	x16,x28,x8			# 12
	srlw	x8,x5,6
	xor	x19,x6,x7
	sllw	x18,x5,7
	and	x19,x19,x5
	srlw	x17,x5,11
	xor	x8,x8,x18
	sllw	x18,x5,21
	xor	x8,x8,x17
	srlw	x17,x5,25
	xor	x8,x8,x18
	sllw	x18,x5,26
	xor	x8,x8,x17
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x18,x8			# Sigma1(e)

	srlw	x8,x9,2
	add	x16,x16,x19
	lw	x19,48(x12)		# K[12]
	sllw	x18,x9,10
	add	x16,x16,x17
	srlw	x17,x9,13
	xor	x8,x8,x18
	sllw	x18,x9,19
	xor	x8,x8,x17
	srlw	x17,x9,22
	xor	x8,x8,x18
	sllw	x18,x9,30
	xor	x8,x8,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#endif
	sw	x28,48(x2)	# offload to ring buffer
	add	x8,x8,x17
	and	x18,x18,x9
	add	x16,x16,x19			# +=K[12]
	add	x8,x8,x18			# +=Maj(a,b,c)
	add	x15,x15,x16
	add	x8,x8,x16
	lbu	x30,56(x11)
	lbu	x18,57(x11)
	lbu	x19,58(x11)
	sll	x30,x30,24
	lbu	x20,59(x11)
	sll	x18,x18,16
	or	x30,x30,x18
	sll	x19,x19,8
	or	x30,x30,x19
	or	x30,x30,x20
#ifdef	__riscv_zbb
	xor	x20,x5,x6			# 13
	rorw	x18,x15,6
	add	x17,x29,x7
	rorw	x19,x15,11
	and	x20,x20,x15
	rorw	x7,x15,25
	xor	x18,x18,x19
	rorw	x19,x8,2
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x18,x7			# Sigma1(e)

	rorw	x7,x8,13
	add	x17,x17,x20
	lw	x20,52(x12)		# K[13]
	xor	x7,x7,x19
	rorw	x19,x8,22
	add	x17,x17,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#else
	add	x17,x29,x7			# 13
	srlw	x7,x15,6
	xor	x20,x5,x6
	sllw	x19,x15,7
	and	x20,x20,x15
	srlw	x18,x15,11
	xor	x7,x7,x19
	sllw	x19,x15,21
	xor	x7,x7,x18
	srlw	x18,x15,25
	xor	x7,x7,x19
	sllw	x19,x15,26
	xor	x7,x7,x18
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x19,x7			# Sigma1(e)

	srlw	x7,x8,2
	add	x17,x17,x20
	lw	x20,52(x12)		# K[13]
	sllw	x19,x8,10
	add	x17,x17,x18
	srlw	x18,x8,13
	xor	x7,x7,x19
	sllw	x19,x8,19
	xor	x7,x7,x18
	srlw	x18,x8,22
	xor	x7,x7,x19
	sllw	x19,x8,30
	xor	x7,x7,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#endif
	sw	x29,52(x2)	# offload to ring buffer
	add	x7,x7,x18
	and	x19,x19,x8
	add	x17,x17,x20			# +=K[13]
	add	x7,x7,x19			# +=Maj(a,b,c)
	add	x14,x14,x17
	add	x7,x7,x17
	lw	x16,0(x2)	# prefetch from ring buffer
	lbu	x31,60(x11)
	lbu	x19,61(x11)
	lbu	x20,62(x11)
	sll	x31,x31,24
	lbu	x21,63(x11)
	sll	x19,x19,16
	or	x31,x31,x19
	sll	x20,x20,8
	or	x31,x31,x20
	or	x31,x31,x21
#ifdef	__riscv_zbb
	xor	x21,x15,x5			# 14
	rorw	x19,x14,6
	add	x18,x30,x6
	rorw	x20,x14,11
	and	x21,x21,x14
	rorw	x6,x14,25
	xor	x19,x19,x20
	rorw	x20,x7,2
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x19,x6			# Sigma1(e)

	rorw	x6,x7,13
	add	x18,x18,x21
	lw	x21,56(x12)		# K[14]
	xor	x6,x6,x20
	rorw	x20,x7,22
	add	x18,x18,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#else
	add	x18,x30,x6			# 14
	srlw	x6,x14,6
	xor	x21,x15,x5
	sllw	x20,x14,7
	and	x21,x21,x14
	srlw	x19,x14,11
	xor	x6,x6,x20
	sllw	x20,x14,21
	xor	x6,x6,x19
	srlw	x19,x14,25
	xor	x6,x6,x20
	sllw	x20,x14,26
	xor	x6,x6,x19
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x20,x6			# Sigma1(e)

	srlw	x6,x7,2
	add	x18,x18,x21
	lw	x21,56(x12)		# K[14]
	sllw	x20,x7,10
	add	x18,x18,x19
	srlw	x19,x7,13
	xor	x6,x6,x20
	sllw	x20,x7,19
	xor	x6,x6,x19
	srlw	x19,x7,22
	xor	x6,x6,x20
	sllw	x20,x7,30
	xor	x6,x6,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#endif
	sw	x30,56(x2)	# offload to ring buffer
	add	x6,x6,x19
	and	x20,x20,x7
	add	x18,x18,x21			# +=K[14]
	add	x6,x6,x20			# +=Maj(a,b,c)
	add	x13,x13,x18
	add	x6,x6,x18
	lw	x17,4(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	xor	x22,x14,x15			# 15
	rorw	x20,x13,6
	add	x19,x31,x5
	rorw	x21,x13,11
	and	x22,x22,x13
	rorw	x5,x13,25
	xor	x20,x20,x21
	rorw	x21,x6,2
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x20,x5			# Sigma1(e)

	rorw	x5,x6,13
	add	x19,x19,x22
	lw	x22,60(x12)		# K[15]
	xor	x5,x5,x21
	rorw	x21,x6,22
	add	x19,x19,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#else
	add	x19,x31,x5			# 15
	srlw	x5,x13,6
	xor	x22,x14,x15
	sllw	x21,x13,7
	and	x22,x22,x13
	srlw	x20,x13,11
	xor	x5,x5,x21
	sllw	x21,x13,21
	xor	x5,x5,x20
	srlw	x20,x13,25
	xor	x5,x5,x21
	sllw	x21,x13,26
	xor	x5,x5,x20
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x21,x5			# Sigma1(e)

	srlw	x5,x6,2
	add	x19,x19,x22
	lw	x22,60(x12)		# K[15]
	sllw	x21,x6,10
	add	x19,x19,x20
	srlw	x20,x6,13
	xor	x5,x5,x21
	sllw	x21,x6,19
	xor	x5,x5,x20
	srlw	x20,x6,22
	xor	x5,x5,x21
	sllw	x21,x6,30
	xor	x5,x5,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#endif
	sw	x31,60(x2)	# offload to ring buffer
	add	x5,x5,x20
	and	x21,x21,x6
	add	x19,x19,x22			# +=K[15]
	add	x5,x5,x21			# +=Maj(a,b,c)
	add	x9,x9,x19
	add	x5,x5,x19
	lw	x18,8(x2)	# prefetch from ring buffer
.L16_xx:
#ifdef	__riscv_zbb
	srlw	x22,x17,3		# Xupdate(16)
	rorw	x20,x17,7
	add	x16,x16,x25		# +=X[i+9]
	xor	x22,x22,x20
	rorw	x20,x17,18

	srlw	x23,x30,10
	rorw	x21,x30,17
	xor	x22,x22,x20		# sigma0(X[i+1])
	rorw	x20,x30,19
	xor	x23,x23,x21
	add	x16,x16,x22
#else
	srlw	x22,x17,3		# Xupdate(16)
	add	x16,x16,x25		# +=X[i+9]
	sllw	x21,x17,14
	srlw	x20,x17,7
	xor	x22,x22,x21
	sllw	x21,x21,11
	xor	x22,x22,x20
	srlw	x20,x17,18
	xor	x22,x22,x21

	srlw	x23,x30,10
	xor	x22,x22,x20		# sigma0(X[i+1])
	sllw	x21,x30,13
	add	x16,x16,x22
	srlw	x20,x30,17
	xor	x23,x23,x21
	sllw	x21,x21,2
	xor	x23,x23,x20
	srlw	x20,x30,19
	xor	x23,x23,x21
#endif
	xor	x23,x23,x20		# sigma1(X[i+14])
	add	x16,x16,x23
#ifdef	__riscv_zbb
	xor	x23,x13,x14			# 16
	rorw	x21,x9,6
	add	x20,x16,x15
	rorw	x22,x9,11
	and	x23,x23,x9
	rorw	x15,x9,25
	xor	x21,x21,x22
	rorw	x22,x5,2
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x21,x15			# Sigma1(e)

	rorw	x15,x5,13
	add	x20,x20,x23
	lw	x23,64(x12)		# K[16]
	xor	x15,x15,x22
	rorw	x22,x5,22
	add	x20,x20,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#else
	add	x20,x16,x15			# 16
	srlw	x15,x9,6
	xor	x23,x13,x14
	sllw	x22,x9,7
	and	x23,x23,x9
	srlw	x21,x9,11
	xor	x15,x15,x22
	sllw	x22,x9,21
	xor	x15,x15,x21
	srlw	x21,x9,25
	xor	x15,x15,x22
	sllw	x22,x9,26
	xor	x15,x15,x21
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x22,x15			# Sigma1(e)

	srlw	x15,x5,2
	add	x20,x20,x23
	lw	x23,64(x12)		# K[16]
	sllw	x22,x5,10
	add	x20,x20,x21
	srlw	x21,x5,13
	xor	x15,x15,x22
	sllw	x22,x5,19
	xor	x15,x15,x21
	srlw	x21,x5,22
	xor	x15,x15,x22
	sllw	x22,x5,30
	xor	x15,x15,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#endif
	sw	x16,0(x2)	# offload to ring buffer
	add	x15,x15,x21
	and	x22,x22,x5
	add	x20,x20,x23			# +=K[16]
	add	x15,x15,x22			# +=Maj(a,b,c)
	add	x8,x8,x20
	add	x15,x15,x20
	lw	x19,12(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x23,x18,3		# Xupdate(17)
	rorw	x21,x18,7
	add	x17,x17,x26		# +=X[i+9]
	xor	x23,x23,x21
	rorw	x21,x18,18

	srlw	x24,x31,10
	rorw	x22,x31,17
	xor	x23,x23,x21		# sigma0(X[i+1])
	rorw	x21,x31,19
	xor	x24,x24,x22
	add	x17,x17,x23
#else
	srlw	x23,x18,3		# Xupdate(17)
	add	x17,x17,x26		# +=X[i+9]
	sllw	x22,x18,14
	srlw	x21,x18,7
	xor	x23,x23,x22
	sllw	x22,x22,11
	xor	x23,x23,x21
	srlw	x21,x18,18
	xor	x23,x23,x22

	srlw	x24,x31,10
	xor	x23,x23,x21		# sigma0(X[i+1])
	sllw	x22,x31,13
	add	x17,x17,x23
	srlw	x21,x31,17
	xor	x24,x24,x22
	sllw	x22,x22,2
	xor	x24,x24,x21
	srlw	x21,x31,19
	xor	x24,x24,x22
#endif
	xor	x24,x24,x21		# sigma1(X[i+14])
	add	x17,x17,x24
#ifdef	__riscv_zbb
	xor	x24,x9,x13			# 17
	rorw	x22,x8,6
	add	x21,x17,x14
	rorw	x23,x8,11
	and	x24,x24,x8
	rorw	x14,x8,25
	xor	x22,x22,x23
	rorw	x23,x15,2
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x22,x14			# Sigma1(e)

	rorw	x14,x15,13
	add	x21,x21,x24
	lw	x24,68(x12)		# K[17]
	xor	x14,x14,x23
	rorw	x23,x15,22
	add	x21,x21,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#else
	add	x21,x17,x14			# 17
	srlw	x14,x8,6
	xor	x24,x9,x13
	sllw	x23,x8,7
	and	x24,x24,x8
	srlw	x22,x8,11
	xor	x14,x14,x23
	sllw	x23,x8,21
	xor	x14,x14,x22
	srlw	x22,x8,25
	xor	x14,x14,x23
	sllw	x23,x8,26
	xor	x14,x14,x22
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x23,x14			# Sigma1(e)

	srlw	x14,x15,2
	add	x21,x21,x24
	lw	x24,68(x12)		# K[17]
	sllw	x23,x15,10
	add	x21,x21,x22
	srlw	x22,x15,13
	xor	x14,x14,x23
	sllw	x23,x15,19
	xor	x14,x14,x22
	srlw	x22,x15,22
	xor	x14,x14,x23
	sllw	x23,x15,30
	xor	x14,x14,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#endif
	sw	x17,4(x2)	# offload to ring buffer
	add	x14,x14,x22
	and	x23,x23,x15
	add	x21,x21,x24			# +=K[17]
	add	x14,x14,x23			# +=Maj(a,b,c)
	add	x7,x7,x21
	add	x14,x14,x21
	lw	x20,16(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x24,x19,3		# Xupdate(18)
	rorw	x22,x19,7
	add	x18,x18,x27		# +=X[i+9]
	xor	x24,x24,x22
	rorw	x22,x19,18

	srlw	x25,x16,10
	rorw	x23,x16,17
	xor	x24,x24,x22		# sigma0(X[i+1])
	rorw	x22,x16,19
	xor	x25,x25,x23
	add	x18,x18,x24
#else
	srlw	x24,x19,3		# Xupdate(18)
	add	x18,x18,x27		# +=X[i+9]
	sllw	x23,x19,14
	srlw	x22,x19,7
	xor	x24,x24,x23
	sllw	x23,x23,11
	xor	x24,x24,x22
	srlw	x22,x19,18
	xor	x24,x24,x23

	srlw	x25,x16,10
	xor	x24,x24,x22		# sigma0(X[i+1])
	sllw	x23,x16,13
	add	x18,x18,x24
	srlw	x22,x16,17
	xor	x25,x25,x23
	sllw	x23,x23,2
	xor	x25,x25,x22
	srlw	x22,x16,19
	xor	x25,x25,x23
#endif
	xor	x25,x25,x22		# sigma1(X[i+14])
	add	x18,x18,x25
#ifdef	__riscv_zbb
	xor	x25,x8,x9			# 18
	rorw	x23,x7,6
	add	x22,x18,x13
	rorw	x24,x7,11
	and	x25,x25,x7
	rorw	x13,x7,25
	xor	x23,x23,x24
	rorw	x24,x14,2
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x23,x13			# Sigma1(e)

	rorw	x13,x14,13
	add	x22,x22,x25
	lw	x25,72(x12)		# K[18]
	xor	x13,x13,x24
	rorw	x24,x14,22
	add	x22,x22,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#else
	add	x22,x18,x13			# 18
	srlw	x13,x7,6
	xor	x25,x8,x9
	sllw	x24,x7,7
	and	x25,x25,x7
	srlw	x23,x7,11
	xor	x13,x13,x24
	sllw	x24,x7,21
	xor	x13,x13,x23
	srlw	x23,x7,25
	xor	x13,x13,x24
	sllw	x24,x7,26
	xor	x13,x13,x23
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x24,x13			# Sigma1(e)

	srlw	x13,x14,2
	add	x22,x22,x25
	lw	x25,72(x12)		# K[18]
	sllw	x24,x14,10
	add	x22,x22,x23
	srlw	x23,x14,13
	xor	x13,x13,x24
	sllw	x24,x14,19
	xor	x13,x13,x23
	srlw	x23,x14,22
	xor	x13,x13,x24
	sllw	x24,x14,30
	xor	x13,x13,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#endif
	sw	x18,8(x2)	# offload to ring buffer
	add	x13,x13,x23
	and	x24,x24,x14
	add	x22,x22,x25			# +=K[18]
	add	x13,x13,x24			# +=Maj(a,b,c)
	add	x6,x6,x22
	add	x13,x13,x22
	lw	x21,20(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x25,x20,3		# Xupdate(19)
	rorw	x23,x20,7
	add	x19,x19,x28		# +=X[i+9]
	xor	x25,x25,x23
	rorw	x23,x20,18

	srlw	x26,x17,10
	rorw	x24,x17,17
	xor	x25,x25,x23		# sigma0(X[i+1])
	rorw	x23,x17,19
	xor	x26,x26,x24
	add	x19,x19,x25
#else
	srlw	x25,x20,3		# Xupdate(19)
	add	x19,x19,x28		# +=X[i+9]
	sllw	x24,x20,14
	srlw	x23,x20,7
	xor	x25,x25,x24
	sllw	x24,x24,11
	xor	x25,x25,x23
	srlw	x23,x20,18
	xor	x25,x25,x24

	srlw	x26,x17,10
	xor	x25,x25,x23		# sigma0(X[i+1])
	sllw	x24,x17,13
	add	x19,x19,x25
	srlw	x23,x17,17
	xor	x26,x26,x24
	sllw	x24,x24,2
	xor	x26,x26,x23
	srlw	x23,x17,19
	xor	x26,x26,x24
#endif
	xor	x26,x26,x23		# sigma1(X[i+14])
	add	x19,x19,x26
#ifdef	__riscv_zbb
	xor	x26,x7,x8			# 19
	rorw	x24,x6,6
	add	x23,x19,x9
	rorw	x25,x6,11
	and	x26,x26,x6
	rorw	x9,x6,25
	xor	x24,x24,x25
	rorw	x25,x13,2
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x24,x9			# Sigma1(e)

	rorw	x9,x13,13
	add	x23,x23,x26
	lw	x26,76(x12)		# K[19]
	xor	x9,x9,x25
	rorw	x25,x13,22
	add	x23,x23,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#else
	add	x23,x19,x9			# 19
	srlw	x9,x6,6
	xor	x26,x7,x8
	sllw	x25,x6,7
	and	x26,x26,x6
	srlw	x24,x6,11
	xor	x9,x9,x25
	sllw	x25,x6,21
	xor	x9,x9,x24
	srlw	x24,x6,25
	xor	x9,x9,x25
	sllw	x25,x6,26
	xor	x9,x9,x24
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x25,x9			# Sigma1(e)

	srlw	x9,x13,2
	add	x23,x23,x26
	lw	x26,76(x12)		# K[19]
	sllw	x25,x13,10
	add	x23,x23,x24
	srlw	x24,x13,13
	xor	x9,x9,x25
	sllw	x25,x13,19
	xor	x9,x9,x24
	srlw	x24,x13,22
	xor	x9,x9,x25
	sllw	x25,x13,30
	xor	x9,x9,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#endif
	sw	x19,12(x2)	# offload to ring buffer
	add	x9,x9,x24
	and	x25,x25,x13
	add	x23,x23,x26			# +=K[19]
	add	x9,x9,x25			# +=Maj(a,b,c)
	add	x5,x5,x23
	add	x9,x9,x23
	lw	x22,24(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x26,x21,3		# Xupdate(20)
	rorw	x24,x21,7
	add	x20,x20,x29		# +=X[i+9]
	xor	x26,x26,x24
	rorw	x24,x21,18

	srlw	x27,x18,10
	rorw	x25,x18,17
	xor	x26,x26,x24		# sigma0(X[i+1])
	rorw	x24,x18,19
	xor	x27,x27,x25
	add	x20,x20,x26
#else
	srlw	x26,x21,3		# Xupdate(20)
	add	x20,x20,x29		# +=X[i+9]
	sllw	x25,x21,14
	srlw	x24,x21,7
	xor	x26,x26,x25
	sllw	x25,x25,11
	xor	x26,x26,x24
	srlw	x24,x21,18
	xor	x26,x26,x25

	srlw	x27,x18,10
	xor	x26,x26,x24		# sigma0(X[i+1])
	sllw	x25,x18,13
	add	x20,x20,x26
	srlw	x24,x18,17
	xor	x27,x27,x25
	sllw	x25,x25,2
	xor	x27,x27,x24
	srlw	x24,x18,19
	xor	x27,x27,x25
#endif
	xor	x27,x27,x24		# sigma1(X[i+14])
	add	x20,x20,x27
#ifdef	__riscv_zbb
	xor	x27,x6,x7			# 20
	rorw	x25,x5,6
	add	x24,x20,x8
	rorw	x26,x5,11
	and	x27,x27,x5
	rorw	x8,x5,25
	xor	x25,x25,x26
	rorw	x26,x9,2
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x25,x8			# Sigma1(e)

	rorw	x8,x9,13
	add	x24,x24,x27
	lw	x27,80(x12)		# K[20]
	xor	x8,x8,x26
	rorw	x26,x9,22
	add	x24,x24,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#else
	add	x24,x20,x8			# 20
	srlw	x8,x5,6
	xor	x27,x6,x7
	sllw	x26,x5,7
	and	x27,x27,x5
	srlw	x25,x5,11
	xor	x8,x8,x26
	sllw	x26,x5,21
	xor	x8,x8,x25
	srlw	x25,x5,25
	xor	x8,x8,x26
	sllw	x26,x5,26
	xor	x8,x8,x25
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x26,x8			# Sigma1(e)

	srlw	x8,x9,2
	add	x24,x24,x27
	lw	x27,80(x12)		# K[20]
	sllw	x26,x9,10
	add	x24,x24,x25
	srlw	x25,x9,13
	xor	x8,x8,x26
	sllw	x26,x9,19
	xor	x8,x8,x25
	srlw	x25,x9,22
	xor	x8,x8,x26
	sllw	x26,x9,30
	xor	x8,x8,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#endif
	sw	x20,16(x2)	# offload to ring buffer
	add	x8,x8,x25
	and	x26,x26,x9
	add	x24,x24,x27			# +=K[20]
	add	x8,x8,x26			# +=Maj(a,b,c)
	add	x15,x15,x24
	add	x8,x8,x24
	lw	x23,28(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x27,x22,3		# Xupdate(21)
	rorw	x25,x22,7
	add	x21,x21,x30		# +=X[i+9]
	xor	x27,x27,x25
	rorw	x25,x22,18

	srlw	x28,x19,10
	rorw	x26,x19,17
	xor	x27,x27,x25		# sigma0(X[i+1])
	rorw	x25,x19,19
	xor	x28,x28,x26
	add	x21,x21,x27
#else
	srlw	x27,x22,3		# Xupdate(21)
	add	x21,x21,x30		# +=X[i+9]
	sllw	x26,x22,14
	srlw	x25,x22,7
	xor	x27,x27,x26
	sllw	x26,x26,11
	xor	x27,x27,x25
	srlw	x25,x22,18
	xor	x27,x27,x26

	srlw	x28,x19,10
	xor	x27,x27,x25		# sigma0(X[i+1])
	sllw	x26,x19,13
	add	x21,x21,x27
	srlw	x25,x19,17
	xor	x28,x28,x26
	sllw	x26,x26,2
	xor	x28,x28,x25
	srlw	x25,x19,19
	xor	x28,x28,x26
#endif
	xor	x28,x28,x25		# sigma1(X[i+14])
	add	x21,x21,x28
#ifdef	__riscv_zbb
	xor	x28,x5,x6			# 21
	rorw	x26,x15,6
	add	x25,x21,x7
	rorw	x27,x15,11
	and	x28,x28,x15
	rorw	x7,x15,25
	xor	x26,x26,x27
	rorw	x27,x8,2
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x26,x7			# Sigma1(e)

	rorw	x7,x8,13
	add	x25,x25,x28
	lw	x28,84(x12)		# K[21]
	xor	x7,x7,x27
	rorw	x27,x8,22
	add	x25,x25,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#else
	add	x25,x21,x7			# 21
	srlw	x7,x15,6
	xor	x28,x5,x6
	sllw	x27,x15,7
	and	x28,x28,x15
	srlw	x26,x15,11
	xor	x7,x7,x27
	sllw	x27,x15,21
	xor	x7,x7,x26
	srlw	x26,x15,25
	xor	x7,x7,x27
	sllw	x27,x15,26
	xor	x7,x7,x26
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x27,x7			# Sigma1(e)

	srlw	x7,x8,2
	add	x25,x25,x28
	lw	x28,84(x12)		# K[21]
	sllw	x27,x8,10
	add	x25,x25,x26
	srlw	x26,x8,13
	xor	x7,x7,x27
	sllw	x27,x8,19
	xor	x7,x7,x26
	srlw	x26,x8,22
	xor	x7,x7,x27
	sllw	x27,x8,30
	xor	x7,x7,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#endif
	sw	x21,20(x2)	# offload to ring buffer
	add	x7,x7,x26
	and	x27,x27,x8
	add	x25,x25,x28			# +=K[21]
	add	x7,x7,x27			# +=Maj(a,b,c)
	add	x14,x14,x25
	add	x7,x7,x25
	lw	x24,32(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x28,x23,3		# Xupdate(22)
	rorw	x26,x23,7
	add	x22,x22,x31		# +=X[i+9]
	xor	x28,x28,x26
	rorw	x26,x23,18

	srlw	x29,x20,10
	rorw	x27,x20,17
	xor	x28,x28,x26		# sigma0(X[i+1])
	rorw	x26,x20,19
	xor	x29,x29,x27
	add	x22,x22,x28
#else
	srlw	x28,x23,3		# Xupdate(22)
	add	x22,x22,x31		# +=X[i+9]
	sllw	x27,x23,14
	srlw	x26,x23,7
	xor	x28,x28,x27
	sllw	x27,x27,11
	xor	x28,x28,x26
	srlw	x26,x23,18
	xor	x28,x28,x27

	srlw	x29,x20,10
	xor	x28,x28,x26		# sigma0(X[i+1])
	sllw	x27,x20,13
	add	x22,x22,x28
	srlw	x26,x20,17
	xor	x29,x29,x27
	sllw	x27,x27,2
	xor	x29,x29,x26
	srlw	x26,x20,19
	xor	x29,x29,x27
#endif
	xor	x29,x29,x26		# sigma1(X[i+14])
	add	x22,x22,x29
#ifdef	__riscv_zbb
	xor	x29,x15,x5			# 22
	rorw	x27,x14,6
	add	x26,x22,x6
	rorw	x28,x14,11
	and	x29,x29,x14
	rorw	x6,x14,25
	xor	x27,x27,x28
	rorw	x28,x7,2
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x27,x6			# Sigma1(e)

	rorw	x6,x7,13
	add	x26,x26,x29
	lw	x29,88(x12)		# K[22]
	xor	x6,x6,x28
	rorw	x28,x7,22
	add	x26,x26,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#else
	add	x26,x22,x6			# 22
	srlw	x6,x14,6
	xor	x29,x15,x5
	sllw	x28,x14,7
	and	x29,x29,x14
	srlw	x27,x14,11
	xor	x6,x6,x28
	sllw	x28,x14,21
	xor	x6,x6,x27
	srlw	x27,x14,25
	xor	x6,x6,x28
	sllw	x28,x14,26
	xor	x6,x6,x27
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x28,x6			# Sigma1(e)

	srlw	x6,x7,2
	add	x26,x26,x29
	lw	x29,88(x12)		# K[22]
	sllw	x28,x7,10
	add	x26,x26,x27
	srlw	x27,x7,13
	xor	x6,x6,x28
	sllw	x28,x7,19
	xor	x6,x6,x27
	srlw	x27,x7,22
	xor	x6,x6,x28
	sllw	x28,x7,30
	xor	x6,x6,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#endif
	sw	x22,24(x2)	# offload to ring buffer
	add	x6,x6,x27
	and	x28,x28,x7
	add	x26,x26,x29			# +=K[22]
	add	x6,x6,x28			# +=Maj(a,b,c)
	add	x13,x13,x26
	add	x6,x6,x26
	lw	x25,36(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x29,x24,3		# Xupdate(23)
	rorw	x27,x24,7
	add	x23,x23,x16		# +=X[i+9]
	xor	x29,x29,x27
	rorw	x27,x24,18

	srlw	x30,x21,10
	rorw	x28,x21,17
	xor	x29,x29,x27		# sigma0(X[i+1])
	rorw	x27,x21,19
	xor	x30,x30,x28
	add	x23,x23,x29
#else
	srlw	x29,x24,3		# Xupdate(23)
	add	x23,x23,x16		# +=X[i+9]
	sllw	x28,x24,14
	srlw	x27,x24,7
	xor	x29,x29,x28
	sllw	x28,x28,11
	xor	x29,x29,x27
	srlw	x27,x24,18
	xor	x29,x29,x28

	srlw	x30,x21,10
	xor	x29,x29,x27		# sigma0(X[i+1])
	sllw	x28,x21,13
	add	x23,x23,x29
	srlw	x27,x21,17
	xor	x30,x30,x28
	sllw	x28,x28,2
	xor	x30,x30,x27
	srlw	x27,x21,19
	xor	x30,x30,x28
#endif
	xor	x30,x30,x27		# sigma1(X[i+14])
	add	x23,x23,x30
#ifdef	__riscv_zbb
	xor	x30,x14,x15			# 23
	rorw	x28,x13,6
	add	x27,x23,x5
	rorw	x29,x13,11
	and	x30,x30,x13
	rorw	x5,x13,25
	xor	x28,x28,x29
	rorw	x29,x6,2
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x28,x5			# Sigma1(e)

	rorw	x5,x6,13
	add	x27,x27,x30
	lw	x30,92(x12)		# K[23]
	xor	x5,x5,x29
	rorw	x29,x6,22
	add	x27,x27,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#else
	add	x27,x23,x5			# 23
	srlw	x5,x13,6
	xor	x30,x14,x15
	sllw	x29,x13,7
	and	x30,x30,x13
	srlw	x28,x13,11
	xor	x5,x5,x29
	sllw	x29,x13,21
	xor	x5,x5,x28
	srlw	x28,x13,25
	xor	x5,x5,x29
	sllw	x29,x13,26
	xor	x5,x5,x28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x29,x5			# Sigma1(e)

	srlw	x5,x6,2
	add	x27,x27,x30
	lw	x30,92(x12)		# K[23]
	sllw	x29,x6,10
	add	x27,x27,x28
	srlw	x28,x6,13
	xor	x5,x5,x29
	sllw	x29,x6,19
	xor	x5,x5,x28
	srlw	x28,x6,22
	xor	x5,x5,x29
	sllw	x29,x6,30
	xor	x5,x5,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#endif
	sw	x23,28(x2)	# offload to ring buffer
	add	x5,x5,x28
	and	x29,x29,x6
	add	x27,x27,x30			# +=K[23]
	add	x5,x5,x29			# +=Maj(a,b,c)
	add	x9,x9,x27
	add	x5,x5,x27
	lw	x26,40(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x30,x25,3		# Xupdate(24)
	rorw	x28,x25,7
	add	x24,x24,x17		# +=X[i+9]
	xor	x30,x30,x28
	rorw	x28,x25,18

	srlw	x31,x22,10
	rorw	x29,x22,17
	xor	x30,x30,x28		# sigma0(X[i+1])
	rorw	x28,x22,19
	xor	x31,x31,x29
	add	x24,x24,x30
#else
	srlw	x30,x25,3		# Xupdate(24)
	add	x24,x24,x17		# +=X[i+9]
	sllw	x29,x25,14
	srlw	x28,x25,7
	xor	x30,x30,x29
	sllw	x29,x29,11
	xor	x30,x30,x28
	srlw	x28,x25,18
	xor	x30,x30,x29

	srlw	x31,x22,10
	xor	x30,x30,x28		# sigma0(X[i+1])
	sllw	x29,x22,13
	add	x24,x24,x30
	srlw	x28,x22,17
	xor	x31,x31,x29
	sllw	x29,x29,2
	xor	x31,x31,x28
	srlw	x28,x22,19
	xor	x31,x31,x29
#endif
	xor	x31,x31,x28		# sigma1(X[i+14])
	add	x24,x24,x31
#ifdef	__riscv_zbb
	xor	x31,x13,x14			# 24
	rorw	x29,x9,6
	add	x28,x24,x15
	rorw	x30,x9,11
	and	x31,x31,x9
	rorw	x15,x9,25
	xor	x29,x29,x30
	rorw	x30,x5,2
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x29,x15			# Sigma1(e)

	rorw	x15,x5,13
	add	x28,x28,x31
	lw	x31,96(x12)		# K[24]
	xor	x15,x15,x30
	rorw	x30,x5,22
	add	x28,x28,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#else
	add	x28,x24,x15			# 24
	srlw	x15,x9,6
	xor	x31,x13,x14
	sllw	x30,x9,7
	and	x31,x31,x9
	srlw	x29,x9,11
	xor	x15,x15,x30
	sllw	x30,x9,21
	xor	x15,x15,x29
	srlw	x29,x9,25
	xor	x15,x15,x30
	sllw	x30,x9,26
	xor	x15,x15,x29
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x30,x15			# Sigma1(e)

	srlw	x15,x5,2
	add	x28,x28,x31
	lw	x31,96(x12)		# K[24]
	sllw	x30,x5,10
	add	x28,x28,x29
	srlw	x29,x5,13
	xor	x15,x15,x30
	sllw	x30,x5,19
	xor	x15,x15,x29
	srlw	x29,x5,22
	xor	x15,x15,x30
	sllw	x30,x5,30
	xor	x15,x15,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#endif
	sw	x24,32(x2)	# offload to ring buffer
	add	x15,x15,x29
	and	x30,x30,x5
	add	x28,x28,x31			# +=K[24]
	add	x15,x15,x30			# +=Maj(a,b,c)
	add	x8,x8,x28
	add	x15,x15,x28
	lw	x27,44(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x31,x26,3		# Xupdate(25)
	rorw	x29,x26,7
	add	x25,x25,x18		# +=X[i+9]
	xor	x31,x31,x29
	rorw	x29,x26,18

	srlw	x16,x23,10
	rorw	x30,x23,17
	xor	x31,x31,x29		# sigma0(X[i+1])
	rorw	x29,x23,19
	xor	x16,x16,x30
	add	x25,x25,x31
#else
	srlw	x31,x26,3		# Xupdate(25)
	add	x25,x25,x18		# +=X[i+9]
	sllw	x30,x26,14
	srlw	x29,x26,7
	xor	x31,x31,x30
	sllw	x30,x30,11
	xor	x31,x31,x29
	srlw	x29,x26,18
	xor	x31,x31,x30

	srlw	x16,x23,10
	xor	x31,x31,x29		# sigma0(X[i+1])
	sllw	x30,x23,13
	add	x25,x25,x31
	srlw	x29,x23,17
	xor	x16,x16,x30
	sllw	x30,x30,2
	xor	x16,x16,x29
	srlw	x29,x23,19
	xor	x16,x16,x30
#endif
	xor	x16,x16,x29		# sigma1(X[i+14])
	add	x25,x25,x16
#ifdef	__riscv_zbb
	xor	x16,x9,x13			# 25
	rorw	x30,x8,6
	add	x29,x25,x14
	rorw	x31,x8,11
	and	x16,x16,x8
	rorw	x14,x8,25
	xor	x30,x30,x31
	rorw	x31,x15,2
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x30,x14			# Sigma1(e)

	rorw	x14,x15,13
	add	x29,x29,x16
	lw	x16,100(x12)		# K[25]
	xor	x14,x14,x31
	rorw	x31,x15,22
	add	x29,x29,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#else
	add	x29,x25,x14			# 25
	srlw	x14,x8,6
	xor	x16,x9,x13
	sllw	x31,x8,7
	and	x16,x16,x8
	srlw	x30,x8,11
	xor	x14,x14,x31
	sllw	x31,x8,21
	xor	x14,x14,x30
	srlw	x30,x8,25
	xor	x14,x14,x31
	sllw	x31,x8,26
	xor	x14,x14,x30
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x31,x14			# Sigma1(e)

	srlw	x14,x15,2
	add	x29,x29,x16
	lw	x16,100(x12)		# K[25]
	sllw	x31,x15,10
	add	x29,x29,x30
	srlw	x30,x15,13
	xor	x14,x14,x31
	sllw	x31,x15,19
	xor	x14,x14,x30
	srlw	x30,x15,22
	xor	x14,x14,x31
	sllw	x31,x15,30
	xor	x14,x14,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#endif
	sw	x25,36(x2)	# offload to ring buffer
	add	x14,x14,x30
	and	x31,x31,x15
	add	x29,x29,x16			# +=K[25]
	add	x14,x14,x31			# +=Maj(a,b,c)
	add	x7,x7,x29
	add	x14,x14,x29
	lw	x28,48(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x16,x27,3		# Xupdate(26)
	rorw	x30,x27,7
	add	x26,x26,x19		# +=X[i+9]
	xor	x16,x16,x30
	rorw	x30,x27,18

	srlw	x17,x24,10
	rorw	x31,x24,17
	xor	x16,x16,x30		# sigma0(X[i+1])
	rorw	x30,x24,19
	xor	x17,x17,x31
	add	x26,x26,x16
#else
	srlw	x16,x27,3		# Xupdate(26)
	add	x26,x26,x19		# +=X[i+9]
	sllw	x31,x27,14
	srlw	x30,x27,7
	xor	x16,x16,x31
	sllw	x31,x31,11
	xor	x16,x16,x30
	srlw	x30,x27,18
	xor	x16,x16,x31

	srlw	x17,x24,10
	xor	x16,x16,x30		# sigma0(X[i+1])
	sllw	x31,x24,13
	add	x26,x26,x16
	srlw	x30,x24,17
	xor	x17,x17,x31
	sllw	x31,x31,2
	xor	x17,x17,x30
	srlw	x30,x24,19
	xor	x17,x17,x31
#endif
	xor	x17,x17,x30		# sigma1(X[i+14])
	add	x26,x26,x17
#ifdef	__riscv_zbb
	xor	x17,x8,x9			# 26
	rorw	x31,x7,6
	add	x30,x26,x13
	rorw	x16,x7,11
	and	x17,x17,x7
	rorw	x13,x7,25
	xor	x31,x31,x16
	rorw	x16,x14,2
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x31,x13			# Sigma1(e)

	rorw	x13,x14,13
	add	x30,x30,x17
	lw	x17,104(x12)		# K[26]
	xor	x13,x13,x16
	rorw	x16,x14,22
	add	x30,x30,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#else
	add	x30,x26,x13			# 26
	srlw	x13,x7,6
	xor	x17,x8,x9
	sllw	x16,x7,7
	and	x17,x17,x7
	srlw	x31,x7,11
	xor	x13,x13,x16
	sllw	x16,x7,21
	xor	x13,x13,x31
	srlw	x31,x7,25
	xor	x13,x13,x16
	sllw	x16,x7,26
	xor	x13,x13,x31
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x16,x13			# Sigma1(e)

	srlw	x13,x14,2
	add	x30,x30,x17
	lw	x17,104(x12)		# K[26]
	sllw	x16,x14,10
	add	x30,x30,x31
	srlw	x31,x14,13
	xor	x13,x13,x16
	sllw	x16,x14,19
	xor	x13,x13,x31
	srlw	x31,x14,22
	xor	x13,x13,x16
	sllw	x16,x14,30
	xor	x13,x13,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#endif
	sw	x26,40(x2)	# offload to ring buffer
	add	x13,x13,x31
	and	x16,x16,x14
	add	x30,x30,x17			# +=K[26]
	add	x13,x13,x16			# +=Maj(a,b,c)
	add	x6,x6,x30
	add	x13,x13,x30
	lw	x29,52(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x17,x28,3		# Xupdate(27)
	rorw	x31,x28,7
	add	x27,x27,x20		# +=X[i+9]
	xor	x17,x17,x31
	rorw	x31,x28,18

	srlw	x18,x25,10
	rorw	x16,x25,17
	xor	x17,x17,x31		# sigma0(X[i+1])
	rorw	x31,x25,19
	xor	x18,x18,x16
	add	x27,x27,x17
#else
	srlw	x17,x28,3		# Xupdate(27)
	add	x27,x27,x20		# +=X[i+9]
	sllw	x16,x28,14
	srlw	x31,x28,7
	xor	x17,x17,x16
	sllw	x16,x16,11
	xor	x17,x17,x31
	srlw	x31,x28,18
	xor	x17,x17,x16

	srlw	x18,x25,10
	xor	x17,x17,x31		# sigma0(X[i+1])
	sllw	x16,x25,13
	add	x27,x27,x17
	srlw	x31,x25,17
	xor	x18,x18,x16
	sllw	x16,x16,2
	xor	x18,x18,x31
	srlw	x31,x25,19
	xor	x18,x18,x16
#endif
	xor	x18,x18,x31		# sigma1(X[i+14])
	add	x27,x27,x18
#ifdef	__riscv_zbb
	xor	x18,x7,x8			# 27
	rorw	x16,x6,6
	add	x31,x27,x9
	rorw	x17,x6,11
	and	x18,x18,x6
	rorw	x9,x6,25
	xor	x16,x16,x17
	rorw	x17,x13,2
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x16,x9			# Sigma1(e)

	rorw	x9,x13,13
	add	x31,x31,x18
	lw	x18,108(x12)		# K[27]
	xor	x9,x9,x17
	rorw	x17,x13,22
	add	x31,x31,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#else
	add	x31,x27,x9			# 27
	srlw	x9,x6,6
	xor	x18,x7,x8
	sllw	x17,x6,7
	and	x18,x18,x6
	srlw	x16,x6,11
	xor	x9,x9,x17
	sllw	x17,x6,21
	xor	x9,x9,x16
	srlw	x16,x6,25
	xor	x9,x9,x17
	sllw	x17,x6,26
	xor	x9,x9,x16
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x17,x9			# Sigma1(e)

	srlw	x9,x13,2
	add	x31,x31,x18
	lw	x18,108(x12)		# K[27]
	sllw	x17,x13,10
	add	x31,x31,x16
	srlw	x16,x13,13
	xor	x9,x9,x17
	sllw	x17,x13,19
	xor	x9,x9,x16
	srlw	x16,x13,22
	xor	x9,x9,x17
	sllw	x17,x13,30
	xor	x9,x9,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#endif
	sw	x27,44(x2)	# offload to ring buffer
	add	x9,x9,x16
	and	x17,x17,x13
	add	x31,x31,x18			# +=K[27]
	add	x9,x9,x17			# +=Maj(a,b,c)
	add	x5,x5,x31
	add	x9,x9,x31
	lw	x30,56(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x18,x29,3		# Xupdate(28)
	rorw	x16,x29,7
	add	x28,x28,x21		# +=X[i+9]
	xor	x18,x18,x16
	rorw	x16,x29,18

	srlw	x19,x26,10
	rorw	x17,x26,17
	xor	x18,x18,x16		# sigma0(X[i+1])
	rorw	x16,x26,19
	xor	x19,x19,x17
	add	x28,x28,x18
#else
	srlw	x18,x29,3		# Xupdate(28)
	add	x28,x28,x21		# +=X[i+9]
	sllw	x17,x29,14
	srlw	x16,x29,7
	xor	x18,x18,x17
	sllw	x17,x17,11
	xor	x18,x18,x16
	srlw	x16,x29,18
	xor	x18,x18,x17

	srlw	x19,x26,10
	xor	x18,x18,x16		# sigma0(X[i+1])
	sllw	x17,x26,13
	add	x28,x28,x18
	srlw	x16,x26,17
	xor	x19,x19,x17
	sllw	x17,x17,2
	xor	x19,x19,x16
	srlw	x16,x26,19
	xor	x19,x19,x17
#endif
	xor	x19,x19,x16		# sigma1(X[i+14])
	add	x28,x28,x19
#ifdef	__riscv_zbb
	xor	x19,x6,x7			# 28
	rorw	x17,x5,6
	add	x16,x28,x8
	rorw	x18,x5,11
	and	x19,x19,x5
	rorw	x8,x5,25
	xor	x17,x17,x18
	rorw	x18,x9,2
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x17,x8			# Sigma1(e)

	rorw	x8,x9,13
	add	x16,x16,x19
	lw	x19,112(x12)		# K[28]
	xor	x8,x8,x18
	rorw	x18,x9,22
	add	x16,x16,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#else
	add	x16,x28,x8			# 28
	srlw	x8,x5,6
	xor	x19,x6,x7
	sllw	x18,x5,7
	and	x19,x19,x5
	srlw	x17,x5,11
	xor	x8,x8,x18
	sllw	x18,x5,21
	xor	x8,x8,x17
	srlw	x17,x5,25
	xor	x8,x8,x18
	sllw	x18,x5,26
	xor	x8,x8,x17
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x18,x8			# Sigma1(e)

	srlw	x8,x9,2
	add	x16,x16,x19
	lw	x19,112(x12)		# K[28]
	sllw	x18,x9,10
	add	x16,x16,x17
	srlw	x17,x9,13
	xor	x8,x8,x18
	sllw	x18,x9,19
	xor	x8,x8,x17
	srlw	x17,x9,22
	xor	x8,x8,x18
	sllw	x18,x9,30
	xor	x8,x8,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#endif
	sw	x28,48(x2)	# offload to ring buffer
	add	x8,x8,x17
	and	x18,x18,x9
	add	x16,x16,x19			# +=K[28]
	add	x8,x8,x18			# +=Maj(a,b,c)
	add	x15,x15,x16
	add	x8,x8,x16
	lw	x31,60(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x19,x30,3		# Xupdate(29)
	rorw	x17,x30,7
	add	x29,x29,x22		# +=X[i+9]
	xor	x19,x19,x17
	rorw	x17,x30,18

	srlw	x20,x27,10
	rorw	x18,x27,17
	xor	x19,x19,x17		# sigma0(X[i+1])
	rorw	x17,x27,19
	xor	x20,x20,x18
	add	x29,x29,x19
#else
	srlw	x19,x30,3		# Xupdate(29)
	add	x29,x29,x22		# +=X[i+9]
	sllw	x18,x30,14
	srlw	x17,x30,7
	xor	x19,x19,x18
	sllw	x18,x18,11
	xor	x19,x19,x17
	srlw	x17,x30,18
	xor	x19,x19,x18

	srlw	x20,x27,10
	xor	x19,x19,x17		# sigma0(X[i+1])
	sllw	x18,x27,13
	add	x29,x29,x19
	srlw	x17,x27,17
	xor	x20,x20,x18
	sllw	x18,x18,2
	xor	x20,x20,x17
	srlw	x17,x27,19
	xor	x20,x20,x18
#endif
	xor	x20,x20,x17		# sigma1(X[i+14])
	add	x29,x29,x20
#ifdef	__riscv_zbb
	xor	x20,x5,x6			# 29
	rorw	x18,x15,6
	add	x17,x29,x7
	rorw	x19,x15,11
	and	x20,x20,x15
	rorw	x7,x15,25
	xor	x18,x18,x19
	rorw	x19,x8,2
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x18,x7			# Sigma1(e)

	rorw	x7,x8,13
	add	x17,x17,x20
	lw	x20,116(x12)		# K[29]
	xor	x7,x7,x19
	rorw	x19,x8,22
	add	x17,x17,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#else
	add	x17,x29,x7			# 29
	srlw	x7,x15,6
	xor	x20,x5,x6
	sllw	x19,x15,7
	and	x20,x20,x15
	srlw	x18,x15,11
	xor	x7,x7,x19
	sllw	x19,x15,21
	xor	x7,x7,x18
	srlw	x18,x15,25
	xor	x7,x7,x19
	sllw	x19,x15,26
	xor	x7,x7,x18
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x19,x7			# Sigma1(e)

	srlw	x7,x8,2
	add	x17,x17,x20
	lw	x20,116(x12)		# K[29]
	sllw	x19,x8,10
	add	x17,x17,x18
	srlw	x18,x8,13
	xor	x7,x7,x19
	sllw	x19,x8,19
	xor	x7,x7,x18
	srlw	x18,x8,22
	xor	x7,x7,x19
	sllw	x19,x8,30
	xor	x7,x7,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#endif
	sw	x29,52(x2)	# offload to ring buffer
	add	x7,x7,x18
	and	x19,x19,x8
	add	x17,x17,x20			# +=K[29]
	add	x7,x7,x19			# +=Maj(a,b,c)
	add	x14,x14,x17
	add	x7,x7,x17
	lw	x16,0(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x20,x31,3		# Xupdate(30)
	rorw	x18,x31,7
	add	x30,x30,x23		# +=X[i+9]
	xor	x20,x20,x18
	rorw	x18,x31,18

	srlw	x21,x28,10
	rorw	x19,x28,17
	xor	x20,x20,x18		# sigma0(X[i+1])
	rorw	x18,x28,19
	xor	x21,x21,x19
	add	x30,x30,x20
#else
	srlw	x20,x31,3		# Xupdate(30)
	add	x30,x30,x23		# +=X[i+9]
	sllw	x19,x31,14
	srlw	x18,x31,7
	xor	x20,x20,x19
	sllw	x19,x19,11
	xor	x20,x20,x18
	srlw	x18,x31,18
	xor	x20,x20,x19

	srlw	x21,x28,10
	xor	x20,x20,x18		# sigma0(X[i+1])
	sllw	x19,x28,13
	add	x30,x30,x20
	srlw	x18,x28,17
	xor	x21,x21,x19
	sllw	x19,x19,2
	xor	x21,x21,x18
	srlw	x18,x28,19
	xor	x21,x21,x19
#endif
	xor	x21,x21,x18		# sigma1(X[i+14])
	add	x30,x30,x21
#ifdef	__riscv_zbb
	xor	x21,x15,x5			# 30
	rorw	x19,x14,6
	add	x18,x30,x6
	rorw	x20,x14,11
	and	x21,x21,x14
	rorw	x6,x14,25
	xor	x19,x19,x20
	rorw	x20,x7,2
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x19,x6			# Sigma1(e)

	rorw	x6,x7,13
	add	x18,x18,x21
	lw	x21,120(x12)		# K[30]
	xor	x6,x6,x20
	rorw	x20,x7,22
	add	x18,x18,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#else
	add	x18,x30,x6			# 30
	srlw	x6,x14,6
	xor	x21,x15,x5
	sllw	x20,x14,7
	and	x21,x21,x14
	srlw	x19,x14,11
	xor	x6,x6,x20
	sllw	x20,x14,21
	xor	x6,x6,x19
	srlw	x19,x14,25
	xor	x6,x6,x20
	sllw	x20,x14,26
	xor	x6,x6,x19
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x20,x6			# Sigma1(e)

	srlw	x6,x7,2
	add	x18,x18,x21
	lw	x21,120(x12)		# K[30]
	sllw	x20,x7,10
	add	x18,x18,x19
	srlw	x19,x7,13
	xor	x6,x6,x20
	sllw	x20,x7,19
	xor	x6,x6,x19
	srlw	x19,x7,22
	xor	x6,x6,x20
	sllw	x20,x7,30
	xor	x6,x6,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#endif
	sw	x30,56(x2)	# offload to ring buffer
	add	x6,x6,x19
	and	x20,x20,x7
	add	x18,x18,x21			# +=K[30]
	add	x6,x6,x20			# +=Maj(a,b,c)
	add	x13,x13,x18
	add	x6,x6,x18
	lw	x17,4(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srlw	x21,x16,3		# Xupdate(31)
	rorw	x19,x16,7
	add	x31,x31,x24		# +=X[i+9]
	xor	x21,x21,x19
	rorw	x19,x16,18

	srlw	x22,x29,10
	rorw	x20,x29,17
	xor	x21,x21,x19		# sigma0(X[i+1])
	rorw	x19,x29,19
	xor	x22,x22,x20
	add	x31,x31,x21
#else
	srlw	x21,x16,3		# Xupdate(31)
	add	x31,x31,x24		# +=X[i+9]
	sllw	x20,x16,14
	srlw	x19,x16,7
	xor	x21,x21,x20
	sllw	x20,x20,11
	xor	x21,x21,x19
	srlw	x19,x16,18
	xor	x21,x21,x20

	srlw	x22,x29,10
	xor	x21,x21,x19		# sigma0(X[i+1])
	sllw	x20,x29,13
	add	x31,x31,x21
	srlw	x19,x29,17
	xor	x22,x22,x20
	sllw	x20,x20,2
	xor	x22,x22,x19
	srlw	x19,x29,19
	xor	x22,x22,x20
#endif
	xor	x22,x22,x19		# sigma1(X[i+14])
	add	x31,x31,x22
#ifdef	__riscv_zbb
	xor	x22,x14,x15			# 31
	rorw	x20,x13,6
	add	x19,x31,x5
	rorw	x21,x13,11
	and	x22,x22,x13
	rorw	x5,x13,25
	xor	x20,x20,x21
	rorw	x21,x6,2
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x20,x5			# Sigma1(e)

	rorw	x5,x6,13
	add	x19,x19,x22
	lw	x22,124(x12)		# K[31]
	xor	x5,x5,x21
	rorw	x21,x6,22
	add	x19,x19,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#else
	add	x19,x31,x5			# 31
	srlw	x5,x13,6
	xor	x22,x14,x15
	sllw	x21,x13,7
	and	x22,x22,x13
	srlw	x20,x13,11
	xor	x5,x5,x21
	sllw	x21,x13,21
	xor	x5,x5,x20
	srlw	x20,x13,25
	xor	x5,x5,x21
	sllw	x21,x13,26
	xor	x5,x5,x20
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x21,x5			# Sigma1(e)

	srlw	x5,x6,2
	add	x19,x19,x22
	lw	x22,124(x12)		# K[31]
	sllw	x21,x6,10
	add	x19,x19,x20
	srlw	x20,x6,13
	xor	x5,x5,x21
	sllw	x21,x6,19
	xor	x5,x5,x20
	srlw	x20,x6,22
	xor	x5,x5,x21
	sllw	x21,x6,30
	xor	x5,x5,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#endif
	sw	x31,60(x2)	# offload to ring buffer
	add	x5,x5,x20
	and	x21,x21,x6
	add	x19,x19,x22			# +=K[31]
	add	x5,x5,x21			# +=Maj(a,b,c)
	add	x9,x9,x19
	add	x5,x5,x19
	lw	x18,8(x2)	# prefetch from ring buffer
	andi	x22,x22,0x7ff
	li	x23,242
	add	x12,x12,16*4	# Ktbl+=16
	bne	x22,x23,.L16_xx

	POP	x31,16*4(x2)	# restore pointer to the end of input
	lw	x16,0*4(x10)
	lw	x17,1*4(x10)
	lw	x18,2*4(x10)
	add	x11,x11,16*4
	lw	x19,3*4(x10)
	add	x5,x5,x16
	lw	x20,4*4(x10)
	add	x6,x6,x17
	lw	x21,5*4(x10)
	add	x7,x7,x18
	lw	x22,6*4(x10)
	add	x8,x8,x19
	lw	x23,7*4(x10)
	add	x9,x9,x20
	sw	x5,0*4(x10)
	add	x13,x13,x21
	sw	x6,1*4(x10)
	add	x14,x14,x22
	sw	x7,2*4(x10)
	add	x15,x15,x23
	sw	x8,3*4(x10)
	sw	x9,4*4(x10)
	sw	x13,5*4(x10)
	sw	x14,6*4(x10)
	sw	x15,7*4(x10)

	add	x12,x12,-192	# rewind x12
	beq	x11,x31,.Loop_break
	j	.Loop
.Loop_break:

	POP	x8,FRAMESIZE-1*__SIZEOF_POINTER__(x2)
	POP	x9,FRAMESIZE-2*__SIZEOF_POINTER__(x2)
	POP	x18,FRAMESIZE-3*__SIZEOF_POINTER__(x2)
	POP	x19,FRAMESIZE-4*__SIZEOF_POINTER__(x2)
	POP	x20,FRAMESIZE-5*__SIZEOF_POINTER__(x2)
	POP	x21,FRAMESIZE-6*__SIZEOF_POINTER__(x2)
	POP	x22,FRAMESIZE-7*__SIZEOF_POINTER__(x2)
	POP	x23,FRAMESIZE-8*__SIZEOF_POINTER__(x2)
	POP	x24,FRAMESIZE-9*__SIZEOF_POINTER__(x2)
	POP	x25,FRAMESIZE-10*__SIZEOF_POINTER__(x2)
	POP	x26,FRAMESIZE-11*__SIZEOF_POINTER__(x2)
	POP	x27,FRAMESIZE-12*__SIZEOF_POINTER__(x2)
	add	x2,x2,FRAMESIZE
	RET
#ifdef	__riscv_zbb
SYM_FUNC_END(sha256_block_data_order_riscv_zbb)
#else
SYM_FUNC_END(sha256_block_data_order_riscv)
#endif

LC_FIPS_RODATA_SECTION
.align	5
K256:
	.word	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.word	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	.word	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.word	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.word	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.word	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.word	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.word	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.word	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.word	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.word	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	.word	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.word	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.word	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	.word	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.word	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
.string	"SHA256 for RISC-V, CRYPTOGAMS by @dot-asm"
.align	5

LC_ASM_END
