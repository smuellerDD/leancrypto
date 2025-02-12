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

#define FRAMESIZE		(16*8+16*__SIZEOF_POINTER__)

.text
.option	pic

#ifdef	__riscv_zbb
SYM_FUNC_START(sha512_block_data_order_riscv_zbb)
SYM_FUNC_ENTER(sha512_block_data_order_riscv_zbb)
#else
SYM_FUNC_START(sha512_block_data_order_riscv)
SYM_FUNC_ENTER(sha512_block_data_order_riscv)
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

	ld	x5,0*8(x10)		# load context
	ld	x6,1*8(x10)
	ld	x7,2*8(x10)
	ld	x8,3*8(x10)
	ld	x9,4*8(x10)
	ld	x13,5*8(x10)
	ld	x14,6*8(x10)
	ld	x15,7*8(x10)

	sll	x31,x12,7
	lla	x12,K512
	add	x31,x11,x31	# pointer to the end of input
	PUSH	x31,16*8(x2)

.Loop:
	lbu	x16,0(x11)
	lbu	x17,1(x11)
	lbu	x18,2(x11)
	lbu	x19,3(x11)
	sll	x16,x16,56
	lbu	x20,4(x11)
	sll	x17,x17,48
	or	x16,x16,x17
	lbu	x21,5(x11)
	sll	x18,x18,40
	or	x16,x16,x18
	lbu	x22,6(x11)
	sll	x19,x19,32
	or	x16,x16,x19
	lbu	x23,7(x11)
	sll	x20,x20,24
	or	x16,x16,x20
	sll	x21,x21,16
	or	x16,x16,x21
	sll	x22,x22,8
	or	x16,x16,x22
	or	x16,x16,x23
	lbu	x17,8(x11)
	lbu	x21,9(x11)
	lbu	x22,10(x11)
	sll	x17,x17,56
	lbu	x23,11(x11)
	sll	x21,x21,48
	or	x17,x17,x21
	lbu	x21,12(x11)
	sll	x22,x22,40
	or	x17,x17,x22
	lbu	x22,13(x11)
	sll	x23,x23,32
	or	x17,x17,x23
	lbu	x23,14(x11)
	sll	x21,x21,24
	or	x17,x17,x21
	lbu	x21,15(x11)
	sll	x22,x22,16
	or	x17,x17,x22
	sll	x23,x23,8
	or	x17,x17,x23
	or	x17,x17,x21
#ifdef	__riscv_zbb
	xor	x23,x13,x14			# 0
	ror	x21,x9,14
	add	x20,x16,x15
	ror	x22,x9,18
	and	x23,x23,x9
	ror	x15,x9,41
	xor	x21,x21,x22
	ror	x22,x5,28
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x21,x15			# Sigma1(e)

	ror	x15,x5,34
	add	x20,x20,x23
	ld	x23,0(x12)		# K[0]
	xor	x15,x15,x22
	ror	x22,x5,39
	add	x20,x20,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#else
	add	x20,x16,x15			# 0
	srl	x15,x9,14
	xor	x23,x13,x14
	sll	x22,x9,23
	and	x23,x23,x9
	srl	x21,x9,18
	xor	x15,x15,x22
	sll	x22,x9,46
	xor	x15,x15,x21
	srl	x21,x9,41
	xor	x15,x15,x22
	sll	x22,x9,50
	xor	x15,x15,x21
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x22,x15			# Sigma1(e)

	srl	x15,x5,28
	add	x20,x20,x23
	ld	x23,0(x12)		# K[0]
	sll	x22,x5,25
	add	x20,x20,x21
	srl	x21,x5,34
	xor	x15,x15,x22
	sll	x22,x5,30
	xor	x15,x15,x21
	srl	x21,x5,39
	xor	x15,x15,x22
	sll	x22,x5,36
	xor	x15,x15,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#endif
	sd	x16,0(x2)	# offload to ring buffer
	add	x15,x15,x21
	and	x22,x22,x5
	add	x20,x20,x23			# +=K[0]
	add	x15,x15,x22			# +=Maj(a,b,c)
	add	x8,x8,x20
	add	x15,x15,x20
	lbu	x18,16(x11)
	lbu	x22,17(x11)
	lbu	x23,18(x11)
	sll	x18,x18,56
	lbu	x24,19(x11)
	sll	x22,x22,48
	or	x18,x18,x22
	lbu	x22,20(x11)
	sll	x23,x23,40
	or	x18,x18,x23
	lbu	x23,21(x11)
	sll	x24,x24,32
	or	x18,x18,x24
	lbu	x24,22(x11)
	sll	x22,x22,24
	or	x18,x18,x22
	lbu	x22,23(x11)
	sll	x23,x23,16
	or	x18,x18,x23
	sll	x24,x24,8
	or	x18,x18,x24
	or	x18,x18,x22
#ifdef	__riscv_zbb
	xor	x24,x9,x13			# 1
	ror	x22,x8,14
	add	x21,x17,x14
	ror	x23,x8,18
	and	x24,x24,x8
	ror	x14,x8,41
	xor	x22,x22,x23
	ror	x23,x15,28
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x22,x14			# Sigma1(e)

	ror	x14,x15,34
	add	x21,x21,x24
	ld	x24,8(x12)		# K[1]
	xor	x14,x14,x23
	ror	x23,x15,39
	add	x21,x21,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#else
	add	x21,x17,x14			# 1
	srl	x14,x8,14
	xor	x24,x9,x13
	sll	x23,x8,23
	and	x24,x24,x8
	srl	x22,x8,18
	xor	x14,x14,x23
	sll	x23,x8,46
	xor	x14,x14,x22
	srl	x22,x8,41
	xor	x14,x14,x23
	sll	x23,x8,50
	xor	x14,x14,x22
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x23,x14			# Sigma1(e)

	srl	x14,x15,28
	add	x21,x21,x24
	ld	x24,8(x12)		# K[1]
	sll	x23,x15,25
	add	x21,x21,x22
	srl	x22,x15,34
	xor	x14,x14,x23
	sll	x23,x15,30
	xor	x14,x14,x22
	srl	x22,x15,39
	xor	x14,x14,x23
	sll	x23,x15,36
	xor	x14,x14,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#endif
	sd	x17,8(x2)	# offload to ring buffer
	add	x14,x14,x22
	and	x23,x23,x15
	add	x21,x21,x24			# +=K[1]
	add	x14,x14,x23			# +=Maj(a,b,c)
	add	x7,x7,x21
	add	x14,x14,x21
	lbu	x19,24(x11)
	lbu	x23,25(x11)
	lbu	x24,26(x11)
	sll	x19,x19,56
	lbu	x25,27(x11)
	sll	x23,x23,48
	or	x19,x19,x23
	lbu	x23,28(x11)
	sll	x24,x24,40
	or	x19,x19,x24
	lbu	x24,29(x11)
	sll	x25,x25,32
	or	x19,x19,x25
	lbu	x25,30(x11)
	sll	x23,x23,24
	or	x19,x19,x23
	lbu	x23,31(x11)
	sll	x24,x24,16
	or	x19,x19,x24
	sll	x25,x25,8
	or	x19,x19,x25
	or	x19,x19,x23
#ifdef	__riscv_zbb
	xor	x25,x8,x9			# 2
	ror	x23,x7,14
	add	x22,x18,x13
	ror	x24,x7,18
	and	x25,x25,x7
	ror	x13,x7,41
	xor	x23,x23,x24
	ror	x24,x14,28
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x23,x13			# Sigma1(e)

	ror	x13,x14,34
	add	x22,x22,x25
	ld	x25,16(x12)		# K[2]
	xor	x13,x13,x24
	ror	x24,x14,39
	add	x22,x22,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#else
	add	x22,x18,x13			# 2
	srl	x13,x7,14
	xor	x25,x8,x9
	sll	x24,x7,23
	and	x25,x25,x7
	srl	x23,x7,18
	xor	x13,x13,x24
	sll	x24,x7,46
	xor	x13,x13,x23
	srl	x23,x7,41
	xor	x13,x13,x24
	sll	x24,x7,50
	xor	x13,x13,x23
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x24,x13			# Sigma1(e)

	srl	x13,x14,28
	add	x22,x22,x25
	ld	x25,16(x12)		# K[2]
	sll	x24,x14,25
	add	x22,x22,x23
	srl	x23,x14,34
	xor	x13,x13,x24
	sll	x24,x14,30
	xor	x13,x13,x23
	srl	x23,x14,39
	xor	x13,x13,x24
	sll	x24,x14,36
	xor	x13,x13,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#endif
	sd	x18,16(x2)	# offload to ring buffer
	add	x13,x13,x23
	and	x24,x24,x14
	add	x22,x22,x25			# +=K[2]
	add	x13,x13,x24			# +=Maj(a,b,c)
	add	x6,x6,x22
	add	x13,x13,x22
	lbu	x20,32(x11)
	lbu	x24,33(x11)
	lbu	x25,34(x11)
	sll	x20,x20,56
	lbu	x26,35(x11)
	sll	x24,x24,48
	or	x20,x20,x24
	lbu	x24,36(x11)
	sll	x25,x25,40
	or	x20,x20,x25
	lbu	x25,37(x11)
	sll	x26,x26,32
	or	x20,x20,x26
	lbu	x26,38(x11)
	sll	x24,x24,24
	or	x20,x20,x24
	lbu	x24,39(x11)
	sll	x25,x25,16
	or	x20,x20,x25
	sll	x26,x26,8
	or	x20,x20,x26
	or	x20,x20,x24
#ifdef	__riscv_zbb
	xor	x26,x7,x8			# 3
	ror	x24,x6,14
	add	x23,x19,x9
	ror	x25,x6,18
	and	x26,x26,x6
	ror	x9,x6,41
	xor	x24,x24,x25
	ror	x25,x13,28
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x24,x9			# Sigma1(e)

	ror	x9,x13,34
	add	x23,x23,x26
	ld	x26,24(x12)		# K[3]
	xor	x9,x9,x25
	ror	x25,x13,39
	add	x23,x23,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#else
	add	x23,x19,x9			# 3
	srl	x9,x6,14
	xor	x26,x7,x8
	sll	x25,x6,23
	and	x26,x26,x6
	srl	x24,x6,18
	xor	x9,x9,x25
	sll	x25,x6,46
	xor	x9,x9,x24
	srl	x24,x6,41
	xor	x9,x9,x25
	sll	x25,x6,50
	xor	x9,x9,x24
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x25,x9			# Sigma1(e)

	srl	x9,x13,28
	add	x23,x23,x26
	ld	x26,24(x12)		# K[3]
	sll	x25,x13,25
	add	x23,x23,x24
	srl	x24,x13,34
	xor	x9,x9,x25
	sll	x25,x13,30
	xor	x9,x9,x24
	srl	x24,x13,39
	xor	x9,x9,x25
	sll	x25,x13,36
	xor	x9,x9,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#endif
	sd	x19,24(x2)	# offload to ring buffer
	add	x9,x9,x24
	and	x25,x25,x13
	add	x23,x23,x26			# +=K[3]
	add	x9,x9,x25			# +=Maj(a,b,c)
	add	x5,x5,x23
	add	x9,x9,x23
	lbu	x21,40(x11)
	lbu	x25,41(x11)
	lbu	x26,42(x11)
	sll	x21,x21,56
	lbu	x27,43(x11)
	sll	x25,x25,48
	or	x21,x21,x25
	lbu	x25,44(x11)
	sll	x26,x26,40
	or	x21,x21,x26
	lbu	x26,45(x11)
	sll	x27,x27,32
	or	x21,x21,x27
	lbu	x27,46(x11)
	sll	x25,x25,24
	or	x21,x21,x25
	lbu	x25,47(x11)
	sll	x26,x26,16
	or	x21,x21,x26
	sll	x27,x27,8
	or	x21,x21,x27
	or	x21,x21,x25
#ifdef	__riscv_zbb
	xor	x27,x6,x7			# 4
	ror	x25,x5,14
	add	x24,x20,x8
	ror	x26,x5,18
	and	x27,x27,x5
	ror	x8,x5,41
	xor	x25,x25,x26
	ror	x26,x9,28
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x25,x8			# Sigma1(e)

	ror	x8,x9,34
	add	x24,x24,x27
	ld	x27,32(x12)		# K[4]
	xor	x8,x8,x26
	ror	x26,x9,39
	add	x24,x24,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#else
	add	x24,x20,x8			# 4
	srl	x8,x5,14
	xor	x27,x6,x7
	sll	x26,x5,23
	and	x27,x27,x5
	srl	x25,x5,18
	xor	x8,x8,x26
	sll	x26,x5,46
	xor	x8,x8,x25
	srl	x25,x5,41
	xor	x8,x8,x26
	sll	x26,x5,50
	xor	x8,x8,x25
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x26,x8			# Sigma1(e)

	srl	x8,x9,28
	add	x24,x24,x27
	ld	x27,32(x12)		# K[4]
	sll	x26,x9,25
	add	x24,x24,x25
	srl	x25,x9,34
	xor	x8,x8,x26
	sll	x26,x9,30
	xor	x8,x8,x25
	srl	x25,x9,39
	xor	x8,x8,x26
	sll	x26,x9,36
	xor	x8,x8,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#endif
	sd	x20,32(x2)	# offload to ring buffer
	add	x8,x8,x25
	and	x26,x26,x9
	add	x24,x24,x27			# +=K[4]
	add	x8,x8,x26			# +=Maj(a,b,c)
	add	x15,x15,x24
	add	x8,x8,x24
	lbu	x22,48(x11)
	lbu	x26,49(x11)
	lbu	x27,50(x11)
	sll	x22,x22,56
	lbu	x28,51(x11)
	sll	x26,x26,48
	or	x22,x22,x26
	lbu	x26,52(x11)
	sll	x27,x27,40
	or	x22,x22,x27
	lbu	x27,53(x11)
	sll	x28,x28,32
	or	x22,x22,x28
	lbu	x28,54(x11)
	sll	x26,x26,24
	or	x22,x22,x26
	lbu	x26,55(x11)
	sll	x27,x27,16
	or	x22,x22,x27
	sll	x28,x28,8
	or	x22,x22,x28
	or	x22,x22,x26
#ifdef	__riscv_zbb
	xor	x28,x5,x6			# 5
	ror	x26,x15,14
	add	x25,x21,x7
	ror	x27,x15,18
	and	x28,x28,x15
	ror	x7,x15,41
	xor	x26,x26,x27
	ror	x27,x8,28
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x26,x7			# Sigma1(e)

	ror	x7,x8,34
	add	x25,x25,x28
	ld	x28,40(x12)		# K[5]
	xor	x7,x7,x27
	ror	x27,x8,39
	add	x25,x25,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#else
	add	x25,x21,x7			# 5
	srl	x7,x15,14
	xor	x28,x5,x6
	sll	x27,x15,23
	and	x28,x28,x15
	srl	x26,x15,18
	xor	x7,x7,x27
	sll	x27,x15,46
	xor	x7,x7,x26
	srl	x26,x15,41
	xor	x7,x7,x27
	sll	x27,x15,50
	xor	x7,x7,x26
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x27,x7			# Sigma1(e)

	srl	x7,x8,28
	add	x25,x25,x28
	ld	x28,40(x12)		# K[5]
	sll	x27,x8,25
	add	x25,x25,x26
	srl	x26,x8,34
	xor	x7,x7,x27
	sll	x27,x8,30
	xor	x7,x7,x26
	srl	x26,x8,39
	xor	x7,x7,x27
	sll	x27,x8,36
	xor	x7,x7,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#endif
	sd	x21,40(x2)	# offload to ring buffer
	add	x7,x7,x26
	and	x27,x27,x8
	add	x25,x25,x28			# +=K[5]
	add	x7,x7,x27			# +=Maj(a,b,c)
	add	x14,x14,x25
	add	x7,x7,x25
	lbu	x23,56(x11)
	lbu	x27,57(x11)
	lbu	x28,58(x11)
	sll	x23,x23,56
	lbu	x29,59(x11)
	sll	x27,x27,48
	or	x23,x23,x27
	lbu	x27,60(x11)
	sll	x28,x28,40
	or	x23,x23,x28
	lbu	x28,61(x11)
	sll	x29,x29,32
	or	x23,x23,x29
	lbu	x29,62(x11)
	sll	x27,x27,24
	or	x23,x23,x27
	lbu	x27,63(x11)
	sll	x28,x28,16
	or	x23,x23,x28
	sll	x29,x29,8
	or	x23,x23,x29
	or	x23,x23,x27
#ifdef	__riscv_zbb
	xor	x29,x15,x5			# 6
	ror	x27,x14,14
	add	x26,x22,x6
	ror	x28,x14,18
	and	x29,x29,x14
	ror	x6,x14,41
	xor	x27,x27,x28
	ror	x28,x7,28
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x27,x6			# Sigma1(e)

	ror	x6,x7,34
	add	x26,x26,x29
	ld	x29,48(x12)		# K[6]
	xor	x6,x6,x28
	ror	x28,x7,39
	add	x26,x26,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#else
	add	x26,x22,x6			# 6
	srl	x6,x14,14
	xor	x29,x15,x5
	sll	x28,x14,23
	and	x29,x29,x14
	srl	x27,x14,18
	xor	x6,x6,x28
	sll	x28,x14,46
	xor	x6,x6,x27
	srl	x27,x14,41
	xor	x6,x6,x28
	sll	x28,x14,50
	xor	x6,x6,x27
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x28,x6			# Sigma1(e)

	srl	x6,x7,28
	add	x26,x26,x29
	ld	x29,48(x12)		# K[6]
	sll	x28,x7,25
	add	x26,x26,x27
	srl	x27,x7,34
	xor	x6,x6,x28
	sll	x28,x7,30
	xor	x6,x6,x27
	srl	x27,x7,39
	xor	x6,x6,x28
	sll	x28,x7,36
	xor	x6,x6,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#endif
	sd	x22,48(x2)	# offload to ring buffer
	add	x6,x6,x27
	and	x28,x28,x7
	add	x26,x26,x29			# +=K[6]
	add	x6,x6,x28			# +=Maj(a,b,c)
	add	x13,x13,x26
	add	x6,x6,x26
	lbu	x24,64(x11)
	lbu	x28,65(x11)
	lbu	x29,66(x11)
	sll	x24,x24,56
	lbu	x30,67(x11)
	sll	x28,x28,48
	or	x24,x24,x28
	lbu	x28,68(x11)
	sll	x29,x29,40
	or	x24,x24,x29
	lbu	x29,69(x11)
	sll	x30,x30,32
	or	x24,x24,x30
	lbu	x30,70(x11)
	sll	x28,x28,24
	or	x24,x24,x28
	lbu	x28,71(x11)
	sll	x29,x29,16
	or	x24,x24,x29
	sll	x30,x30,8
	or	x24,x24,x30
	or	x24,x24,x28
#ifdef	__riscv_zbb
	xor	x30,x14,x15			# 7
	ror	x28,x13,14
	add	x27,x23,x5
	ror	x29,x13,18
	and	x30,x30,x13
	ror	x5,x13,41
	xor	x28,x28,x29
	ror	x29,x6,28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x28,x5			# Sigma1(e)

	ror	x5,x6,34
	add	x27,x27,x30
	ld	x30,56(x12)		# K[7]
	xor	x5,x5,x29
	ror	x29,x6,39
	add	x27,x27,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#else
	add	x27,x23,x5			# 7
	srl	x5,x13,14
	xor	x30,x14,x15
	sll	x29,x13,23
	and	x30,x30,x13
	srl	x28,x13,18
	xor	x5,x5,x29
	sll	x29,x13,46
	xor	x5,x5,x28
	srl	x28,x13,41
	xor	x5,x5,x29
	sll	x29,x13,50
	xor	x5,x5,x28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x29,x5			# Sigma1(e)

	srl	x5,x6,28
	add	x27,x27,x30
	ld	x30,56(x12)		# K[7]
	sll	x29,x6,25
	add	x27,x27,x28
	srl	x28,x6,34
	xor	x5,x5,x29
	sll	x29,x6,30
	xor	x5,x5,x28
	srl	x28,x6,39
	xor	x5,x5,x29
	sll	x29,x6,36
	xor	x5,x5,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#endif
	sd	x23,56(x2)	# offload to ring buffer
	add	x5,x5,x28
	and	x29,x29,x6
	add	x27,x27,x30			# +=K[7]
	add	x5,x5,x29			# +=Maj(a,b,c)
	add	x9,x9,x27
	add	x5,x5,x27
	lbu	x25,72(x11)
	lbu	x29,73(x11)
	lbu	x30,74(x11)
	sll	x25,x25,56
	lbu	x31,75(x11)
	sll	x29,x29,48
	or	x25,x25,x29
	lbu	x29,76(x11)
	sll	x30,x30,40
	or	x25,x25,x30
	lbu	x30,77(x11)
	sll	x31,x31,32
	or	x25,x25,x31
	lbu	x31,78(x11)
	sll	x29,x29,24
	or	x25,x25,x29
	lbu	x29,79(x11)
	sll	x30,x30,16
	or	x25,x25,x30
	sll	x31,x31,8
	or	x25,x25,x31
	or	x25,x25,x29
#ifdef	__riscv_zbb
	xor	x31,x13,x14			# 8
	ror	x29,x9,14
	add	x28,x24,x15
	ror	x30,x9,18
	and	x31,x31,x9
	ror	x15,x9,41
	xor	x29,x29,x30
	ror	x30,x5,28
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x29,x15			# Sigma1(e)

	ror	x15,x5,34
	add	x28,x28,x31
	ld	x31,64(x12)		# K[8]
	xor	x15,x15,x30
	ror	x30,x5,39
	add	x28,x28,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#else
	add	x28,x24,x15			# 8
	srl	x15,x9,14
	xor	x31,x13,x14
	sll	x30,x9,23
	and	x31,x31,x9
	srl	x29,x9,18
	xor	x15,x15,x30
	sll	x30,x9,46
	xor	x15,x15,x29
	srl	x29,x9,41
	xor	x15,x15,x30
	sll	x30,x9,50
	xor	x15,x15,x29
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x30,x15			# Sigma1(e)

	srl	x15,x5,28
	add	x28,x28,x31
	ld	x31,64(x12)		# K[8]
	sll	x30,x5,25
	add	x28,x28,x29
	srl	x29,x5,34
	xor	x15,x15,x30
	sll	x30,x5,30
	xor	x15,x15,x29
	srl	x29,x5,39
	xor	x15,x15,x30
	sll	x30,x5,36
	xor	x15,x15,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#endif
	sd	x24,64(x2)	# offload to ring buffer
	add	x15,x15,x29
	and	x30,x30,x5
	add	x28,x28,x31			# +=K[8]
	add	x15,x15,x30			# +=Maj(a,b,c)
	add	x8,x8,x28
	add	x15,x15,x28
	lbu	x26,80(x11)
	lbu	x30,81(x11)
	lbu	x31,82(x11)
	sll	x26,x26,56
	lbu	x16,83(x11)
	sll	x30,x30,48
	or	x26,x26,x30
	lbu	x30,84(x11)
	sll	x31,x31,40
	or	x26,x26,x31
	lbu	x31,85(x11)
	sll	x16,x16,32
	or	x26,x26,x16
	lbu	x16,86(x11)
	sll	x30,x30,24
	or	x26,x26,x30
	lbu	x30,87(x11)
	sll	x31,x31,16
	or	x26,x26,x31
	sll	x16,x16,8
	or	x26,x26,x16
	or	x26,x26,x30
#ifdef	__riscv_zbb
	xor	x16,x9,x13			# 9
	ror	x30,x8,14
	add	x29,x25,x14
	ror	x31,x8,18
	and	x16,x16,x8
	ror	x14,x8,41
	xor	x30,x30,x31
	ror	x31,x15,28
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x30,x14			# Sigma1(e)

	ror	x14,x15,34
	add	x29,x29,x16
	ld	x16,72(x12)		# K[9]
	xor	x14,x14,x31
	ror	x31,x15,39
	add	x29,x29,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#else
	add	x29,x25,x14			# 9
	srl	x14,x8,14
	xor	x16,x9,x13
	sll	x31,x8,23
	and	x16,x16,x8
	srl	x30,x8,18
	xor	x14,x14,x31
	sll	x31,x8,46
	xor	x14,x14,x30
	srl	x30,x8,41
	xor	x14,x14,x31
	sll	x31,x8,50
	xor	x14,x14,x30
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x31,x14			# Sigma1(e)

	srl	x14,x15,28
	add	x29,x29,x16
	ld	x16,72(x12)		# K[9]
	sll	x31,x15,25
	add	x29,x29,x30
	srl	x30,x15,34
	xor	x14,x14,x31
	sll	x31,x15,30
	xor	x14,x14,x30
	srl	x30,x15,39
	xor	x14,x14,x31
	sll	x31,x15,36
	xor	x14,x14,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#endif
	sd	x25,72(x2)	# offload to ring buffer
	add	x14,x14,x30
	and	x31,x31,x15
	add	x29,x29,x16			# +=K[9]
	add	x14,x14,x31			# +=Maj(a,b,c)
	add	x7,x7,x29
	add	x14,x14,x29
	lbu	x27,88(x11)
	lbu	x31,89(x11)
	lbu	x16,90(x11)
	sll	x27,x27,56
	lbu	x17,91(x11)
	sll	x31,x31,48
	or	x27,x27,x31
	lbu	x31,92(x11)
	sll	x16,x16,40
	or	x27,x27,x16
	lbu	x16,93(x11)
	sll	x17,x17,32
	or	x27,x27,x17
	lbu	x17,94(x11)
	sll	x31,x31,24
	or	x27,x27,x31
	lbu	x31,95(x11)
	sll	x16,x16,16
	or	x27,x27,x16
	sll	x17,x17,8
	or	x27,x27,x17
	or	x27,x27,x31
#ifdef	__riscv_zbb
	xor	x17,x8,x9			# 10
	ror	x31,x7,14
	add	x30,x26,x13
	ror	x16,x7,18
	and	x17,x17,x7
	ror	x13,x7,41
	xor	x31,x31,x16
	ror	x16,x14,28
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x31,x13			# Sigma1(e)

	ror	x13,x14,34
	add	x30,x30,x17
	ld	x17,80(x12)		# K[10]
	xor	x13,x13,x16
	ror	x16,x14,39
	add	x30,x30,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#else
	add	x30,x26,x13			# 10
	srl	x13,x7,14
	xor	x17,x8,x9
	sll	x16,x7,23
	and	x17,x17,x7
	srl	x31,x7,18
	xor	x13,x13,x16
	sll	x16,x7,46
	xor	x13,x13,x31
	srl	x31,x7,41
	xor	x13,x13,x16
	sll	x16,x7,50
	xor	x13,x13,x31
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x16,x13			# Sigma1(e)

	srl	x13,x14,28
	add	x30,x30,x17
	ld	x17,80(x12)		# K[10]
	sll	x16,x14,25
	add	x30,x30,x31
	srl	x31,x14,34
	xor	x13,x13,x16
	sll	x16,x14,30
	xor	x13,x13,x31
	srl	x31,x14,39
	xor	x13,x13,x16
	sll	x16,x14,36
	xor	x13,x13,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#endif
	sd	x26,80(x2)	# offload to ring buffer
	add	x13,x13,x31
	and	x16,x16,x14
	add	x30,x30,x17			# +=K[10]
	add	x13,x13,x16			# +=Maj(a,b,c)
	add	x6,x6,x30
	add	x13,x13,x30
	lbu	x28,96(x11)
	lbu	x16,97(x11)
	lbu	x17,98(x11)
	sll	x28,x28,56
	lbu	x18,99(x11)
	sll	x16,x16,48
	or	x28,x28,x16
	lbu	x16,100(x11)
	sll	x17,x17,40
	or	x28,x28,x17
	lbu	x17,101(x11)
	sll	x18,x18,32
	or	x28,x28,x18
	lbu	x18,102(x11)
	sll	x16,x16,24
	or	x28,x28,x16
	lbu	x16,103(x11)
	sll	x17,x17,16
	or	x28,x28,x17
	sll	x18,x18,8
	or	x28,x28,x18
	or	x28,x28,x16
#ifdef	__riscv_zbb
	xor	x18,x7,x8			# 11
	ror	x16,x6,14
	add	x31,x27,x9
	ror	x17,x6,18
	and	x18,x18,x6
	ror	x9,x6,41
	xor	x16,x16,x17
	ror	x17,x13,28
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x16,x9			# Sigma1(e)

	ror	x9,x13,34
	add	x31,x31,x18
	ld	x18,88(x12)		# K[11]
	xor	x9,x9,x17
	ror	x17,x13,39
	add	x31,x31,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#else
	add	x31,x27,x9			# 11
	srl	x9,x6,14
	xor	x18,x7,x8
	sll	x17,x6,23
	and	x18,x18,x6
	srl	x16,x6,18
	xor	x9,x9,x17
	sll	x17,x6,46
	xor	x9,x9,x16
	srl	x16,x6,41
	xor	x9,x9,x17
	sll	x17,x6,50
	xor	x9,x9,x16
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x17,x9			# Sigma1(e)

	srl	x9,x13,28
	add	x31,x31,x18
	ld	x18,88(x12)		# K[11]
	sll	x17,x13,25
	add	x31,x31,x16
	srl	x16,x13,34
	xor	x9,x9,x17
	sll	x17,x13,30
	xor	x9,x9,x16
	srl	x16,x13,39
	xor	x9,x9,x17
	sll	x17,x13,36
	xor	x9,x9,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#endif
	sd	x27,88(x2)	# offload to ring buffer
	add	x9,x9,x16
	and	x17,x17,x13
	add	x31,x31,x18			# +=K[11]
	add	x9,x9,x17			# +=Maj(a,b,c)
	add	x5,x5,x31
	add	x9,x9,x31
	lbu	x29,104(x11)
	lbu	x17,105(x11)
	lbu	x18,106(x11)
	sll	x29,x29,56
	lbu	x19,107(x11)
	sll	x17,x17,48
	or	x29,x29,x17
	lbu	x17,108(x11)
	sll	x18,x18,40
	or	x29,x29,x18
	lbu	x18,109(x11)
	sll	x19,x19,32
	or	x29,x29,x19
	lbu	x19,110(x11)
	sll	x17,x17,24
	or	x29,x29,x17
	lbu	x17,111(x11)
	sll	x18,x18,16
	or	x29,x29,x18
	sll	x19,x19,8
	or	x29,x29,x19
	or	x29,x29,x17
#ifdef	__riscv_zbb
	xor	x19,x6,x7			# 12
	ror	x17,x5,14
	add	x16,x28,x8
	ror	x18,x5,18
	and	x19,x19,x5
	ror	x8,x5,41
	xor	x17,x17,x18
	ror	x18,x9,28
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x17,x8			# Sigma1(e)

	ror	x8,x9,34
	add	x16,x16,x19
	ld	x19,96(x12)		# K[12]
	xor	x8,x8,x18
	ror	x18,x9,39
	add	x16,x16,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#else
	add	x16,x28,x8			# 12
	srl	x8,x5,14
	xor	x19,x6,x7
	sll	x18,x5,23
	and	x19,x19,x5
	srl	x17,x5,18
	xor	x8,x8,x18
	sll	x18,x5,46
	xor	x8,x8,x17
	srl	x17,x5,41
	xor	x8,x8,x18
	sll	x18,x5,50
	xor	x8,x8,x17
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x18,x8			# Sigma1(e)

	srl	x8,x9,28
	add	x16,x16,x19
	ld	x19,96(x12)		# K[12]
	sll	x18,x9,25
	add	x16,x16,x17
	srl	x17,x9,34
	xor	x8,x8,x18
	sll	x18,x9,30
	xor	x8,x8,x17
	srl	x17,x9,39
	xor	x8,x8,x18
	sll	x18,x9,36
	xor	x8,x8,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#endif
	sd	x28,96(x2)	# offload to ring buffer
	add	x8,x8,x17
	and	x18,x18,x9
	add	x16,x16,x19			# +=K[12]
	add	x8,x8,x18			# +=Maj(a,b,c)
	add	x15,x15,x16
	add	x8,x8,x16
	lbu	x30,112(x11)
	lbu	x18,113(x11)
	lbu	x19,114(x11)
	sll	x30,x30,56
	lbu	x20,115(x11)
	sll	x18,x18,48
	or	x30,x30,x18
	lbu	x18,116(x11)
	sll	x19,x19,40
	or	x30,x30,x19
	lbu	x19,117(x11)
	sll	x20,x20,32
	or	x30,x30,x20
	lbu	x20,118(x11)
	sll	x18,x18,24
	or	x30,x30,x18
	lbu	x18,119(x11)
	sll	x19,x19,16
	or	x30,x30,x19
	sll	x20,x20,8
	or	x30,x30,x20
	or	x30,x30,x18
#ifdef	__riscv_zbb
	xor	x20,x5,x6			# 13
	ror	x18,x15,14
	add	x17,x29,x7
	ror	x19,x15,18
	and	x20,x20,x15
	ror	x7,x15,41
	xor	x18,x18,x19
	ror	x19,x8,28
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x18,x7			# Sigma1(e)

	ror	x7,x8,34
	add	x17,x17,x20
	ld	x20,104(x12)		# K[13]
	xor	x7,x7,x19
	ror	x19,x8,39
	add	x17,x17,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#else
	add	x17,x29,x7			# 13
	srl	x7,x15,14
	xor	x20,x5,x6
	sll	x19,x15,23
	and	x20,x20,x15
	srl	x18,x15,18
	xor	x7,x7,x19
	sll	x19,x15,46
	xor	x7,x7,x18
	srl	x18,x15,41
	xor	x7,x7,x19
	sll	x19,x15,50
	xor	x7,x7,x18
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x19,x7			# Sigma1(e)

	srl	x7,x8,28
	add	x17,x17,x20
	ld	x20,104(x12)		# K[13]
	sll	x19,x8,25
	add	x17,x17,x18
	srl	x18,x8,34
	xor	x7,x7,x19
	sll	x19,x8,30
	xor	x7,x7,x18
	srl	x18,x8,39
	xor	x7,x7,x19
	sll	x19,x8,36
	xor	x7,x7,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#endif
	sd	x29,104(x2)	# offload to ring buffer
	add	x7,x7,x18
	and	x19,x19,x8
	add	x17,x17,x20			# +=K[13]
	add	x7,x7,x19			# +=Maj(a,b,c)
	add	x14,x14,x17
	add	x7,x7,x17
	ld	x16,0(x2)	# prefetch from ring buffer
	lbu	x31,120(x11)
	lbu	x19,121(x11)
	lbu	x20,122(x11)
	sll	x31,x31,56
	lbu	x21,123(x11)
	sll	x19,x19,48
	or	x31,x31,x19
	lbu	x19,124(x11)
	sll	x20,x20,40
	or	x31,x31,x20
	lbu	x20,125(x11)
	sll	x21,x21,32
	or	x31,x31,x21
	lbu	x21,126(x11)
	sll	x19,x19,24
	or	x31,x31,x19
	lbu	x19,127(x11)
	sll	x20,x20,16
	or	x31,x31,x20
	sll	x21,x21,8
	or	x31,x31,x21
	or	x31,x31,x19
#ifdef	__riscv_zbb
	xor	x21,x15,x5			# 14
	ror	x19,x14,14
	add	x18,x30,x6
	ror	x20,x14,18
	and	x21,x21,x14
	ror	x6,x14,41
	xor	x19,x19,x20
	ror	x20,x7,28
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x19,x6			# Sigma1(e)

	ror	x6,x7,34
	add	x18,x18,x21
	ld	x21,112(x12)		# K[14]
	xor	x6,x6,x20
	ror	x20,x7,39
	add	x18,x18,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#else
	add	x18,x30,x6			# 14
	srl	x6,x14,14
	xor	x21,x15,x5
	sll	x20,x14,23
	and	x21,x21,x14
	srl	x19,x14,18
	xor	x6,x6,x20
	sll	x20,x14,46
	xor	x6,x6,x19
	srl	x19,x14,41
	xor	x6,x6,x20
	sll	x20,x14,50
	xor	x6,x6,x19
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x20,x6			# Sigma1(e)

	srl	x6,x7,28
	add	x18,x18,x21
	ld	x21,112(x12)		# K[14]
	sll	x20,x7,25
	add	x18,x18,x19
	srl	x19,x7,34
	xor	x6,x6,x20
	sll	x20,x7,30
	xor	x6,x6,x19
	srl	x19,x7,39
	xor	x6,x6,x20
	sll	x20,x7,36
	xor	x6,x6,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#endif
	sd	x30,112(x2)	# offload to ring buffer
	add	x6,x6,x19
	and	x20,x20,x7
	add	x18,x18,x21			# +=K[14]
	add	x6,x6,x20			# +=Maj(a,b,c)
	add	x13,x13,x18
	add	x6,x6,x18
	ld	x17,8(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	xor	x22,x14,x15			# 15
	ror	x20,x13,14
	add	x19,x31,x5
	ror	x21,x13,18
	and	x22,x22,x13
	ror	x5,x13,41
	xor	x20,x20,x21
	ror	x21,x6,28
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x20,x5			# Sigma1(e)

	ror	x5,x6,34
	add	x19,x19,x22
	ld	x22,120(x12)		# K[15]
	xor	x5,x5,x21
	ror	x21,x6,39
	add	x19,x19,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#else
	add	x19,x31,x5			# 15
	srl	x5,x13,14
	xor	x22,x14,x15
	sll	x21,x13,23
	and	x22,x22,x13
	srl	x20,x13,18
	xor	x5,x5,x21
	sll	x21,x13,46
	xor	x5,x5,x20
	srl	x20,x13,41
	xor	x5,x5,x21
	sll	x21,x13,50
	xor	x5,x5,x20
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x21,x5			# Sigma1(e)

	srl	x5,x6,28
	add	x19,x19,x22
	ld	x22,120(x12)		# K[15]
	sll	x21,x6,25
	add	x19,x19,x20
	srl	x20,x6,34
	xor	x5,x5,x21
	sll	x21,x6,30
	xor	x5,x5,x20
	srl	x20,x6,39
	xor	x5,x5,x21
	sll	x21,x6,36
	xor	x5,x5,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#endif
	sd	x31,120(x2)	# offload to ring buffer
	add	x5,x5,x20
	and	x21,x21,x6
	add	x19,x19,x22			# +=K[15]
	add	x5,x5,x21			# +=Maj(a,b,c)
	add	x9,x9,x19
	add	x5,x5,x19
	ld	x18,16(x2)	# prefetch from ring buffer
.L16_xx:
#ifdef	__riscv_zbb
	srl	x22,x17,7		# Xupdate(16)
	ror	x20,x17,1
	add	x16,x16,x25		# +=X[i+9]
	xor	x22,x22,x20
	ror	x20,x17,8

	srl	x23,x30,6
	ror	x21,x30,19
	xor	x22,x22,x20		# sigma0(X[i+1])
	ror	x20,x30,61
	xor	x23,x23,x21
	add	x16,x16,x22
#else
	srl	x22,x17,7		# Xupdate(16)
	add	x16,x16,x25		# +=X[i+9]
	sll	x21,x17,56
	srl	x20,x17,1
	xor	x22,x22,x21
	sll	x21,x21,7
	xor	x22,x22,x20
	srl	x20,x17,8
	xor	x22,x22,x21

	srl	x23,x30,6
	xor	x22,x22,x20		# sigma0(X[i+1])
	sll	x21,x30,3
	add	x16,x16,x22
	srl	x20,x30,19
	xor	x23,x23,x21
	sll	x21,x21,42
	xor	x23,x23,x20
	srl	x20,x30,61
	xor	x23,x23,x21
#endif
	xor	x23,x23,x20		# sigma1(X[i+14])
	add	x16,x16,x23
#ifdef	__riscv_zbb
	xor	x23,x13,x14			# 16
	ror	x21,x9,14
	add	x20,x16,x15
	ror	x22,x9,18
	and	x23,x23,x9
	ror	x15,x9,41
	xor	x21,x21,x22
	ror	x22,x5,28
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x21,x15			# Sigma1(e)

	ror	x15,x5,34
	add	x20,x20,x23
	ld	x23,128(x12)		# K[16]
	xor	x15,x15,x22
	ror	x22,x5,39
	add	x20,x20,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#else
	add	x20,x16,x15			# 16
	srl	x15,x9,14
	xor	x23,x13,x14
	sll	x22,x9,23
	and	x23,x23,x9
	srl	x21,x9,18
	xor	x15,x15,x22
	sll	x22,x9,46
	xor	x15,x15,x21
	srl	x21,x9,41
	xor	x15,x15,x22
	sll	x22,x9,50
	xor	x15,x15,x21
	xor	x23,x23,x14			# Ch(e,f,g)
	xor	x21,x22,x15			# Sigma1(e)

	srl	x15,x5,28
	add	x20,x20,x23
	ld	x23,128(x12)		# K[16]
	sll	x22,x5,25
	add	x20,x20,x21
	srl	x21,x5,34
	xor	x15,x15,x22
	sll	x22,x5,30
	xor	x15,x15,x21
	srl	x21,x5,39
	xor	x15,x15,x22
	sll	x22,x5,36
	xor	x15,x15,x21
	and	x21,x6,x7
	xor	x15,x15,x22			# Sigma0(a)
	xor	x22,x6,x7
#endif
	sd	x16,0(x2)	# offload to ring buffer
	add	x15,x15,x21
	and	x22,x22,x5
	add	x20,x20,x23			# +=K[16]
	add	x15,x15,x22			# +=Maj(a,b,c)
	add	x8,x8,x20
	add	x15,x15,x20
	ld	x19,24(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x23,x18,7		# Xupdate(17)
	ror	x21,x18,1
	add	x17,x17,x26		# +=X[i+9]
	xor	x23,x23,x21
	ror	x21,x18,8

	srl	x24,x31,6
	ror	x22,x31,19
	xor	x23,x23,x21		# sigma0(X[i+1])
	ror	x21,x31,61
	xor	x24,x24,x22
	add	x17,x17,x23
#else
	srl	x23,x18,7		# Xupdate(17)
	add	x17,x17,x26		# +=X[i+9]
	sll	x22,x18,56
	srl	x21,x18,1
	xor	x23,x23,x22
	sll	x22,x22,7
	xor	x23,x23,x21
	srl	x21,x18,8
	xor	x23,x23,x22

	srl	x24,x31,6
	xor	x23,x23,x21		# sigma0(X[i+1])
	sll	x22,x31,3
	add	x17,x17,x23
	srl	x21,x31,19
	xor	x24,x24,x22
	sll	x22,x22,42
	xor	x24,x24,x21
	srl	x21,x31,61
	xor	x24,x24,x22
#endif
	xor	x24,x24,x21		# sigma1(X[i+14])
	add	x17,x17,x24
#ifdef	__riscv_zbb
	xor	x24,x9,x13			# 17
	ror	x22,x8,14
	add	x21,x17,x14
	ror	x23,x8,18
	and	x24,x24,x8
	ror	x14,x8,41
	xor	x22,x22,x23
	ror	x23,x15,28
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x22,x14			# Sigma1(e)

	ror	x14,x15,34
	add	x21,x21,x24
	ld	x24,136(x12)		# K[17]
	xor	x14,x14,x23
	ror	x23,x15,39
	add	x21,x21,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#else
	add	x21,x17,x14			# 17
	srl	x14,x8,14
	xor	x24,x9,x13
	sll	x23,x8,23
	and	x24,x24,x8
	srl	x22,x8,18
	xor	x14,x14,x23
	sll	x23,x8,46
	xor	x14,x14,x22
	srl	x22,x8,41
	xor	x14,x14,x23
	sll	x23,x8,50
	xor	x14,x14,x22
	xor	x24,x24,x13			# Ch(e,f,g)
	xor	x22,x23,x14			# Sigma1(e)

	srl	x14,x15,28
	add	x21,x21,x24
	ld	x24,136(x12)		# K[17]
	sll	x23,x15,25
	add	x21,x21,x22
	srl	x22,x15,34
	xor	x14,x14,x23
	sll	x23,x15,30
	xor	x14,x14,x22
	srl	x22,x15,39
	xor	x14,x14,x23
	sll	x23,x15,36
	xor	x14,x14,x22
	and	x22,x5,x6
	xor	x14,x14,x23			# Sigma0(a)
	xor	x23,x5,x6
#endif
	sd	x17,8(x2)	# offload to ring buffer
	add	x14,x14,x22
	and	x23,x23,x15
	add	x21,x21,x24			# +=K[17]
	add	x14,x14,x23			# +=Maj(a,b,c)
	add	x7,x7,x21
	add	x14,x14,x21
	ld	x20,32(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x24,x19,7		# Xupdate(18)
	ror	x22,x19,1
	add	x18,x18,x27		# +=X[i+9]
	xor	x24,x24,x22
	ror	x22,x19,8

	srl	x25,x16,6
	ror	x23,x16,19
	xor	x24,x24,x22		# sigma0(X[i+1])
	ror	x22,x16,61
	xor	x25,x25,x23
	add	x18,x18,x24
#else
	srl	x24,x19,7		# Xupdate(18)
	add	x18,x18,x27		# +=X[i+9]
	sll	x23,x19,56
	srl	x22,x19,1
	xor	x24,x24,x23
	sll	x23,x23,7
	xor	x24,x24,x22
	srl	x22,x19,8
	xor	x24,x24,x23

	srl	x25,x16,6
	xor	x24,x24,x22		# sigma0(X[i+1])
	sll	x23,x16,3
	add	x18,x18,x24
	srl	x22,x16,19
	xor	x25,x25,x23
	sll	x23,x23,42
	xor	x25,x25,x22
	srl	x22,x16,61
	xor	x25,x25,x23
#endif
	xor	x25,x25,x22		# sigma1(X[i+14])
	add	x18,x18,x25
#ifdef	__riscv_zbb
	xor	x25,x8,x9			# 18
	ror	x23,x7,14
	add	x22,x18,x13
	ror	x24,x7,18
	and	x25,x25,x7
	ror	x13,x7,41
	xor	x23,x23,x24
	ror	x24,x14,28
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x23,x13			# Sigma1(e)

	ror	x13,x14,34
	add	x22,x22,x25
	ld	x25,144(x12)		# K[18]
	xor	x13,x13,x24
	ror	x24,x14,39
	add	x22,x22,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#else
	add	x22,x18,x13			# 18
	srl	x13,x7,14
	xor	x25,x8,x9
	sll	x24,x7,23
	and	x25,x25,x7
	srl	x23,x7,18
	xor	x13,x13,x24
	sll	x24,x7,46
	xor	x13,x13,x23
	srl	x23,x7,41
	xor	x13,x13,x24
	sll	x24,x7,50
	xor	x13,x13,x23
	xor	x25,x25,x9			# Ch(e,f,g)
	xor	x23,x24,x13			# Sigma1(e)

	srl	x13,x14,28
	add	x22,x22,x25
	ld	x25,144(x12)		# K[18]
	sll	x24,x14,25
	add	x22,x22,x23
	srl	x23,x14,34
	xor	x13,x13,x24
	sll	x24,x14,30
	xor	x13,x13,x23
	srl	x23,x14,39
	xor	x13,x13,x24
	sll	x24,x14,36
	xor	x13,x13,x23
	and	x23,x15,x5
	xor	x13,x13,x24			# Sigma0(a)
	xor	x24,x15,x5
#endif
	sd	x18,16(x2)	# offload to ring buffer
	add	x13,x13,x23
	and	x24,x24,x14
	add	x22,x22,x25			# +=K[18]
	add	x13,x13,x24			# +=Maj(a,b,c)
	add	x6,x6,x22
	add	x13,x13,x22
	ld	x21,40(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x25,x20,7		# Xupdate(19)
	ror	x23,x20,1
	add	x19,x19,x28		# +=X[i+9]
	xor	x25,x25,x23
	ror	x23,x20,8

	srl	x26,x17,6
	ror	x24,x17,19
	xor	x25,x25,x23		# sigma0(X[i+1])
	ror	x23,x17,61
	xor	x26,x26,x24
	add	x19,x19,x25
#else
	srl	x25,x20,7		# Xupdate(19)
	add	x19,x19,x28		# +=X[i+9]
	sll	x24,x20,56
	srl	x23,x20,1
	xor	x25,x25,x24
	sll	x24,x24,7
	xor	x25,x25,x23
	srl	x23,x20,8
	xor	x25,x25,x24

	srl	x26,x17,6
	xor	x25,x25,x23		# sigma0(X[i+1])
	sll	x24,x17,3
	add	x19,x19,x25
	srl	x23,x17,19
	xor	x26,x26,x24
	sll	x24,x24,42
	xor	x26,x26,x23
	srl	x23,x17,61
	xor	x26,x26,x24
#endif
	xor	x26,x26,x23		# sigma1(X[i+14])
	add	x19,x19,x26
#ifdef	__riscv_zbb
	xor	x26,x7,x8			# 19
	ror	x24,x6,14
	add	x23,x19,x9
	ror	x25,x6,18
	and	x26,x26,x6
	ror	x9,x6,41
	xor	x24,x24,x25
	ror	x25,x13,28
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x24,x9			# Sigma1(e)

	ror	x9,x13,34
	add	x23,x23,x26
	ld	x26,152(x12)		# K[19]
	xor	x9,x9,x25
	ror	x25,x13,39
	add	x23,x23,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#else
	add	x23,x19,x9			# 19
	srl	x9,x6,14
	xor	x26,x7,x8
	sll	x25,x6,23
	and	x26,x26,x6
	srl	x24,x6,18
	xor	x9,x9,x25
	sll	x25,x6,46
	xor	x9,x9,x24
	srl	x24,x6,41
	xor	x9,x9,x25
	sll	x25,x6,50
	xor	x9,x9,x24
	xor	x26,x26,x8			# Ch(e,f,g)
	xor	x24,x25,x9			# Sigma1(e)

	srl	x9,x13,28
	add	x23,x23,x26
	ld	x26,152(x12)		# K[19]
	sll	x25,x13,25
	add	x23,x23,x24
	srl	x24,x13,34
	xor	x9,x9,x25
	sll	x25,x13,30
	xor	x9,x9,x24
	srl	x24,x13,39
	xor	x9,x9,x25
	sll	x25,x13,36
	xor	x9,x9,x24
	and	x24,x14,x15
	xor	x9,x9,x25			# Sigma0(a)
	xor	x25,x14,x15
#endif
	sd	x19,24(x2)	# offload to ring buffer
	add	x9,x9,x24
	and	x25,x25,x13
	add	x23,x23,x26			# +=K[19]
	add	x9,x9,x25			# +=Maj(a,b,c)
	add	x5,x5,x23
	add	x9,x9,x23
	ld	x22,48(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x26,x21,7		# Xupdate(20)
	ror	x24,x21,1
	add	x20,x20,x29		# +=X[i+9]
	xor	x26,x26,x24
	ror	x24,x21,8

	srl	x27,x18,6
	ror	x25,x18,19
	xor	x26,x26,x24		# sigma0(X[i+1])
	ror	x24,x18,61
	xor	x27,x27,x25
	add	x20,x20,x26
#else
	srl	x26,x21,7		# Xupdate(20)
	add	x20,x20,x29		# +=X[i+9]
	sll	x25,x21,56
	srl	x24,x21,1
	xor	x26,x26,x25
	sll	x25,x25,7
	xor	x26,x26,x24
	srl	x24,x21,8
	xor	x26,x26,x25

	srl	x27,x18,6
	xor	x26,x26,x24		# sigma0(X[i+1])
	sll	x25,x18,3
	add	x20,x20,x26
	srl	x24,x18,19
	xor	x27,x27,x25
	sll	x25,x25,42
	xor	x27,x27,x24
	srl	x24,x18,61
	xor	x27,x27,x25
#endif
	xor	x27,x27,x24		# sigma1(X[i+14])
	add	x20,x20,x27
#ifdef	__riscv_zbb
	xor	x27,x6,x7			# 20
	ror	x25,x5,14
	add	x24,x20,x8
	ror	x26,x5,18
	and	x27,x27,x5
	ror	x8,x5,41
	xor	x25,x25,x26
	ror	x26,x9,28
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x25,x8			# Sigma1(e)

	ror	x8,x9,34
	add	x24,x24,x27
	ld	x27,160(x12)		# K[20]
	xor	x8,x8,x26
	ror	x26,x9,39
	add	x24,x24,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#else
	add	x24,x20,x8			# 20
	srl	x8,x5,14
	xor	x27,x6,x7
	sll	x26,x5,23
	and	x27,x27,x5
	srl	x25,x5,18
	xor	x8,x8,x26
	sll	x26,x5,46
	xor	x8,x8,x25
	srl	x25,x5,41
	xor	x8,x8,x26
	sll	x26,x5,50
	xor	x8,x8,x25
	xor	x27,x27,x7			# Ch(e,f,g)
	xor	x25,x26,x8			# Sigma1(e)

	srl	x8,x9,28
	add	x24,x24,x27
	ld	x27,160(x12)		# K[20]
	sll	x26,x9,25
	add	x24,x24,x25
	srl	x25,x9,34
	xor	x8,x8,x26
	sll	x26,x9,30
	xor	x8,x8,x25
	srl	x25,x9,39
	xor	x8,x8,x26
	sll	x26,x9,36
	xor	x8,x8,x25
	and	x25,x13,x14
	xor	x8,x8,x26			# Sigma0(a)
	xor	x26,x13,x14
#endif
	sd	x20,32(x2)	# offload to ring buffer
	add	x8,x8,x25
	and	x26,x26,x9
	add	x24,x24,x27			# +=K[20]
	add	x8,x8,x26			# +=Maj(a,b,c)
	add	x15,x15,x24
	add	x8,x8,x24
	ld	x23,56(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x27,x22,7		# Xupdate(21)
	ror	x25,x22,1
	add	x21,x21,x30		# +=X[i+9]
	xor	x27,x27,x25
	ror	x25,x22,8

	srl	x28,x19,6
	ror	x26,x19,19
	xor	x27,x27,x25		# sigma0(X[i+1])
	ror	x25,x19,61
	xor	x28,x28,x26
	add	x21,x21,x27
#else
	srl	x27,x22,7		# Xupdate(21)
	add	x21,x21,x30		# +=X[i+9]
	sll	x26,x22,56
	srl	x25,x22,1
	xor	x27,x27,x26
	sll	x26,x26,7
	xor	x27,x27,x25
	srl	x25,x22,8
	xor	x27,x27,x26

	srl	x28,x19,6
	xor	x27,x27,x25		# sigma0(X[i+1])
	sll	x26,x19,3
	add	x21,x21,x27
	srl	x25,x19,19
	xor	x28,x28,x26
	sll	x26,x26,42
	xor	x28,x28,x25
	srl	x25,x19,61
	xor	x28,x28,x26
#endif
	xor	x28,x28,x25		# sigma1(X[i+14])
	add	x21,x21,x28
#ifdef	__riscv_zbb
	xor	x28,x5,x6			# 21
	ror	x26,x15,14
	add	x25,x21,x7
	ror	x27,x15,18
	and	x28,x28,x15
	ror	x7,x15,41
	xor	x26,x26,x27
	ror	x27,x8,28
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x26,x7			# Sigma1(e)

	ror	x7,x8,34
	add	x25,x25,x28
	ld	x28,168(x12)		# K[21]
	xor	x7,x7,x27
	ror	x27,x8,39
	add	x25,x25,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#else
	add	x25,x21,x7			# 21
	srl	x7,x15,14
	xor	x28,x5,x6
	sll	x27,x15,23
	and	x28,x28,x15
	srl	x26,x15,18
	xor	x7,x7,x27
	sll	x27,x15,46
	xor	x7,x7,x26
	srl	x26,x15,41
	xor	x7,x7,x27
	sll	x27,x15,50
	xor	x7,x7,x26
	xor	x28,x28,x6			# Ch(e,f,g)
	xor	x26,x27,x7			# Sigma1(e)

	srl	x7,x8,28
	add	x25,x25,x28
	ld	x28,168(x12)		# K[21]
	sll	x27,x8,25
	add	x25,x25,x26
	srl	x26,x8,34
	xor	x7,x7,x27
	sll	x27,x8,30
	xor	x7,x7,x26
	srl	x26,x8,39
	xor	x7,x7,x27
	sll	x27,x8,36
	xor	x7,x7,x26
	and	x26,x9,x13
	xor	x7,x7,x27			# Sigma0(a)
	xor	x27,x9,x13
#endif
	sd	x21,40(x2)	# offload to ring buffer
	add	x7,x7,x26
	and	x27,x27,x8
	add	x25,x25,x28			# +=K[21]
	add	x7,x7,x27			# +=Maj(a,b,c)
	add	x14,x14,x25
	add	x7,x7,x25
	ld	x24,64(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x28,x23,7		# Xupdate(22)
	ror	x26,x23,1
	add	x22,x22,x31		# +=X[i+9]
	xor	x28,x28,x26
	ror	x26,x23,8

	srl	x29,x20,6
	ror	x27,x20,19
	xor	x28,x28,x26		# sigma0(X[i+1])
	ror	x26,x20,61
	xor	x29,x29,x27
	add	x22,x22,x28
#else
	srl	x28,x23,7		# Xupdate(22)
	add	x22,x22,x31		# +=X[i+9]
	sll	x27,x23,56
	srl	x26,x23,1
	xor	x28,x28,x27
	sll	x27,x27,7
	xor	x28,x28,x26
	srl	x26,x23,8
	xor	x28,x28,x27

	srl	x29,x20,6
	xor	x28,x28,x26		# sigma0(X[i+1])
	sll	x27,x20,3
	add	x22,x22,x28
	srl	x26,x20,19
	xor	x29,x29,x27
	sll	x27,x27,42
	xor	x29,x29,x26
	srl	x26,x20,61
	xor	x29,x29,x27
#endif
	xor	x29,x29,x26		# sigma1(X[i+14])
	add	x22,x22,x29
#ifdef	__riscv_zbb
	xor	x29,x15,x5			# 22
	ror	x27,x14,14
	add	x26,x22,x6
	ror	x28,x14,18
	and	x29,x29,x14
	ror	x6,x14,41
	xor	x27,x27,x28
	ror	x28,x7,28
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x27,x6			# Sigma1(e)

	ror	x6,x7,34
	add	x26,x26,x29
	ld	x29,176(x12)		# K[22]
	xor	x6,x6,x28
	ror	x28,x7,39
	add	x26,x26,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#else
	add	x26,x22,x6			# 22
	srl	x6,x14,14
	xor	x29,x15,x5
	sll	x28,x14,23
	and	x29,x29,x14
	srl	x27,x14,18
	xor	x6,x6,x28
	sll	x28,x14,46
	xor	x6,x6,x27
	srl	x27,x14,41
	xor	x6,x6,x28
	sll	x28,x14,50
	xor	x6,x6,x27
	xor	x29,x29,x5			# Ch(e,f,g)
	xor	x27,x28,x6			# Sigma1(e)

	srl	x6,x7,28
	add	x26,x26,x29
	ld	x29,176(x12)		# K[22]
	sll	x28,x7,25
	add	x26,x26,x27
	srl	x27,x7,34
	xor	x6,x6,x28
	sll	x28,x7,30
	xor	x6,x6,x27
	srl	x27,x7,39
	xor	x6,x6,x28
	sll	x28,x7,36
	xor	x6,x6,x27
	and	x27,x8,x9
	xor	x6,x6,x28			# Sigma0(a)
	xor	x28,x8,x9
#endif
	sd	x22,48(x2)	# offload to ring buffer
	add	x6,x6,x27
	and	x28,x28,x7
	add	x26,x26,x29			# +=K[22]
	add	x6,x6,x28			# +=Maj(a,b,c)
	add	x13,x13,x26
	add	x6,x6,x26
	ld	x25,72(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x29,x24,7		# Xupdate(23)
	ror	x27,x24,1
	add	x23,x23,x16		# +=X[i+9]
	xor	x29,x29,x27
	ror	x27,x24,8

	srl	x30,x21,6
	ror	x28,x21,19
	xor	x29,x29,x27		# sigma0(X[i+1])
	ror	x27,x21,61
	xor	x30,x30,x28
	add	x23,x23,x29
#else
	srl	x29,x24,7		# Xupdate(23)
	add	x23,x23,x16		# +=X[i+9]
	sll	x28,x24,56
	srl	x27,x24,1
	xor	x29,x29,x28
	sll	x28,x28,7
	xor	x29,x29,x27
	srl	x27,x24,8
	xor	x29,x29,x28

	srl	x30,x21,6
	xor	x29,x29,x27		# sigma0(X[i+1])
	sll	x28,x21,3
	add	x23,x23,x29
	srl	x27,x21,19
	xor	x30,x30,x28
	sll	x28,x28,42
	xor	x30,x30,x27
	srl	x27,x21,61
	xor	x30,x30,x28
#endif
	xor	x30,x30,x27		# sigma1(X[i+14])
	add	x23,x23,x30
#ifdef	__riscv_zbb
	xor	x30,x14,x15			# 23
	ror	x28,x13,14
	add	x27,x23,x5
	ror	x29,x13,18
	and	x30,x30,x13
	ror	x5,x13,41
	xor	x28,x28,x29
	ror	x29,x6,28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x28,x5			# Sigma1(e)

	ror	x5,x6,34
	add	x27,x27,x30
	ld	x30,184(x12)		# K[23]
	xor	x5,x5,x29
	ror	x29,x6,39
	add	x27,x27,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#else
	add	x27,x23,x5			# 23
	srl	x5,x13,14
	xor	x30,x14,x15
	sll	x29,x13,23
	and	x30,x30,x13
	srl	x28,x13,18
	xor	x5,x5,x29
	sll	x29,x13,46
	xor	x5,x5,x28
	srl	x28,x13,41
	xor	x5,x5,x29
	sll	x29,x13,50
	xor	x5,x5,x28
	xor	x30,x30,x15			# Ch(e,f,g)
	xor	x28,x29,x5			# Sigma1(e)

	srl	x5,x6,28
	add	x27,x27,x30
	ld	x30,184(x12)		# K[23]
	sll	x29,x6,25
	add	x27,x27,x28
	srl	x28,x6,34
	xor	x5,x5,x29
	sll	x29,x6,30
	xor	x5,x5,x28
	srl	x28,x6,39
	xor	x5,x5,x29
	sll	x29,x6,36
	xor	x5,x5,x28
	and	x28,x7,x8
	xor	x5,x5,x29			# Sigma0(a)
	xor	x29,x7,x8
#endif
	sd	x23,56(x2)	# offload to ring buffer
	add	x5,x5,x28
	and	x29,x29,x6
	add	x27,x27,x30			# +=K[23]
	add	x5,x5,x29			# +=Maj(a,b,c)
	add	x9,x9,x27
	add	x5,x5,x27
	ld	x26,80(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x30,x25,7		# Xupdate(24)
	ror	x28,x25,1
	add	x24,x24,x17		# +=X[i+9]
	xor	x30,x30,x28
	ror	x28,x25,8

	srl	x31,x22,6
	ror	x29,x22,19
	xor	x30,x30,x28		# sigma0(X[i+1])
	ror	x28,x22,61
	xor	x31,x31,x29
	add	x24,x24,x30
#else
	srl	x30,x25,7		# Xupdate(24)
	add	x24,x24,x17		# +=X[i+9]
	sll	x29,x25,56
	srl	x28,x25,1
	xor	x30,x30,x29
	sll	x29,x29,7
	xor	x30,x30,x28
	srl	x28,x25,8
	xor	x30,x30,x29

	srl	x31,x22,6
	xor	x30,x30,x28		# sigma0(X[i+1])
	sll	x29,x22,3
	add	x24,x24,x30
	srl	x28,x22,19
	xor	x31,x31,x29
	sll	x29,x29,42
	xor	x31,x31,x28
	srl	x28,x22,61
	xor	x31,x31,x29
#endif
	xor	x31,x31,x28		# sigma1(X[i+14])
	add	x24,x24,x31
#ifdef	__riscv_zbb
	xor	x31,x13,x14			# 24
	ror	x29,x9,14
	add	x28,x24,x15
	ror	x30,x9,18
	and	x31,x31,x9
	ror	x15,x9,41
	xor	x29,x29,x30
	ror	x30,x5,28
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x29,x15			# Sigma1(e)

	ror	x15,x5,34
	add	x28,x28,x31
	ld	x31,192(x12)		# K[24]
	xor	x15,x15,x30
	ror	x30,x5,39
	add	x28,x28,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#else
	add	x28,x24,x15			# 24
	srl	x15,x9,14
	xor	x31,x13,x14
	sll	x30,x9,23
	and	x31,x31,x9
	srl	x29,x9,18
	xor	x15,x15,x30
	sll	x30,x9,46
	xor	x15,x15,x29
	srl	x29,x9,41
	xor	x15,x15,x30
	sll	x30,x9,50
	xor	x15,x15,x29
	xor	x31,x31,x14			# Ch(e,f,g)
	xor	x29,x30,x15			# Sigma1(e)

	srl	x15,x5,28
	add	x28,x28,x31
	ld	x31,192(x12)		# K[24]
	sll	x30,x5,25
	add	x28,x28,x29
	srl	x29,x5,34
	xor	x15,x15,x30
	sll	x30,x5,30
	xor	x15,x15,x29
	srl	x29,x5,39
	xor	x15,x15,x30
	sll	x30,x5,36
	xor	x15,x15,x29
	and	x29,x6,x7
	xor	x15,x15,x30			# Sigma0(a)
	xor	x30,x6,x7
#endif
	sd	x24,64(x2)	# offload to ring buffer
	add	x15,x15,x29
	and	x30,x30,x5
	add	x28,x28,x31			# +=K[24]
	add	x15,x15,x30			# +=Maj(a,b,c)
	add	x8,x8,x28
	add	x15,x15,x28
	ld	x27,88(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x31,x26,7		# Xupdate(25)
	ror	x29,x26,1
	add	x25,x25,x18		# +=X[i+9]
	xor	x31,x31,x29
	ror	x29,x26,8

	srl	x16,x23,6
	ror	x30,x23,19
	xor	x31,x31,x29		# sigma0(X[i+1])
	ror	x29,x23,61
	xor	x16,x16,x30
	add	x25,x25,x31
#else
	srl	x31,x26,7		# Xupdate(25)
	add	x25,x25,x18		# +=X[i+9]
	sll	x30,x26,56
	srl	x29,x26,1
	xor	x31,x31,x30
	sll	x30,x30,7
	xor	x31,x31,x29
	srl	x29,x26,8
	xor	x31,x31,x30

	srl	x16,x23,6
	xor	x31,x31,x29		# sigma0(X[i+1])
	sll	x30,x23,3
	add	x25,x25,x31
	srl	x29,x23,19
	xor	x16,x16,x30
	sll	x30,x30,42
	xor	x16,x16,x29
	srl	x29,x23,61
	xor	x16,x16,x30
#endif
	xor	x16,x16,x29		# sigma1(X[i+14])
	add	x25,x25,x16
#ifdef	__riscv_zbb
	xor	x16,x9,x13			# 25
	ror	x30,x8,14
	add	x29,x25,x14
	ror	x31,x8,18
	and	x16,x16,x8
	ror	x14,x8,41
	xor	x30,x30,x31
	ror	x31,x15,28
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x30,x14			# Sigma1(e)

	ror	x14,x15,34
	add	x29,x29,x16
	ld	x16,200(x12)		# K[25]
	xor	x14,x14,x31
	ror	x31,x15,39
	add	x29,x29,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#else
	add	x29,x25,x14			# 25
	srl	x14,x8,14
	xor	x16,x9,x13
	sll	x31,x8,23
	and	x16,x16,x8
	srl	x30,x8,18
	xor	x14,x14,x31
	sll	x31,x8,46
	xor	x14,x14,x30
	srl	x30,x8,41
	xor	x14,x14,x31
	sll	x31,x8,50
	xor	x14,x14,x30
	xor	x16,x16,x13			# Ch(e,f,g)
	xor	x30,x31,x14			# Sigma1(e)

	srl	x14,x15,28
	add	x29,x29,x16
	ld	x16,200(x12)		# K[25]
	sll	x31,x15,25
	add	x29,x29,x30
	srl	x30,x15,34
	xor	x14,x14,x31
	sll	x31,x15,30
	xor	x14,x14,x30
	srl	x30,x15,39
	xor	x14,x14,x31
	sll	x31,x15,36
	xor	x14,x14,x30
	and	x30,x5,x6
	xor	x14,x14,x31			# Sigma0(a)
	xor	x31,x5,x6
#endif
	sd	x25,72(x2)	# offload to ring buffer
	add	x14,x14,x30
	and	x31,x31,x15
	add	x29,x29,x16			# +=K[25]
	add	x14,x14,x31			# +=Maj(a,b,c)
	add	x7,x7,x29
	add	x14,x14,x29
	ld	x28,96(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x16,x27,7		# Xupdate(26)
	ror	x30,x27,1
	add	x26,x26,x19		# +=X[i+9]
	xor	x16,x16,x30
	ror	x30,x27,8

	srl	x17,x24,6
	ror	x31,x24,19
	xor	x16,x16,x30		# sigma0(X[i+1])
	ror	x30,x24,61
	xor	x17,x17,x31
	add	x26,x26,x16
#else
	srl	x16,x27,7		# Xupdate(26)
	add	x26,x26,x19		# +=X[i+9]
	sll	x31,x27,56
	srl	x30,x27,1
	xor	x16,x16,x31
	sll	x31,x31,7
	xor	x16,x16,x30
	srl	x30,x27,8
	xor	x16,x16,x31

	srl	x17,x24,6
	xor	x16,x16,x30		# sigma0(X[i+1])
	sll	x31,x24,3
	add	x26,x26,x16
	srl	x30,x24,19
	xor	x17,x17,x31
	sll	x31,x31,42
	xor	x17,x17,x30
	srl	x30,x24,61
	xor	x17,x17,x31
#endif
	xor	x17,x17,x30		# sigma1(X[i+14])
	add	x26,x26,x17
#ifdef	__riscv_zbb
	xor	x17,x8,x9			# 26
	ror	x31,x7,14
	add	x30,x26,x13
	ror	x16,x7,18
	and	x17,x17,x7
	ror	x13,x7,41
	xor	x31,x31,x16
	ror	x16,x14,28
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x31,x13			# Sigma1(e)

	ror	x13,x14,34
	add	x30,x30,x17
	ld	x17,208(x12)		# K[26]
	xor	x13,x13,x16
	ror	x16,x14,39
	add	x30,x30,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#else
	add	x30,x26,x13			# 26
	srl	x13,x7,14
	xor	x17,x8,x9
	sll	x16,x7,23
	and	x17,x17,x7
	srl	x31,x7,18
	xor	x13,x13,x16
	sll	x16,x7,46
	xor	x13,x13,x31
	srl	x31,x7,41
	xor	x13,x13,x16
	sll	x16,x7,50
	xor	x13,x13,x31
	xor	x17,x17,x9			# Ch(e,f,g)
	xor	x31,x16,x13			# Sigma1(e)

	srl	x13,x14,28
	add	x30,x30,x17
	ld	x17,208(x12)		# K[26]
	sll	x16,x14,25
	add	x30,x30,x31
	srl	x31,x14,34
	xor	x13,x13,x16
	sll	x16,x14,30
	xor	x13,x13,x31
	srl	x31,x14,39
	xor	x13,x13,x16
	sll	x16,x14,36
	xor	x13,x13,x31
	and	x31,x15,x5
	xor	x13,x13,x16			# Sigma0(a)
	xor	x16,x15,x5
#endif
	sd	x26,80(x2)	# offload to ring buffer
	add	x13,x13,x31
	and	x16,x16,x14
	add	x30,x30,x17			# +=K[26]
	add	x13,x13,x16			# +=Maj(a,b,c)
	add	x6,x6,x30
	add	x13,x13,x30
	ld	x29,104(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x17,x28,7		# Xupdate(27)
	ror	x31,x28,1
	add	x27,x27,x20		# +=X[i+9]
	xor	x17,x17,x31
	ror	x31,x28,8

	srl	x18,x25,6
	ror	x16,x25,19
	xor	x17,x17,x31		# sigma0(X[i+1])
	ror	x31,x25,61
	xor	x18,x18,x16
	add	x27,x27,x17
#else
	srl	x17,x28,7		# Xupdate(27)
	add	x27,x27,x20		# +=X[i+9]
	sll	x16,x28,56
	srl	x31,x28,1
	xor	x17,x17,x16
	sll	x16,x16,7
	xor	x17,x17,x31
	srl	x31,x28,8
	xor	x17,x17,x16

	srl	x18,x25,6
	xor	x17,x17,x31		# sigma0(X[i+1])
	sll	x16,x25,3
	add	x27,x27,x17
	srl	x31,x25,19
	xor	x18,x18,x16
	sll	x16,x16,42
	xor	x18,x18,x31
	srl	x31,x25,61
	xor	x18,x18,x16
#endif
	xor	x18,x18,x31		# sigma1(X[i+14])
	add	x27,x27,x18
#ifdef	__riscv_zbb
	xor	x18,x7,x8			# 27
	ror	x16,x6,14
	add	x31,x27,x9
	ror	x17,x6,18
	and	x18,x18,x6
	ror	x9,x6,41
	xor	x16,x16,x17
	ror	x17,x13,28
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x16,x9			# Sigma1(e)

	ror	x9,x13,34
	add	x31,x31,x18
	ld	x18,216(x12)		# K[27]
	xor	x9,x9,x17
	ror	x17,x13,39
	add	x31,x31,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#else
	add	x31,x27,x9			# 27
	srl	x9,x6,14
	xor	x18,x7,x8
	sll	x17,x6,23
	and	x18,x18,x6
	srl	x16,x6,18
	xor	x9,x9,x17
	sll	x17,x6,46
	xor	x9,x9,x16
	srl	x16,x6,41
	xor	x9,x9,x17
	sll	x17,x6,50
	xor	x9,x9,x16
	xor	x18,x18,x8			# Ch(e,f,g)
	xor	x16,x17,x9			# Sigma1(e)

	srl	x9,x13,28
	add	x31,x31,x18
	ld	x18,216(x12)		# K[27]
	sll	x17,x13,25
	add	x31,x31,x16
	srl	x16,x13,34
	xor	x9,x9,x17
	sll	x17,x13,30
	xor	x9,x9,x16
	srl	x16,x13,39
	xor	x9,x9,x17
	sll	x17,x13,36
	xor	x9,x9,x16
	and	x16,x14,x15
	xor	x9,x9,x17			# Sigma0(a)
	xor	x17,x14,x15
#endif
	sd	x27,88(x2)	# offload to ring buffer
	add	x9,x9,x16
	and	x17,x17,x13
	add	x31,x31,x18			# +=K[27]
	add	x9,x9,x17			# +=Maj(a,b,c)
	add	x5,x5,x31
	add	x9,x9,x31
	ld	x30,112(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x18,x29,7		# Xupdate(28)
	ror	x16,x29,1
	add	x28,x28,x21		# +=X[i+9]
	xor	x18,x18,x16
	ror	x16,x29,8

	srl	x19,x26,6
	ror	x17,x26,19
	xor	x18,x18,x16		# sigma0(X[i+1])
	ror	x16,x26,61
	xor	x19,x19,x17
	add	x28,x28,x18
#else
	srl	x18,x29,7		# Xupdate(28)
	add	x28,x28,x21		# +=X[i+9]
	sll	x17,x29,56
	srl	x16,x29,1
	xor	x18,x18,x17
	sll	x17,x17,7
	xor	x18,x18,x16
	srl	x16,x29,8
	xor	x18,x18,x17

	srl	x19,x26,6
	xor	x18,x18,x16		# sigma0(X[i+1])
	sll	x17,x26,3
	add	x28,x28,x18
	srl	x16,x26,19
	xor	x19,x19,x17
	sll	x17,x17,42
	xor	x19,x19,x16
	srl	x16,x26,61
	xor	x19,x19,x17
#endif
	xor	x19,x19,x16		# sigma1(X[i+14])
	add	x28,x28,x19
#ifdef	__riscv_zbb
	xor	x19,x6,x7			# 28
	ror	x17,x5,14
	add	x16,x28,x8
	ror	x18,x5,18
	and	x19,x19,x5
	ror	x8,x5,41
	xor	x17,x17,x18
	ror	x18,x9,28
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x17,x8			# Sigma1(e)

	ror	x8,x9,34
	add	x16,x16,x19
	ld	x19,224(x12)		# K[28]
	xor	x8,x8,x18
	ror	x18,x9,39
	add	x16,x16,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#else
	add	x16,x28,x8			# 28
	srl	x8,x5,14
	xor	x19,x6,x7
	sll	x18,x5,23
	and	x19,x19,x5
	srl	x17,x5,18
	xor	x8,x8,x18
	sll	x18,x5,46
	xor	x8,x8,x17
	srl	x17,x5,41
	xor	x8,x8,x18
	sll	x18,x5,50
	xor	x8,x8,x17
	xor	x19,x19,x7			# Ch(e,f,g)
	xor	x17,x18,x8			# Sigma1(e)

	srl	x8,x9,28
	add	x16,x16,x19
	ld	x19,224(x12)		# K[28]
	sll	x18,x9,25
	add	x16,x16,x17
	srl	x17,x9,34
	xor	x8,x8,x18
	sll	x18,x9,30
	xor	x8,x8,x17
	srl	x17,x9,39
	xor	x8,x8,x18
	sll	x18,x9,36
	xor	x8,x8,x17
	and	x17,x13,x14
	xor	x8,x8,x18			# Sigma0(a)
	xor	x18,x13,x14
#endif
	sd	x28,96(x2)	# offload to ring buffer
	add	x8,x8,x17
	and	x18,x18,x9
	add	x16,x16,x19			# +=K[28]
	add	x8,x8,x18			# +=Maj(a,b,c)
	add	x15,x15,x16
	add	x8,x8,x16
	ld	x31,120(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x19,x30,7		# Xupdate(29)
	ror	x17,x30,1
	add	x29,x29,x22		# +=X[i+9]
	xor	x19,x19,x17
	ror	x17,x30,8

	srl	x20,x27,6
	ror	x18,x27,19
	xor	x19,x19,x17		# sigma0(X[i+1])
	ror	x17,x27,61
	xor	x20,x20,x18
	add	x29,x29,x19
#else
	srl	x19,x30,7		# Xupdate(29)
	add	x29,x29,x22		# +=X[i+9]
	sll	x18,x30,56
	srl	x17,x30,1
	xor	x19,x19,x18
	sll	x18,x18,7
	xor	x19,x19,x17
	srl	x17,x30,8
	xor	x19,x19,x18

	srl	x20,x27,6
	xor	x19,x19,x17		# sigma0(X[i+1])
	sll	x18,x27,3
	add	x29,x29,x19
	srl	x17,x27,19
	xor	x20,x20,x18
	sll	x18,x18,42
	xor	x20,x20,x17
	srl	x17,x27,61
	xor	x20,x20,x18
#endif
	xor	x20,x20,x17		# sigma1(X[i+14])
	add	x29,x29,x20
#ifdef	__riscv_zbb
	xor	x20,x5,x6			# 29
	ror	x18,x15,14
	add	x17,x29,x7
	ror	x19,x15,18
	and	x20,x20,x15
	ror	x7,x15,41
	xor	x18,x18,x19
	ror	x19,x8,28
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x18,x7			# Sigma1(e)

	ror	x7,x8,34
	add	x17,x17,x20
	ld	x20,232(x12)		# K[29]
	xor	x7,x7,x19
	ror	x19,x8,39
	add	x17,x17,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#else
	add	x17,x29,x7			# 29
	srl	x7,x15,14
	xor	x20,x5,x6
	sll	x19,x15,23
	and	x20,x20,x15
	srl	x18,x15,18
	xor	x7,x7,x19
	sll	x19,x15,46
	xor	x7,x7,x18
	srl	x18,x15,41
	xor	x7,x7,x19
	sll	x19,x15,50
	xor	x7,x7,x18
	xor	x20,x20,x6			# Ch(e,f,g)
	xor	x18,x19,x7			# Sigma1(e)

	srl	x7,x8,28
	add	x17,x17,x20
	ld	x20,232(x12)		# K[29]
	sll	x19,x8,25
	add	x17,x17,x18
	srl	x18,x8,34
	xor	x7,x7,x19
	sll	x19,x8,30
	xor	x7,x7,x18
	srl	x18,x8,39
	xor	x7,x7,x19
	sll	x19,x8,36
	xor	x7,x7,x18
	and	x18,x9,x13
	xor	x7,x7,x19			# Sigma0(a)
	xor	x19,x9,x13
#endif
	sd	x29,104(x2)	# offload to ring buffer
	add	x7,x7,x18
	and	x19,x19,x8
	add	x17,x17,x20			# +=K[29]
	add	x7,x7,x19			# +=Maj(a,b,c)
	add	x14,x14,x17
	add	x7,x7,x17
	ld	x16,0(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x20,x31,7		# Xupdate(30)
	ror	x18,x31,1
	add	x30,x30,x23		# +=X[i+9]
	xor	x20,x20,x18
	ror	x18,x31,8

	srl	x21,x28,6
	ror	x19,x28,19
	xor	x20,x20,x18		# sigma0(X[i+1])
	ror	x18,x28,61
	xor	x21,x21,x19
	add	x30,x30,x20
#else
	srl	x20,x31,7		# Xupdate(30)
	add	x30,x30,x23		# +=X[i+9]
	sll	x19,x31,56
	srl	x18,x31,1
	xor	x20,x20,x19
	sll	x19,x19,7
	xor	x20,x20,x18
	srl	x18,x31,8
	xor	x20,x20,x19

	srl	x21,x28,6
	xor	x20,x20,x18		# sigma0(X[i+1])
	sll	x19,x28,3
	add	x30,x30,x20
	srl	x18,x28,19
	xor	x21,x21,x19
	sll	x19,x19,42
	xor	x21,x21,x18
	srl	x18,x28,61
	xor	x21,x21,x19
#endif
	xor	x21,x21,x18		# sigma1(X[i+14])
	add	x30,x30,x21
#ifdef	__riscv_zbb
	xor	x21,x15,x5			# 30
	ror	x19,x14,14
	add	x18,x30,x6
	ror	x20,x14,18
	and	x21,x21,x14
	ror	x6,x14,41
	xor	x19,x19,x20
	ror	x20,x7,28
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x19,x6			# Sigma1(e)

	ror	x6,x7,34
	add	x18,x18,x21
	ld	x21,240(x12)		# K[30]
	xor	x6,x6,x20
	ror	x20,x7,39
	add	x18,x18,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#else
	add	x18,x30,x6			# 30
	srl	x6,x14,14
	xor	x21,x15,x5
	sll	x20,x14,23
	and	x21,x21,x14
	srl	x19,x14,18
	xor	x6,x6,x20
	sll	x20,x14,46
	xor	x6,x6,x19
	srl	x19,x14,41
	xor	x6,x6,x20
	sll	x20,x14,50
	xor	x6,x6,x19
	xor	x21,x21,x5			# Ch(e,f,g)
	xor	x19,x20,x6			# Sigma1(e)

	srl	x6,x7,28
	add	x18,x18,x21
	ld	x21,240(x12)		# K[30]
	sll	x20,x7,25
	add	x18,x18,x19
	srl	x19,x7,34
	xor	x6,x6,x20
	sll	x20,x7,30
	xor	x6,x6,x19
	srl	x19,x7,39
	xor	x6,x6,x20
	sll	x20,x7,36
	xor	x6,x6,x19
	and	x19,x8,x9
	xor	x6,x6,x20			# Sigma0(a)
	xor	x20,x8,x9
#endif
	sd	x30,112(x2)	# offload to ring buffer
	add	x6,x6,x19
	and	x20,x20,x7
	add	x18,x18,x21			# +=K[30]
	add	x6,x6,x20			# +=Maj(a,b,c)
	add	x13,x13,x18
	add	x6,x6,x18
	ld	x17,8(x2)	# prefetch from ring buffer
#ifdef	__riscv_zbb
	srl	x21,x16,7		# Xupdate(31)
	ror	x19,x16,1
	add	x31,x31,x24		# +=X[i+9]
	xor	x21,x21,x19
	ror	x19,x16,8

	srl	x22,x29,6
	ror	x20,x29,19
	xor	x21,x21,x19		# sigma0(X[i+1])
	ror	x19,x29,61
	xor	x22,x22,x20
	add	x31,x31,x21
#else
	srl	x21,x16,7		# Xupdate(31)
	add	x31,x31,x24		# +=X[i+9]
	sll	x20,x16,56
	srl	x19,x16,1
	xor	x21,x21,x20
	sll	x20,x20,7
	xor	x21,x21,x19
	srl	x19,x16,8
	xor	x21,x21,x20

	srl	x22,x29,6
	xor	x21,x21,x19		# sigma0(X[i+1])
	sll	x20,x29,3
	add	x31,x31,x21
	srl	x19,x29,19
	xor	x22,x22,x20
	sll	x20,x20,42
	xor	x22,x22,x19
	srl	x19,x29,61
	xor	x22,x22,x20
#endif
	xor	x22,x22,x19		# sigma1(X[i+14])
	add	x31,x31,x22
#ifdef	__riscv_zbb
	xor	x22,x14,x15			# 31
	ror	x20,x13,14
	add	x19,x31,x5
	ror	x21,x13,18
	and	x22,x22,x13
	ror	x5,x13,41
	xor	x20,x20,x21
	ror	x21,x6,28
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x20,x5			# Sigma1(e)

	ror	x5,x6,34
	add	x19,x19,x22
	ld	x22,248(x12)		# K[31]
	xor	x5,x5,x21
	ror	x21,x6,39
	add	x19,x19,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#else
	add	x19,x31,x5			# 31
	srl	x5,x13,14
	xor	x22,x14,x15
	sll	x21,x13,23
	and	x22,x22,x13
	srl	x20,x13,18
	xor	x5,x5,x21
	sll	x21,x13,46
	xor	x5,x5,x20
	srl	x20,x13,41
	xor	x5,x5,x21
	sll	x21,x13,50
	xor	x5,x5,x20
	xor	x22,x22,x15			# Ch(e,f,g)
	xor	x20,x21,x5			# Sigma1(e)

	srl	x5,x6,28
	add	x19,x19,x22
	ld	x22,248(x12)		# K[31]
	sll	x21,x6,25
	add	x19,x19,x20
	srl	x20,x6,34
	xor	x5,x5,x21
	sll	x21,x6,30
	xor	x5,x5,x20
	srl	x20,x6,39
	xor	x5,x5,x21
	sll	x21,x6,36
	xor	x5,x5,x20
	and	x20,x7,x8
	xor	x5,x5,x21			# Sigma0(a)
	xor	x21,x7,x8
#endif
	sd	x31,120(x2)	# offload to ring buffer
	add	x5,x5,x20
	and	x21,x21,x6
	add	x19,x19,x22			# +=K[31]
	add	x5,x5,x21			# +=Maj(a,b,c)
	add	x9,x9,x19
	add	x5,x5,x19
	ld	x18,16(x2)	# prefetch from ring buffer
	andi	x22,x22,0x7ff
	li	x23,23
	add	x12,x12,16*8	# Ktbl+=16
	bne	x22,x23,.L16_xx

	POP	x31,16*8(x2)	# restore pointer to the end of input
	ld	x16,0*8(x10)
	ld	x17,1*8(x10)
	ld	x18,2*8(x10)
	add	x11,x11,16*8
	ld	x19,3*8(x10)
	add	x5,x5,x16
	ld	x20,4*8(x10)
	add	x6,x6,x17
	ld	x21,5*8(x10)
	add	x7,x7,x18
	ld	x22,6*8(x10)
	add	x8,x8,x19
	ld	x23,7*8(x10)
	add	x9,x9,x20
	sd	x5,0*8(x10)
	add	x13,x13,x21
	sd	x6,1*8(x10)
	add	x14,x14,x22
	sd	x7,2*8(x10)
	add	x15,x15,x23
	sd	x8,3*8(x10)
	sd	x9,4*8(x10)
	sd	x13,5*8(x10)
	sd	x14,6*8(x10)
	sd	x15,7*8(x10)

	add	x12,x12,-512	# rewind x12
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
SYM_FUNC_END(sha512_block_data_order_riscv_zbb)
#else
SYM_FUNC_END(sha512_block_data_order_riscv)
#endif

.section	.rodata
.align	5
K512:
	.dword	0x428a2f98d728ae22, 0x7137449123ef65cd
	.dword	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	.dword	0x3956c25bf348b538, 0x59f111f1b605d019
	.dword	0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	.dword	0xd807aa98a3030242, 0x12835b0145706fbe
	.dword	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	.dword	0x72be5d74f27b896f, 0x80deb1fe3b1696b1
	.dword	0x9bdc06a725c71235, 0xc19bf174cf692694
	.dword	0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	.dword	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	.dword	0x2de92c6f592b0275, 0x4a7484aa6ea6e483
	.dword	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	.dword	0x983e5152ee66dfab, 0xa831c66d2db43210
	.dword	0xb00327c898fb213f, 0xbf597fc7beef0ee4
	.dword	0xc6e00bf33da88fc2, 0xd5a79147930aa725
	.dword	0x06ca6351e003826f, 0x142929670a0e6e70
	.dword	0x27b70a8546d22ffc, 0x2e1b21385c26c926
	.dword	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	.dword	0x650a73548baf63de, 0x766a0abb3c77b2a8
	.dword	0x81c2c92e47edaee6, 0x92722c851482353b
	.dword	0xa2bfe8a14cf10364, 0xa81a664bbc423001
	.dword	0xc24b8b70d0f89791, 0xc76c51a30654be30
	.dword	0xd192e819d6ef5218, 0xd69906245565a910
	.dword	0xf40e35855771202a, 0x106aa07032bbd1b8
	.dword	0x19a4c116b8d2d0c8, 0x1e376c085141ab53
	.dword	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	.dword	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	.dword	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	.dword	0x748f82ee5defb2fc, 0x78a5636f43172f60
	.dword	0x84c87814a1f0ab72, 0x8cc702081a6439ec
	.dword	0x90befffa23631e28, 0xa4506cebde82bde9
	.dword	0xbef9a3f7b2c67915, 0xc67178f2e372532b
	.dword	0xca273eceea26619c, 0xd186b8c721c0c207
	.dword	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	.dword	0x06f067aa72176fba, 0x0a637dc5a2c898a6
	.dword	0x113f9804bef90dae, 0x1b710b35131c471b
	.dword	0x28db77f523047d84, 0x32caab7b40c72493
	.dword	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	.dword	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	.dword	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
.string	"SHA512 for RISC-V, CRYPTOGAMS by @dot-asm"
.align	5

ASM_END
