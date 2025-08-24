//
// Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
//
// License: see LICENSE file in root directory
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
// WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
//
// This code is derived from the OpenSSL file of
// crypto/aes/asm/aesni-x86_64.pl which is subject to the following license:
//
// Copyright (c) 2006-2019, CRYPTOGAMS by <appro@openssl.org>
// All rights reserved.
//
// The source code in this file is licensed under the CRYPTOGAMS license.
// For further details see http://www.openssl.org/~appro/cryptogams/.

#include "assembler_support.h"

.text

SYM_FUNC_START(gcm_init_v8)
SYM_FUNC_ENTER(gcm_init_v8)
.align	4
	ld1	{v17.2d},[x1]		//load input H
	movi	v19.16b,#0xe1
	shl	v19.2d,v19.2d,#57		//0xc2.0
	ext	v3.16b,v17.16b,v17.16b,#8
	ushr	v18.2d,v19.2d,#63
	dup	v17.4s,v17.s[1]
	ext	v16.16b,v18.16b,v19.16b,#8		//t0=0xc2....01
	ushr	v18.2d,v3.2d,#63
	sshr	v17.4s,v17.4s,#31		//broadcast carry bit
	and	v18.16b,v18.16b,v16.16b
	shl	v3.2d,v3.2d,#1
	ext	v18.16b,v18.16b,v18.16b,#8
	and	v16.16b,v16.16b,v17.16b
	orr	v3.16b,v3.16b,v18.16b		//H<<<=1
	eor	v20.16b,v3.16b,v16.16b		//twisted H
	st1	{v20.2d},[x0],#16		//store Htable[0]

	//calculate H^2
	ext	v16.16b,v20.16b,v20.16b,#8		//Karatsuba pre-processing
.long	0x0ef4e280	//pmull v0.16b,v20.16b,v20.16b 20
	eor	v16.16b,v16.16b,v20.16b
.long	0x4ef4e282	//pmull2 v2.16b,v20.16b,v20.16b
.long	0x0ef0e201	//pmull v1.16b,v16.16b,v16.16b 16

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase 0

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v22.16b,v0.16b,v18.16b

	ext	v17.16b,v22.16b,v22.16b,#8		//Karatsuba pre-processing
	eor	v17.16b,v17.16b,v22.16b
	ext	v21.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v21.2d,v22.2d},[x0],#32	//store Htable[1..2]
	//calculate H^3 and H^4
.long	0x0ef6e280	//pmull v0.16b,v20.16b, v22.16b 20
.long	0x0ef6e2c5	//pmull v5.16b,v22.16b,v22.16b 22
.long	0x4ef6e282	//pmull2 v2.16b,v20.16b, v22.16b
.long	0x4ef6e2c7	//pmull2 v7.16b,v22.16b,v22.16b
.long	0x0ef1e201	//pmull v1.16b,v16.16b,v17.16b 16
.long	0x0ef1e226	//pmull v6.16b,v17.16b,v17.16b 17

	ext	v16.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	ext	v17.16b,v5.16b,v7.16b,#8
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v16.16b
	eor	v4.16b,v5.16b,v7.16b
	eor	v6.16b,v6.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase 0
	eor	v6.16b,v6.16b,v4.16b
.long	0x0ef3e0a4	//pmull v4.16b,v5.16b,v19.16b 5

	ins	v2.d[0],v1.d[1]
	ins	v7.d[0],v6.d[1]
	ins	v1.d[1],v0.d[0]
	ins	v6.d[1],v5.d[0]
	eor	v0.16b,v1.16b,v18.16b
	eor	v5.16b,v6.16b,v4.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
	ext	v4.16b,v5.16b,v5.16b,#8
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
.long	0x0ef3e0a5	//pmull v5.16b,v5.16b,v19.16b 5
	eor	v18.16b,v18.16b,v2.16b
	eor	v4.16b,v4.16b,v7.16b
	eor	v20.16b, v0.16b,v18.16b		//H^3
	eor	v22.16b,v5.16b,v4.16b		//H^4

	ext	v16.16b,v20.16b, v20.16b,#8		//Karatsuba pre-processing
	ext	v17.16b,v22.16b,v22.16b,#8
	eor	v16.16b,v16.16b,v20.16b
	eor	v17.16b,v17.16b,v22.16b
	ext	v21.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v20.2d,v21.2d,v22.2d},[x0]		//store Htable[3..5]
	RET
SYM_FUNC_END(gcm_init_v8)

SYM_FUNC_START(gcm_gmult_v8)
SYM_FUNC_ENTER(gcm_gmult_v8)
.align	4
	ld1	{v17.2d},[x0]		//load Xi
	movi	v19.16b,#0xe1
	ld1	{v20.2d,v21.2d},[x1]	//load twisted H, ...
	shl	v19.2d,v19.2d,#57
#ifndef __ARMEB__
	rev64	v17.16b,v17.16b
#endif
	ext	v3.16b,v17.16b,v17.16b,#8

.long	0x0ee3e280	//pmull v0.16b,v20.16b,v3.16b		//H.lo·Xi.lo 20
	eor	v17.16b,v17.16b,v3.16b		//Karatsuba pre-processing
.long	0x4ee3e282	//pmull2 v2.16b,v20.16b,v3.16b		//H.hi·Xi.hi
.long	0x0ef1e2a1	//pmull v1.16b,v21.16b,v17.16b		//(H.lo+H.hi)·(Xi.lo+Xi.hi) 21

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b

#ifndef __ARMEB__
	rev64	v0.16b,v0.16b
#endif
	ext	v0.16b,v0.16b,v0.16b,#8
	st1	{v0.2d},[x0]		//write out Xi

	RET
SYM_FUNC_END(gcm_gmult_v8)

#if 0
.globl	gcm_ghash_v8

.align	4
gcm_ghash_v8:
	cmp	x3,#64
	b.hs	.Lgcm_ghash_v8_4x
	ld1	{v0.2d},[x0]		//load [rotated] Xi
						//"[rotated]" means that
						//loaded value would have
						//to be rotated in order to
						//make it appear as in
						//algorithm specification
	subs	x3,x3,#32		//see if x3 is 32 or larger
	mov	x12,#16		//x12 is used as post-
						//increment for input pointer;
						//as loop is modulo-scheduled
						//x12 is zeroed just in time
						//to preclude overstepping
						//inp[len], which means that
						//last block[s] are actually
						//loaded twice, but last
						//copy is not processed
	ld1	{v20.2d,v21.2d},[x1],#32	//load twisted H, ..., H^2
	movi	v19.16b,#0xe1
	ld1	{v22.2d},[x1]
	csel	x12,xzr,x12,eq			//is it time to zero x12?
	ext	v0.16b,v0.16b,v0.16b,#8		//rotate Xi
	ld1	{v16.2d},[x2],#16	//load [rotated] I[0]
	shl	v19.2d,v19.2d,#57		//compose 0xc2.0 constant
#ifndef __ARMEB__
	rev64	v16.16b,v16.16b
	rev64	v0.16b,v0.16b
#endif
	ext	v3.16b,v16.16b,v16.16b,#8		//rotate I[0]
	b.lo	.Lodd_tail_v8		//x3 was less than 32
	ld1	{v17.2d},[x2],x12	//load [rotated] I[1]
#ifndef __ARMEB__
	rev64	v17.16b,v17.16b
#endif
	ext	v7.16b,v17.16b,v17.16b,#8
	eor	v3.16b,v3.16b,v0.16b		//I[i]^=Xi
.long	0x0ee7e284	//pmull v4.16b,v20.16b,v7.16b		//H·Ii+1 20
	eor	v17.16b,v17.16b,v7.16b		//Karatsuba pre-processing
.long	0x4ee7e286	//pmull2 v6.16b,v20.16b,v7.16b
	b	.Loop_mod2x_v8

.align	4
.Loop_mod2x_v8:
	ext	v18.16b,v3.16b,v3.16b,#8
	subs	x3,x3,#32		//is there more data?
.long	0x0ee3e2c0	//pmull v0.16b,v22.16b,v3.16b		//H^2.lo·Xi.lo 22
	csel	x12,xzr,x12,lo			//is it time to zero x12?

.long	0x0ef1e2a5	//pmull v5.16b,v21.16b,v17.16b 21
	eor	v18.16b,v18.16b,v3.16b		//Karatsuba pre-processing
.long	0x4ee3e2c2	//pmull2 v2.16b,v22.16b,v3.16b		//H^2.hi·Xi.hi
	eor	v0.16b,v0.16b,v4.16b		//accumulate
.long	0x4ef2e2a1	//pmull2 v1.16b,v21.16b,v18.16b		//(H^2.lo+H^2.hi)·(Xi.lo+Xi.hi)
	ld1	{v16.2d},[x2],x12	//load [rotated] I[i+2]

	eor	v2.16b,v2.16b,v6.16b
	csel	x12,xzr,x12,eq			//is it time to zero x12?
	eor	v1.16b,v1.16b,v5.16b

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v17.2d},[x2],x12	//load [rotated] I[i+3]
#ifndef __ARMEB__
	rev64	v16.16b,v16.16b
#endif
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0

#ifndef __ARMEB__
	rev64	v17.16b,v17.16b
#endif
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v7.16b,v17.16b,v17.16b,#8
	ext	v3.16b,v16.16b,v16.16b,#8
	eor	v0.16b,v1.16b,v18.16b
.long	0x0ee7e284	//pmull v4.16b,v20.16b,v7.16b		//H·Ii+1 20
	eor	v3.16b,v3.16b,v2.16b		//accumulate v3.16b early

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v3.16b,v3.16b,v18.16b
	eor	v17.16b,v17.16b,v7.16b		//Karatsuba pre-processing
	eor	v3.16b,v3.16b,v0.16b
.long	0x4ee7e286	//pmull2 v6.16b,v20.16b,v7.16b
	b.hs	.Loop_mod2x_v8		//there was at least 32 more bytes

	eor	v2.16b,v2.16b,v18.16b
	ext	v3.16b,v16.16b,v16.16b,#8		//re-construct v3.16b
	adds	x3,x3,#32		//re-construct x3
	eor	v0.16b,v0.16b,v2.16b		//re-construct v0.16b
	b.eq	.Ldone_v8		//is x3 zero?
.Lodd_tail_v8:
	ext	v18.16b,v0.16b,v0.16b,#8
	eor	v3.16b,v3.16b,v0.16b		//inp^=Xi
	eor	v17.16b,v16.16b,v18.16b		//v17.16b is rotated inp^Xi

.long	0x0ee3e280	//pmull v0.16b,v20.16b,v3.16b		//H.lo·Xi.lo 20
	eor	v17.16b,v17.16b,v3.16b		//Karatsuba pre-processing
.long	0x4ee3e282	//pmull2 v2.16b,v20.16b,v3.16b		//H.hi·Xi.hi
.long	0x0ef1e2a1	//pmull v1.16b,v21.16b,v17.16b		//(H.lo+H.hi)·(Xi.lo+Xi.hi) 21

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b

.Ldone_v8:
#ifndef __ARMEB__
	rev64	v0.16b,v0.16b
#endif
	ext	v0.16b,v0.16b,v0.16b,#8
	st1	{v0.2d},[x0]		//write out Xi

	ret
#endif

#if 0
.align	4
gcm_ghash_v8_4x:
.Lgcm_ghash_v8_4x:
	ld1	{v0.2d},[x0]		//load [rotated] Xi
	ld1	{v20.2d,v21.2d,v22.2d},[x1],#48	//load twisted H, ..., H^2
	movi	v19.16b,#0xe1
	ld1	{v26.2d,v27.2d,v28.2d},[x1]	//load twisted H^3, ..., H^4
	shl	v19.2d,v19.2d,#57		//compose 0xc2.0 constant

	ld1	{v4.2d,v5.2d,v6.2d,v7.2d},[x2],#64
#ifndef __ARMEB__
	rev64	v0.16b,v0.16b
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v7.16b,v7.16b
	rev64	v4.16b,v4.16b
#endif
	ext	v25.16b,v7.16b,v7.16b,#8
	ext	v24.16b,v6.16b,v6.16b,#8
	ext	v23.16b,v5.16b,v5.16b,#8

.long	0x0ef9e29d	//pmull v29.16b,v20.16b,v25.16b		//H·Ii+3 20
	eor	v7.16b,v7.16b,v25.16b
.long	0x4ef9e29f	//pmull2 v31.16b,v20.16b,v25.16b
.long	0x0ee7e2be	//pmull v30.16b,v21.16b,v7.16b 21

.long	0x0ef8e2d0	//pmull v16.16b,v22.16b,v24.16b		//H^2·Ii+2 22
	eor	v6.16b,v6.16b,v24.16b
.long	0x4ef8e2d8	//pmull2 v24.16b,v22.16b,v24.16b
.long	0x4ee6e2a6	//pmull2 v6.16b,v21.16b,v6.16b

	eor	v29.16b,v29.16b,v16.16b
	eor	v31.16b,v31.16b,v24.16b
	eor	v30.16b,v30.16b,v6.16b

.long	0x0ef7e347	//pmull v7.16b,v26.16b,v23.16b		//H^3·Ii+1 26
	eor	v5.16b,v5.16b,v23.16b
.long	0x4ef7e357	//pmull2 v23.16b,v26.16b,v23.16b
.long	0x0ee5e365	//pmull v5.16b,v27.16b,v5.16b 27

	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	eor	v30.16b,v30.16b,v5.16b

	subs	x3,x3,#128
	b.lo	.Ltail4x

	b	.Loop4x

.align	4
.Loop4x:
	eor	v16.16b,v4.16b,v0.16b
	ld1	{v4.2d,v5.2d,v6.2d,v7.2d},[x2],#64
	ext	v3.16b,v16.16b,v16.16b,#8
#ifndef __ARMEB__
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v7.16b,v7.16b
	rev64	v4.16b,v4.16b
#endif

.long	0x0ee3e380	//pmull v0.16b,v28.16b,v3.16b		//H^4·(Xi+Ii) 28
	eor	v16.16b,v16.16b,v3.16b
.long	0x4ee3e382	//pmull2 v2.16b,v28.16b,v3.16b
	ext	v25.16b,v7.16b,v7.16b,#8
.long	0x4ef0e361	//pmull2 v1.16b,v27.16b,v16.16b

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	ext	v24.16b,v6.16b,v6.16b,#8
	eor	v1.16b,v1.16b,v30.16b
	ext	v23.16b,v5.16b,v5.16b,#8

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
.long	0x0ef9e29d	//pmull v29.16b,v20.16b,v25.16b		//H·Ii+3 20
	eor	v7.16b,v7.16b,v25.16b
	eor	v1.16b,v1.16b,v17.16b
.long	0x4ef9e29f	//pmull2 v31.16b,v20.16b,v25.16b
	eor	v1.16b,v1.16b,v18.16b
.long	0x0ee7e2be	//pmull v30.16b,v21.16b,v7.16b 21

.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
.long	0x0ef8e2d0	//pmull v16.16b,v22.16b,v24.16b		//H^2·Ii+2 22
	eor	v6.16b,v6.16b,v24.16b
.long	0x4ef8e2d8	//pmull2 v24.16b,v22.16b,v24.16b
	eor	v0.16b,v1.16b,v18.16b
.long	0x4ee6e2a6	//pmull2 v6.16b,v21.16b,v6.16b

	eor	v29.16b,v29.16b,v16.16b
	eor	v31.16b,v31.16b,v24.16b
	eor	v30.16b,v30.16b,v6.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
.long	0x0ef7e347	//pmull v7.16b,v26.16b,v23.16b		//H^3·Ii+1 26
	eor	v5.16b,v5.16b,v23.16b
	eor	v18.16b,v18.16b,v2.16b
.long	0x4ef7e357	//pmull2 v23.16b,v26.16b,v23.16b
.long	0x0ee5e365	//pmull v5.16b,v27.16b,v5.16b 27

	eor	v0.16b,v0.16b,v18.16b
	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	ext	v0.16b,v0.16b,v0.16b,#8
	eor	v30.16b,v30.16b,v5.16b

	subs	x3,x3,#64
	b.hs	.Loop4x

.Ltail4x:
	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

.long	0x0ee3e380	//pmull v0.16b,v28.16b,v3.16b		//H^4·(Xi+Ii) 28
	eor	v16.16b,v16.16b,v3.16b
.long	0x4ee3e382	//pmull2 v2.16b,v28.16b,v3.16b
.long	0x4ef0e361	//pmull2 v1.16b,v27.16b,v16.16b

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b

	adds	x3,x3,#64
	b.eq	.Ldone4x

	cmp	x3,#32
	b.lo	.Lone
	b.eq	.Ltwo
.Lthree:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d,v5.2d,v6.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__ARMEB__
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v4.16b,v4.16b
#endif

.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v24.16b,v6.16b,v6.16b,#8
	ext	v23.16b,v5.16b,v5.16b,#8
	eor	v0.16b,v1.16b,v18.16b

.long	0x0ef8e29d	//pmull v29.16b,v20.16b,v24.16b		//H·Ii+2 20
	eor	v6.16b,v6.16b,v24.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
.long	0x4ef8e29f	//pmull2 v31.16b,v20.16b,v24.16b
.long	0x0ee6e2be	//pmull v30.16b,v21.16b,v6.16b 21
	eor	v0.16b,v0.16b,v18.16b
.long	0x0ef7e2c7	//pmull v7.16b,v22.16b,v23.16b		//H^2·Ii+1 22
	eor	v5.16b,v5.16b,v23.16b
	ext	v0.16b,v0.16b,v0.16b,#8

.long	0x4ef7e2d7	//pmull2 v23.16b,v22.16b,v23.16b
	eor	v16.16b,v4.16b,v0.16b
.long	0x4ee5e2a5	//pmull2 v5.16b,v21.16b,v5.16b
	ext	v3.16b,v16.16b,v16.16b,#8

	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	eor	v30.16b,v30.16b,v5.16b

.long	0x0ee3e340	//pmull v0.16b,v26.16b,v3.16b		//H^3·(Xi+Ii) 26
	eor	v16.16b,v16.16b,v3.16b
.long	0x4ee3e342	//pmull2 v2.16b,v26.16b,v3.16b
.long	0x0ef0e361	//pmull v1.16b,v27.16b,v16.16b 27

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b
	b	.Ldone4x

.align	4
.Ltwo:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d,v5.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__ARMEB__
	rev64	v5.16b,v5.16b
	rev64	v4.16b,v4.16b
#endif

.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v23.16b,v5.16b,v5.16b,#8
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

.long	0x0ef7e29d	//pmull v29.16b,v20.16b,v23.16b		//H·Ii+1 20
	eor	v5.16b,v5.16b,v23.16b

	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

.long	0x4ef7e29f	//pmull2 v31.16b,v20.16b,v23.16b
.long	0x0ee5e2be	//pmull v30.16b,v21.16b,v5.16b 21

.long	0x0ee3e2c0	//pmull v0.16b,v22.16b,v3.16b		//H^2·(Xi+Ii) 22
	eor	v16.16b,v16.16b,v3.16b
.long	0x4ee3e2c2	//pmull2 v2.16b,v22.16b,v3.16b
.long	0x4ef0e2a1	//pmull2 v1.16b,v21.16b,v16.16b

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b
	b	.Ldone4x

.align	4
.Lone:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__ARMEB__
	rev64	v4.16b,v4.16b
#endif

.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

.long	0x0ee3e280	//pmull v0.16b,v20.16b,v3.16b 20
	eor	v16.16b,v16.16b,v3.16b
.long	0x4ee3e282	//pmull2 v2.16b,v20.16b,v3.16b
.long	0x0ef0e2a1	//pmull v1.16b,v21.16b,v16.16b 21

.Ldone4x:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b

.long	0x0ef3e012	//pmull v18.16b,v0.16b,v19.16b		//1st phase of reduction 0
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
.long	0x0ef3e000	//pmull v0.16b,v0.16b,v19.16b 0
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

#ifndef __ARMEB__
	rev64	v0.16b,v0.16b
#endif
	st1	{v0.2d},[x0]		//write out Xi

	ret
#endif

.byte	71,72,65,83,72,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
.align	2

LC_ASM_END
