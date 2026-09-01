/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The SNTRUP code is derived in parts from the code base
 * https://libntruprime.cr.yp.to/ which uses the following license:
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.; This is free software;
 * see the source for copying conditions. There is NO; warranty; not even for
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#ifndef sntrup_int16_h
#define sntrup_int16_h

#include "ext_headers_internal.h"
#include "null_buffer.h"

static inline int16_t sntrup_int16_negative_mask(int16_t sntrup_int16_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("sarw $15,%0" : "+r"(sntrup_int16_x) : : "cc");
	return sntrup_int16_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int16_t sntrup_int16_y;
	__asm__("sbfx %w0,%w1,15,1"
		: "=r"(sntrup_int16_y)
		: "r"(sntrup_int16_x)
		:);
	return sntrup_int16_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int16_t sntrup_int16_y;
	__asm__("sxth %0,%1\n asr %0,%0,#31"
		: "=r"(sntrup_int16_y)
		: "r"(sntrup_int16_x)
		:);
	return sntrup_int16_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int16_t sntrup_int16_y;
	__asm__("sll %1,16,%0\n sra %0,31,%0"
		: "=r"(sntrup_int16_y)
		: "r"(sntrup_int16_x)
		:);
	return sntrup_int16_y;
#else
	sntrup_int16_x >>= 16 - 6;
	sntrup_int16_x += (int16_t)optimization_blocker_uint64;
	sntrup_int16_x >>= 5;
	return sntrup_int16_x;
#endif
}

static inline int16_t sntrup_int16_nonzero_mask(int16_t sntrup_int16_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	int16_t sntrup_int16_q, sntrup_int16_z;
	__asm__("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0"
		: "=&r"(sntrup_int16_z), "=&r"(sntrup_int16_q)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int16_t sntrup_int16_z;
	__asm__("tst %w1,65535\n csetm %w0,ne"
		: "=r"(sntrup_int16_z)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	__asm__("uxth %0,%0\n cmp %0,#0\n movne %0,#-1"
		: "+r"(sntrup_int16_x)
		:
		: "cc");
	return sntrup_int16_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int16_t sntrup_int16_z;
	__asm__("sll %0,16,%0\n srl %0,16,%0\n cmp %%g0,%0\n subx %%g0,0,%1"
		: "+r"(sntrup_int16_x), "=r"(sntrup_int16_z)
		:
		: "cc");
	return sntrup_int16_z;
#else
	sntrup_int16_x |= -sntrup_int16_x;
	return sntrup_int16_negative_mask(sntrup_int16_x);
#endif
}

static inline int16_t sntrup_int16_positive_mask(int16_t sntrup_int16_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	int16_t sntrup_int16_q, sntrup_int16_z;
	__asm__("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0"
		: "=&r"(sntrup_int16_z), "=&r"(sntrup_int16_q)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int16_t sntrup_int16_z;
	__asm__("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt"
		: "=r"(sntrup_int16_z)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int16_t sntrup_int16_z;
	__asm__("sll %1,16,%0\n sra %0,31,%0\n sub %0,%1,%0\n sra %0,31,%0"
		: "=&r"(sntrup_int16_z)
		: "r"(sntrup_int16_x)
		:);
	return sntrup_int16_z;
#else
	int16_t sntrup_int16_z = -sntrup_int16_x;
	sntrup_int16_z ^= sntrup_int16_x & sntrup_int16_z;
	return sntrup_int16_negative_mask(sntrup_int16_z);
#endif
}

static inline int16_t sntrup_int16_zero_mask(int16_t sntrup_int16_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	int16_t sntrup_int16_q, sntrup_int16_z;
	__asm__("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0"
		: "=&r"(sntrup_int16_z), "=&r"(sntrup_int16_q)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int16_t sntrup_int16_z;
	__asm__("tst %w1,65535\n csetm %w0,eq"
		: "=r"(sntrup_int16_z)
		: "r"(sntrup_int16_x)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int16_t sntrup_int16_z;
	__asm__("sll %0,16,%0\n srl %0,16,%0\n cmp %%g0,%0\n addx %%g0,-1,%1"
		: "+r"(sntrup_int16_x), "=r"(sntrup_int16_z)
		:
		: "cc");
	return sntrup_int16_z;
#else
	return ~sntrup_int16_nonzero_mask(sntrup_int16_x);
#endif
}

static inline int16_t sntrup_int16_equal_mask(int16_t sntrup_int16_x,
					      int16_t sntrup_int16_y)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	int16_t sntrup_int16_q, sntrup_int16_z;
	__asm__("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0"
		: "=&r"(sntrup_int16_z), "=&r"(sntrup_int16_q)
		: "r"(sntrup_int16_x), "r"(sntrup_int16_y)
		: "cc");
	return sntrup_int16_z;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int16_t sntrup_int16_z;
	__asm__("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq"
		: "=&r"(sntrup_int16_z)
		: "r"(sntrup_int16_x), "r"(sntrup_int16_y)
		: "cc");
	return sntrup_int16_z;
#else
	return sntrup_int16_zero_mask(sntrup_int16_x ^ sntrup_int16_y);
#endif
}

#endif
