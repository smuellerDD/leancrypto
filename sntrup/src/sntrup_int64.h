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

#ifndef sntrup_int64_h
#define sntrup_int64_h

#include "ext_headers_internal.h"
#include "null_buffer.h"

static inline uint64_t sntrup_int64_unsigned_topbit_01(uint64_t sntrup_int64_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("shrq $63,%0" : "+r"(sntrup_int64_x) : : "cc");
	return sntrup_int64_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	uint64_t sntrup_int64_y;
	__asm__("lsr %0,%1,63" : "=r"(sntrup_int64_y) : "r"(sntrup_int64_x) :);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int64_t sntrup_int64_y;
	__asm__("lsr %Q0,%R1,#31\n mov %R0,#0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	uint64_t sntrup_int64_y;
	__asm__("srl %H1,31,%L0\n mov 0,%H0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#else
	sntrup_int64_x >>= 64 - 6;
	sntrup_int64_x += (int64_t)optimization_blocker_uint64;
	sntrup_int64_x >>= 5;
	return sntrup_int64_x;
#endif
}

static inline int64_t sntrup_int64_negative_01(int64_t sntrup_int64_x)
{
	return (int64_t)sntrup_int64_unsigned_topbit_01(
		(uint64_t)sntrup_int64_x);
}

static inline int64_t sntrup_int64_bottombit_mask(int64_t sntrup_int64_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("andq $1,%0" : "+r"(sntrup_int64_x) : : "cc");
	return -sntrup_int64_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int64_t sntrup_int64_y;
	__asm__("sbfx %0,%1,0,1"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int64_t sntrup_int64_y;
	__asm__("and %Q0,%Q1,#1\n neg %Q0,%Q0\n mov %R0,%Q0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int64_t sntrup_int64_y;
	__asm__("and %L1,1,%L0\n neg %L0,%L0\n mov %L0,%H0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#else
	sntrup_int64_x &= 1 + sntrup_int64_optblocker;
	return -sntrup_int64_x;
#endif
}

static inline int64_t sntrup_int64_bottombit_01(int64_t sntrup_int64_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("andq $1,%0" : "+r"(sntrup_int64_x) : : "cc");
	return sntrup_int64_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int64_t sntrup_int64_y;
	__asm__("ubfx %0,%1,0,1"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int64_t sntrup_int64_y;
	__asm__("and %Q0,%Q1,#1\n mov %R0,#0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int64_t sntrup_int64_y;
	__asm__("and %L1,1,%L0\n mov 0,%H0"
		: "=r"(sntrup_int64_y)
		: "r"(sntrup_int64_x)
		:);
	return sntrup_int64_y;
#else
	sntrup_int64_x &= 1 + sntrup_int64_optblocker;
	return sntrup_int64_x;
#endif
}

static inline int64_t
sntrup_int64_bitinrangepublicpos_mask(int64_t sntrup_int64_x,
				      int64_t sntrup_int64_s)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("sarq %%cl,%0"
		: "+r"(sntrup_int64_x)
		: "c"(sntrup_int64_s)
		: "cc");
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	__asm__("asr %0,%0,%1" : "+r"(sntrup_int64_x) : "r"(sntrup_int64_s) :);
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	__asm__("and %Q0,%Q0,#63\n lsr %Q1,%Q1,%Q0\n rsb %R0,%Q0,#32\n orr %Q1,%Q1,%R1,lsl %R0\n subs %R0,%Q0,#32\n orrhs %Q1,%Q1,%R1,asr %R0\n asr %R1,%R1,%Q0"
		: "+&r"(sntrup_int64_s), "+r"(sntrup_int64_x)
		:
		: "cc");
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int64_t sntrup_int64_y, sntrup_int64_z;
	__asm__("not %L0,%H0\n sll %L0,26,%H1\n sll %H3,1,%L1\n srl %L3,%L0,%L2\n sll %L1,%H0,%L1\n sra %H3,%L0,%H2\n sra %H1,31,%H1\n or %L2,%L1,%L2\n xor %L2,%H2,%L1\n and %H1,%L1,%L1\n sra %H2,%H1,%H3\n xor %L2,%L1,%L3"
		: "+&r"(sntrup_int64_s), "=&r"(sntrup_int64_z),
		  "=&r"(sntrup_int64_y), "+r"(sntrup_int64_x)
		:
		:);
#else
	sntrup_int64_x >>= sntrup_int64_s ^ sntrup_int64_optblocker;
#endif
	return sntrup_int64_bottombit_mask(sntrup_int64_x);
}

static inline int64_t sntrup_int64_shlmod(int64_t sntrup_int64_x,
					  int64_t sntrup_int64_s)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("shlq %%cl,%0"
		: "+r"(sntrup_int64_x)
		: "c"(sntrup_int64_s)
		: "cc");
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	__asm__("lsl %0,%0,%1" : "+r"(sntrup_int64_x) : "r"(sntrup_int64_s) :);
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	__asm__("and %Q0,%Q0,#63\n lsl %R1,%R1,%Q0\n sub %R0,%Q0,#32\n orr %R1,%R1,%Q1,lsl %R0\n rsb %R0,%Q0,#32\n orr %R1,%R1,%Q1,lsr %R0\n lsl %Q1,%Q1,%Q0"
		: "+&r"(sntrup_int64_s), "+r"(sntrup_int64_x)
		:
		:);
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int64_t sntrup_int64_y, sntrup_int64_z;
	__asm__("not %L0,%H0\n sll %L0,26,%H1\n srl %L3,1,%L1\n sll %L3,%L0,%L2\n srl %L1,%H0,%L1\n sll %H3,%L0,%H2\n sra %H1,31,%H1\n or %H2,%L1,%H2\n xor %L2,%H2,%L1\n and %H1,%L2,%L3\n and %H1,%L1,%L1\n xor %L3,%L2,%L3\n xor %H2,%L1,%H3"
		: "+&r"(sntrup_int64_s), "=&r"(sntrup_int64_z),
		  "=&r"(sntrup_int64_y), "+r"(sntrup_int64_x)
		:
		:);
#else
	int sntrup_int64_k, sntrup_int64_l;
	for (sntrup_int64_l = 0, sntrup_int64_k = 1; sntrup_int64_k < 64;
	     ++sntrup_int64_l, sntrup_int64_k *= 2)
		sntrup_int64_x ^=
			(sntrup_int64_x ^ (sntrup_int64_x << sntrup_int64_k)) &
			sntrup_int64_bitinrangepublicpos_mask(sntrup_int64_s,
							      sntrup_int64_l);
#endif
	return sntrup_int64_x;
}

#endif
