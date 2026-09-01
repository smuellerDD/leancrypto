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

#ifndef sntrup_int32_h
#define sntrup_int32_h

#include "ext_headers_internal.h"
#include "null_buffer.h"

static inline int32_t sntrup_int32_negative_mask(int32_t sntrup_int32_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("sarl $31,%0" : "+r"(sntrup_int32_x) : : "cc");
	return sntrup_int32_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int32_t sntrup_int32_y;
	__asm__("asr %w0,%w1,31"
		: "=r"(sntrup_int32_y)
		: "r"(sntrup_int32_x)
		:);
	return sntrup_int32_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int32_t sntrup_int32_y;
	__asm__("asr %0,%1,#31" : "=r"(sntrup_int32_y) : "r"(sntrup_int32_x) :);
	return sntrup_int32_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int32_t sntrup_int32_y;
	__asm__("sra %1,31,%0" : "=r"(sntrup_int32_y) : "r"(sntrup_int32_x) :);
	return sntrup_int32_y;
#else
	sntrup_int32_x >>= 32 - 6;
	sntrup_int32_x += (int32_t)optimization_blocker_uint64;
	sntrup_int32_x >>= 5;
	return sntrup_int32_x;
#endif
}

static inline int32_t sntrup_int32_min(int32_t sntrup_int32_x,
				       int32_t sntrup_int32_y)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("cmpl %1,%0\n cmovgl %1,%0"
		: "+r"(sntrup_int32_x)
		: "r"(sntrup_int32_y)
		: "cc");
	return sntrup_int32_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	__asm__("cmp %w0,%w1\n csel %w0,%w0,%w1,lt"
		: "+r"(sntrup_int32_x)
		: "r"(sntrup_int32_y)
		: "cc");
	return sntrup_int32_x;
#else
	int32_t sntrup_int32_r = sntrup_int32_y ^ sntrup_int32_x;
	int32_t sntrup_int32_z = sntrup_int32_y - sntrup_int32_x;
	sntrup_int32_z ^= sntrup_int32_r & (sntrup_int32_z ^ sntrup_int32_y);
	sntrup_int32_z = sntrup_int32_negative_mask(sntrup_int32_z);
	sntrup_int32_z &= sntrup_int32_r;
	return sntrup_int32_x ^ sntrup_int32_z;
#endif
}

static inline void sntrup_int32_minmax(int32_t *sntrup_int32_p,
				       int32_t *sntrup_int32_q)
{
	int32_t sntrup_int32_x = *sntrup_int32_p;
	int32_t sntrup_int32_y = *sntrup_int32_q;
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	int32_t sntrup_int32_z;
	__asm__("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2"
		: "=&r"(sntrup_int32_z), "+&r"(sntrup_int32_x),
		  "+r"(sntrup_int32_y)
		:
		: "cc");
	*sntrup_int32_p = sntrup_int32_x;
	*sntrup_int32_q = sntrup_int32_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int32_t sntrup_int32_r, sntrup_int32_s;
	__asm__("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt"
		: "=&r"(sntrup_int32_r), "=r"(sntrup_int32_s)
		: "r"(sntrup_int32_x), "r"(sntrup_int32_y)
		: "cc");
	*sntrup_int32_p = sntrup_int32_r;
	*sntrup_int32_q = sntrup_int32_s;
#else
	int32_t sntrup_int32_r = sntrup_int32_y ^ sntrup_int32_x;
	int32_t sntrup_int32_z = sntrup_int32_y - sntrup_int32_x;
	sntrup_int32_z ^= sntrup_int32_r & (sntrup_int32_z ^ sntrup_int32_y);
	sntrup_int32_z = sntrup_int32_negative_mask(sntrup_int32_z);
	sntrup_int32_z &= sntrup_int32_r;
	sntrup_int32_x ^= sntrup_int32_z;
	sntrup_int32_y ^= sntrup_int32_z;
	*sntrup_int32_p = sntrup_int32_x;
	*sntrup_int32_q = sntrup_int32_y;
#endif
}

#endif
