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

#ifndef sntrup_int8_h
#define sntrup_int8_h

#include "ext_headers_internal.h"
#include "null_buffer.h"

static inline int8_t sntrup_int8_bottombit_01(int8_t sntrup_int8_x)
{
#if (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&      \
	defined(__x86_64__)
	__asm__("andb $1,%0" : "+r"(sntrup_int8_x) : : "cc");
	return sntrup_int8_x;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__aarch64__)
	int8_t sntrup_int8_y;
	__asm__("ubfx %w0,%w1,0,1"
		: "=r"(sntrup_int8_y)
		: "r"(sntrup_int8_x)
		:);
	return sntrup_int8_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__arm__) && defined(__ARM_ARCH) && (__ARM_ARCH >= 6) &&        \
	!defined(__thumb__)
	int8_t sntrup_int8_y;
	__asm__("and %0,%1,#1" : "=r"(sntrup_int8_y) : "r"(sntrup_int8_x) :);
	return sntrup_int8_y;
#elif (defined(__GNUASM__) || (defined(__GNUC__) && !defined(__FILC__))) &&    \
	defined(__sparc_v8__)
	int8_t sntrup_int8_y;
	__asm__("and %1,1,%0" : "=r"(sntrup_int8_y) : "r"(sntrup_int8_x) :);
	return sntrup_int8_y;
#else
	sntrup_int8_x &= 1 + (int8_t)optimization_blocker_uint64;
	return sntrup_int8_x;
#endif
}

#endif
