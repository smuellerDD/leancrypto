/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef _CPU_RANDOM_X86
#define _CPU_RANDOM_X86

#if defined(__x86_64__) || defined(__i386__)

#include "bool.h"

#define ESDM_CPU_ES_IMPLEMENTED

#define RDRAND_RETRY_LOOPS 10

#define RDRAND_INT ".byte 0x0f,0xc7,0xf0"
#define RDSEED_INT ".byte 0x0f,0xc7,0xf8"
#ifdef __LP64__
#define RDRAND_LONG ".byte 0x48,0x0f,0xc7,0xf0"
#define RDSEED_LONG ".byte 0x48,0x0f,0xc7,0xf8"
#else
#define RDRAND_LONG RDRAND_INT
#define RDSEED_LONG RDSEED_INT
#endif

#define ECX_RDRAND (1 << 30)
#define EXT_FEAT_EBX_RDSEED (1 << 18)

#define cpuid_eax(level, a, b, c, d)                                           \
	__asm__ __volatile__("cpuid\n\t"                                       \
			     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)              \
			     : "0"(level))

#define cpuid_eax_ecx(level, count, a, b, c, d)                                \
	__asm__ __volatile__("cpuid\n\t"                                       \
			     : "=a"(a), "=b"(b), "=c"(c), "=d"(d)              \
			     : "0"(level), "2"(count))

static inline int rdseed_available(void)
{
	unsigned int eax, ebx, ecx, edx;

	/* Read the maximum leaf */
	cpuid_eax(0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax >= 7) {
		/* read advanced features eax = 7, ecx = 0 */
		cpuid_eax_ecx(7, 0, eax, ebx, ecx, edx);

		return !!(ebx & EXT_FEAT_EBX_RDSEED);
	}
	return false;
}

static inline int rdrand_available(void)
{
	unsigned int eax, ebx, ecx, edx;

	/* Read the maximum leaf */
	cpuid_eax(0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax >= 1) {
		cpuid_eax(1, eax, ebx, ecx, edx);
		return !!(ecx & ECX_RDRAND);
	}

	return false;
}

static inline bool cpu_es_x86_rdseed(unsigned long *buf)
{
	unsigned int retry = 0;
	unsigned char ok;
	static int rdseed_avail = -1;

	if (rdseed_avail == -1) {
		rdseed_avail = rdseed_available();
	}
	if (!rdseed_avail)
		return false;

	do {
		__asm__ __volatile__(RDSEED_LONG "\n\t"
						 "setc %0"
				     : "=qm"(ok), "=a"(*buf));
	} while (!ok && retry++ > RDRAND_RETRY_LOOPS);

	return !!ok;
}

static inline bool cpu_es_x86_rdrand(unsigned long *buf)
{
	int ok;
	static int rdrand_avail = -1;

	if (rdrand_avail == -1) {
		rdrand_avail = rdrand_available();
	}
	if (!rdrand_avail)
		return false;

	__asm__ __volatile__("1: " RDRAND_LONG "\n\t"
			     "jc 2f\n\t"
			     "decl %0\n\t"
			     "jnz 1b\n\t"
			     "2:"
			     : "=r"(ok), "=a"(*buf)
			     : "0"(RDRAND_RETRY_LOOPS));
	return !!ok;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	bool ret = cpu_es_x86_rdseed(buf);

	if (!ret)
		return cpu_es_x86_rdrand(buf);
	return ret;
}

static inline unsigned int cpu_es_multiplier(void)
{
	unsigned long v;

	/* Invoke check twice in case the first time the gather loop failed */
	if (!cpu_es_x86_rdseed(&v) && !cpu_es_x86_rdseed(&v)) {
		/*
		 * Intel SPEC: pulling more than 511 128 Bit blocks from RDRAND ensures
		 * one reseed making it logically equivalent to RDSEED. So pull at least
		 * 1023 64 Bit sub-blocks.
		 */
		return 1024;
	}

	return 1;
}

#endif

#endif /* _CPU_RANDOM_X86 */
