/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <cpuid.h>
#include <immintrin.h>

#include <stdbool.h>

#define LC_CPU_ES_IMPLEMENTED

#define RDRAND_RETRY_LOOPS 10

/*
 * RDSEED underflows routinely when the DRNG conditioner cannot refill the
 * seed queue as fast as it is drained - guaranteed to happen when pulling
 * many words back-to-back. This is a transient condition that clears within
 * microseconds, so per the Intel DRNG Software Implementation Guide retry
 * with PAUSE in between. The bound only exists to turn genuinely broken
 * hardware into a failure instead of a livelock.
 */
#define RDSEED_RETRY_LOOPS 1024

#define ECX_RDRAND (1 << 30)
#define EXT_FEAT_EBX_RDSEED (1 << 18)

static inline int rdseed_available(void)
{
	static int rdseed_avail = -1;
	unsigned int eax, ebx, ecx, edx;

	if (rdseed_avail > -1) {
		return rdseed_avail;
	}

	/* Read the maximum leaf */
	__cpuid(0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax >= 7) {
		/* read advanced features eax = 7, ecx = 0 */
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		rdseed_avail = !!(ebx & EXT_FEAT_EBX_RDSEED);
	} else {
		rdseed_avail = false;
	}

	return rdseed_avail;
}

static inline int rdrand_available(void)
{
	static int rdrand_avail = -1;
	unsigned int eax, ebx, ecx, edx;

	if (rdrand_avail > -1) {
		return rdrand_avail;
	}

	/* Read the maximum leaf */
	__cpuid(0, eax, ebx, ecx, edx);

	/* Only make call if the leaf is present */
	if (eax >= 1) {
		__cpuid(1, eax, ebx, ecx, edx);
		rdrand_avail = !!(ecx & ECX_RDRAND);
	} else {
		rdrand_avail = false;
	}

	return rdrand_avail;
}

#ifdef __x86_64__
__attribute__((target("rdseed"))) static inline int
lc_rdseed_step(unsigned long *buf)
{
	return _rdseed64_step((unsigned long long *)buf);
}

__attribute__((target("rdrnd"))) static inline int
lc_rdrand_step(unsigned long *buf)
{
	return _rdrand64_step((unsigned long long *)buf);
}
#else
__attribute__((target("rdseed"))) static inline int
lc_rdseed_step(unsigned long *buf)
{
	return _rdseed32_step((unsigned int *)buf);
}

__attribute__((target("rdrnd"))) static inline int
lc_rdrand_step(unsigned long *buf)
{
	return _rdrand32_step((unsigned int *)buf);
}
#endif

static inline bool cpu_es_x86_rdseed(unsigned long *buf)
{
	unsigned int retry = 0;

	if (!rdseed_available())
		return false;

	while (!lc_rdseed_step(buf)) {
		if (retry++ >= RDSEED_RETRY_LOOPS)
			return false;
		__builtin_ia32_pause();
	}

	return true;
}

static inline bool cpu_es_x86_rdrand(unsigned long *buf)
{
	unsigned int retry = 0;

	if (!rdrand_available())
		return false;

	while (!lc_rdrand_step(buf)) {
		if (retry++ >= RDRAND_RETRY_LOOPS)
			return false;
	}

	return true;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	/*
	 * perform no fallback between both options,
	 * as compression would be missing for rdrand,
	 * when rdseed was initially detected
	 */
	if (rdseed_available()) {
		return cpu_es_x86_rdseed(buf);
	}
	if (rdrand_available()) {
		return cpu_es_x86_rdrand(buf);
	}
	return false;
}

static inline unsigned int cpu_es_multiplier(void)
{
	unsigned long v;

	/* Invoke check twice in case the first time the gather loop failed */
	if (!cpu_es_x86_rdseed(&v) && !cpu_es_x86_rdseed(&v)) {
		/*
		 * Intel DRNG Software IG:
		 * pulling more than 511 128 Bit blocks from RDRAND ensures
		 * one reseed making it logically equivalent to RDSEED. So pull at least
		 * 1023 64 Bit sub-blocks.
		 *
		 * AMD uses AES CTR-DRBG with 256 bit keys for RDRAND
		 * Intel is not explicit in this document, so we have to assume
		 * AES CTR-DRBG with 128 bit keys for RDRAND. So double the
		 * amount of rounds for at least 2 128 bit seeds on every hardware.
		 *
		 * See:
		 * https://www.intel.com/content/www/us/en/content-details/864722/intel-digital-random-number-generator-software-implementation-guide.html
		 * https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/white-papers/amd-random-number-generator.pdf
		 */
		return 2 * 1024;
	}

	return 1;
}

#endif

#endif /* _CPU_RANDOM_X86 */
