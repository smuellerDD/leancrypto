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

#ifndef _CPU_RANDOM_S390
#define _CPU_RANDOM_S390

#if defined(__s390__)

#include <stdint.h>
#include <sys/auxv.h>

#include <stdbool.h>

#define ESDM_CPU_ES_IMPLEMENTED

/* Function code 114 as per Principles of Operation */
#define CPACF_PRNO_TRNG 0x72
#define CPACF_PRNO 0xb93c /* MSA5 */

#ifndef HWCAP_S390_STFLE
#define HWCAP_S390_STFLE 4
#endif

/* Store-facility-list-extended: test facility bit @nr (MSB-first numbering) */
static inline bool s390_facility(unsigned int nr)
{
	uint64_t list[4] = { 0 };
	register unsigned long r0 __asm__("0") =
		sizeof(list) / sizeof(list[0]) - 1;

	if (!(getauxval(AT_HWCAP) & HWCAP_S390_STFLE))
		return false;

	__asm__ __volatile__("	.insn	s,0xb2b00000,%[list]\n" /* stfle */
			     : [list] "+Q"(list[0]), [reg0] "+d"(r0)
			     :
			     : "cc", "memory");

	if (nr >= sizeof(list) * 8)
		return false;
	return (list[nr / 64] >> (63 - (nr % 64))) & 1;
}

static inline bool cpacf_prno_trng_query(void)
{
	uint8_t mask[16];
	register unsigned long r0 __asm__("0") = 0; /* query function code */
	register unsigned long r1 __asm__("1") = (unsigned long)mask;

	/*
	 * PRNO requires MSA extension 5 (facility 57); without it even the
	 * query form of the instruction raises an operation exception.
	 */
	if (!s390_facility(57))
		return false;

	__asm__ __volatile__("	.insn	rre,0xb93c0000,2,4\n" /* PRNO query */
			     :
			     : "d"(r0), "d"(r1)
			     : "cc", "r2", "r4", "memory");

	return (mask[CPACF_PRNO_TRNG >> 3] & (0x80 >> (CPACF_PRNO_TRNG & 7))) !=
	       0;
}

static inline bool cpacf_prno_trng_available(void)
{
	/*
	 * Plain static cache: a concurrent first call recomputes the same
	 * value, matching the detection caching in cpu_random_arm.h.
	 */
	static int avail = -1;

	if (avail < 0)
		avail = cpacf_prno_trng_query() ? 1 : 0;
	return avail == 1;
}

/**
 * cpacf_trng() - executes the TRNG subfunction of the PRNO instruction
 * @ucbuf: buffer for unconditioned data
 * @ucbuf_len: amount of unconditioned data to fetch in bytes
 * @cbuf: buffer for conditioned data
 * @cbuf_len: amount of conditioned data to fetch in bytes
 */
static inline void cpacf_trng(uint8_t *ucbuf, unsigned long ucbuf_len,
			      uint8_t *cbuf, unsigned long cbuf_len)
{
	register unsigned long r0 asm("0") = (unsigned long)CPACF_PRNO_TRNG;
	register unsigned long r2 asm("2") = (unsigned long)ucbuf;
	register unsigned long r3 asm("3") = (unsigned long)ucbuf_len;
	register unsigned long r4 asm("4") = (unsigned long)cbuf;
	register unsigned long r5 asm("5") = (unsigned long)cbuf_len;

	__asm__ __volatile__(
		"0:	.insn	rre,%[opc] << 16,%[ucbuf],%[cbuf]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [ucbuf] "+a"(r2), [ucbuflen] "+d"(r3), [cbuf] "+a"(r4),
		  [cbuflen] "+d"(r5)
		: [fc] "d"(r0), [opc] "i"(CPACF_PRNO)
		: "cc", "memory");
}

static inline bool cpu_es_get(unsigned long *buf)
{
	/*
	 * Executing PRNO-TRNG without the facility present raises an operation
	 * exception (SIGILL); degrade to claiming no entropy instead.
	 */
	if (!cpacf_prno_trng_available())
		return false;

	cpacf_trng(NULL, 0, (uint8_t *)buf, sizeof(unsigned long));
	return true;
}

static inline unsigned int cpu_es_multiplier(void)
{
	return 1;
}

#endif

#endif /* _CPU_RANDOM_S390 */
