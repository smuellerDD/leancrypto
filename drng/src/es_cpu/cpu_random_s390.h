/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "bool.h"

#define ESDM_CPU_ES_IMPLEMENTED

/* Function code 114 as per Principles of Operation */
#define CPACF_PRNO_TRNG 0x72
#define CPACF_PRNO 0xb93c /* MSA5 */

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
	cpacf_trng(NULL, 0, (uint8_t *)buf, sizeof(unsigned long));
	return true;
}

static inline unsigned int cpu_es_multiplier(void)
{
	return 1;
}

#endif

#endif /* _CPU_RANDOM_S390 */
