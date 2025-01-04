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

#ifndef _CPU_RANDOM_POWERPC
#define _CPU_RANDOM_POWERPC

#if defined(__powerpc__)

#include "bool.h"

#define ESDM_CPU_ES_IMPLEMENTED

#define PPC_DARN_ERR 0xFFFFFFFFFFFFFFFFul
static inline bool cpu_es_get(unsigned long *buf)
{
	unsigned long val;
	unsigned int i;

	/*
	 * Using DARN with
	 * L=0 - 32-bit conditioned random number
	 * L=1 - 64-bit conditioned random number
	 * L=2 - 64-bit unconditioned random number
	 */
	for (i = 0; i < 10; i++) {
		__asm__ __volatile__("darn %0, 1" : "=r"(val));

		if (val != PPC_DARN_ERR) {
			*buf = val;
			return true;
		}
	}

	return false;
}

static inline unsigned int cpu_es_multiplier(void)
{
	/*
	 * PowerISA defines DARN to deliver at least 0.5 bits of
	 * entropy per data bit.
	 */
	return 2;
}

#endif

#endif /* _CPU_RANDOM_POWERPC */
