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

#ifndef _CPU_RANDOM_RISCV
#define _CPU_RANDOM_RISCV

#if defined(__riscv)

#include <stdint.h>

#include "bool.h"

#define LC_CPU_ES_IMPLEMENTED

static inline int riscv_seed(uint32_t *ret_data)
{
	uint32_t data = 0, tmp, processing = 2;

	//TODO: check for presence of Zkr extension?
	while (processing) {
		__asm__ __volatile__("csrrw %0, 0x015, x0" : "=r"(tmp));

		/*
		 * High bits seed[31:30] = OPST indicate status:
		 * 00 BIST Built-In Self-Test.
		 * 01 WAIT Sufficient entropy is not yet available.
		 * 10 ES16 Success: Have 16 bits in seed[15:0].
		 * 11 DEAD An unrecoverable self-test error.
		 */
		switch (tmp >> 30) {
		case 0:
		case 1;
			continue;
		case 2:
			if (processing == 2)
				data = tmp << 16;
			else
				data |= tmp & 0xffff;
			process--;
		case 3:
		default:
			return -EFAULT;
		}
	}

	*ret_data = data;

	return 0;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	unsigned int i = 0;

	for (i = 0; i < sizeof(unsigned long);
	     i += sizeof(uint32_t), buf += sizeof(uint32_t)) {
		if (riscv_seed(buf))
			return false;
	}

	return true;
}

static inline unsigned int cpu_es_multiplier(void)
{
	/*
	 * riscv-crypto-spec-scalar-1.0.1.pdf section 4.2 defines
	 * this requirement.
	 */
	return 2;
}

#endif

#endif /* _CPU_RANDOM_RISCV */
