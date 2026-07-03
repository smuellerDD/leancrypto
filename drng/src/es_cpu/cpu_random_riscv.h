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

#ifndef _CPU_RANDOM_RISCV
#define _CPU_RANDOM_RISCV

#if defined(__riscv)

#include <stdint.h>

#include "bool.h"

#define LC_CPU_ES_IMPLEMENTED

/*
 * Number of times to re-read the seed CSR while it reports WAIT (entropy not
 * yet available). BIST/DEAD are treated as hard failures.
 */
#define RISCV_SEED_RETRY_LOOPS 1024

/*
 * Read one 16-bit entropy sample from the RISC-V Zkr "seed" CSR (0x015).
 *
 * A read returns the status OPST in bits [31:30] and, only when OPST == ES16
 * (0b10), 16 bits of entropy in bits [15:0]; the other bits are status/reserved
 * and must NOT be treated as entropy. Retry while OPST == WAIT (0b01); fail on
 * BIST (0b00) and DEAD (0b11).
 */
static inline bool riscv_seed16(uint16_t *out)
{
	unsigned int retry;

	for (retry = 0; retry < RISCV_SEED_RETRY_LOOPS; retry++) {
		unsigned long data;

		__asm__ __volatile__("csrrw %0, 0x015, x0" : "=r"(data));

		switch ((data >> 30) & 0x3) {
		case 0x2: /* ES16: 16 valid entropy bits in [15:0] */
			*out = (uint16_t)(data & 0xffff);
			return true;
		case 0x1: /* WAIT: entropy not ready, retry */
			continue;
		default: /* BIST (0b00) or DEAD (0b11): unusable */
			return false;
		}
	}

	return false;
}

static inline bool cpu_es_get(unsigned long *buf)
{
	uint16_t *out = (uint16_t *)buf;
	unsigned int i;

	/*
	 * Fill exactly one unsigned long with 16-bit ES16 entropy samples. The
	 * previous implementation dereferenced buf as unsigned long* (writing 8
	 * bytes per step) and advanced it by sizeof(uint32_t) *elements* (32
	 * bytes) rather than bytes, writing far past the caller's single
	 * unsigned long slot - an out-of-bounds write on rv64. It also used the
	 * raw CSR value (status + reserved bits) as entropy without checking
	 * OPST.
	 */
	for (i = 0; i < sizeof(unsigned long) / sizeof(uint16_t); i++) {
		if (!riscv_seed16(&out[i]))
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
