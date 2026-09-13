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

#include "ext_headers_x86.h"
#include "sntrup_decode_int16.h"
#include "sntrup_int16.h"
#include "params.h"

/* out = in if bottom bits of in have weight w */
/* otherwise out = (1,1,...,1,0,0,...,0) */
void sntrup_core_wforce_avx2(uint8_t *out, const uint8_t *in,
			     const uint8_t *kbytes, const uint8_t *cbytes)
{
	int16_t weight;
	int16_t mask;
	__m256i maskvec;
	int i;

	(void)kbytes;
	(void)cbytes;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	sntrup_core_weight_avx2((uint8_t *)&weight, in, 0, 0);
	sntrup_decode_int16(&weight, (uint8_t *)&weight);

	mask = sntrup_int16_equal_mask(weight, w);
	maskvec = _mm256_set1_epi16(mask);

	i = w - 32;
	for (;;) {
		do {
			__m256i x = _mm256_loadu_si256((__m256i *)in);
			x ^= _mm256_set1_epi8(1);
			x &= maskvec;
			x ^= _mm256_set1_epi8(1);
			_mm256_storeu_si256((__m256i *)out, x);
			in += 32;
			out += 32;
			i -= 32;
		} while (i >= 0);
		if (i <= -32)
			break;
		in += i;
		out += i;
	}

	i = p - w - 32;
	for (;;) {
		do {
			__m256i x = _mm256_loadu_si256((__m256i *)in);
			x &= maskvec;
			_mm256_storeu_si256((__m256i *)out, x);
			in += 32;
			out += 32;
			i -= 32;
		} while (i >= 0);
		if (i <= -32)
			break;
		in += i;
		out += i;
	}

	LC_FPU_DISABLE;

#pragma GCC diagnostic pop
}
