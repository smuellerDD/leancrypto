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
#include "sntrup_int16.h"
#include "params.h"

int sntrup_verify_clen_avx2(const uint8_t *x, const uint8_t *y)
{
	__m256i diff = _mm256_set1_epi8(0);
	int differentbits = 0;
	int i = sntrup_verify_BYTES - 32;

	LC_FPU_ENABLE;

	for (;;) {
		do {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			__m256i x0 = _mm256_loadu_si256((__m256i *)x);
			__m256i y0 = _mm256_loadu_si256((__m256i *)y);
#pragma GCC diagnostic pop
			diff |= x0 ^ y0;
			i -= 32;
			x += 32;
			y += 32;
		} while (i >= 0);
		if (i <= -32)
			break;
		x += i;
		y += i;
	}

	diff |= _mm256_srli_epi16(diff, 8);
	diff |= _mm256_srli_epi32(diff, 16);
	diff |= _mm256_srli_epi64(diff, 32);

	differentbits = _mm256_extract_epi8(diff, 0);
	differentbits |= _mm256_extract_epi8(diff, 8);
	differentbits |= _mm256_extract_epi8(diff, 16);
	differentbits |= _mm256_extract_epi8(diff, 24);

	LC_FPU_DISABLE;

	return sntrup_int16_nonzero_mask((int16_t)differentbits);
}
