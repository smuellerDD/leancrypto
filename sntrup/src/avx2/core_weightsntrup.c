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
#include "sntrup_encode_int16.h"
#include "params.h"

/* out = little-endian weight of bottom bits of in */
void sntrup_core_weight_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			     const uint8_t *kbytes, const uint8_t *cbytes)
{
	int8_t *in = (int8_t *)inbytes;
	int i;
	__m256i sum, sumhi;
	int16_t weight;

	(void)kbytes;
	(void)cbytes;

	/*
	 * LC_FPU_ENABLE/DISABLE not needed here as this function is already
	 * called by a function that has LC_FPU_ENABLE guards.
	 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	sum = _mm256_loadu_si256((__m256i *)(in + p - 32));
	sum &= endingmask;

	for (i = p - 32; i >= 0; i -= 32) {
		__m256i bits = _mm256_loadu_si256((__m256i *)in);
		bits &= _mm256_set1_epi8(1);
		sum = _mm256_add_epi8(sum, bits);
		in += 32;
	}

	/* sum is 32xint8; want to add these int8 */
	sumhi = _mm256_srli_epi16(sum, 8);
	sum &= _mm256_set1_epi16(0xff);
	sum = _mm256_add_epi16(sum, sumhi);

	/* sum is 16xint16; want to add these int16 */
	sum = _mm256_hadd_epi16(sum, sum);
	/* want sum[0]+sum[1]+sum[2]+sum[3]+sum[8]+sum[9]+sum[10]+sum[11] */
	sum = _mm256_hadd_epi16(sum, sum);
	/* want sum[0]+sum[1]+sum[8]+sum[9] */
	sum = _mm256_hadd_epi16(sum, sum);
	/* want sum[0]+sum[8] */

	weight = (int16_t)_mm256_extract_epi16(sum, 0);
	weight += (int16_t)_mm256_extract_epi16(sum, 8);

	sntrup_encode_int16(outbytes, &weight);
#pragma GCC diagnostic pop
}
