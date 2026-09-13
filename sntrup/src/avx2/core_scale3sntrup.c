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
#include "sntrup_int64.h"
#include "sntrup_uint64.h"
#include "params.h"

/* out = 3*in in Rq */
void sntrup_core_scale3_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			     const uint8_t *kbytes, const uint8_t *cbytes,
			     struct ws_core_scale3 *ws_full)
{
	struct ws_core_scale3_avx2 *ws = &ws_full->u.avx2;
	int i = p - 16;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	ws->save = _mm256_loadu_si256((__m256i *)(inbytes + 2 * i));
	/* in case outbytes = inbytes */

	(void)kbytes;
	(void)cbytes;

	for (;;) {
		do {
			ws->x = _mm256_loadu_si256((__m256i *)inbytes);
			ws->x = _mm256_mullo_epi16(ws->x, _mm256_set1_epi16(3));
			ws->x = _mm256_sub_epi16(
				ws->x, _mm256_set1_epi16((q + 1) / 2));
			ws->xneg = _mm256_srai_epi16(ws->x, 15);
			ws->x = _mm256_add_epi16(ws->x, _mm256_set1_epi16(q) &
								ws->xneg);
			ws->xneg = _mm256_srai_epi16(ws->x, 15);
			ws->x = _mm256_add_epi16(ws->x, _mm256_set1_epi16(q) &
								ws->xneg);
			ws->x = _mm256_sub_epi16(
				ws->x, _mm256_set1_epi16((q - 1) / 2));
			_mm256_storeu_si256((__m256i *)outbytes, ws->x);

			inbytes += 32;
			outbytes += 32;
			i -= 16;
		} while (i >= 0);
		if (i <= -16)
			break;
		inbytes += 2 * i;
		outbytes += 2 * i;
		_mm256_storeu_si256((__m256i *)outbytes, ws->save);
	}

	LC_FPU_DISABLE;
#pragma GCC diagnostic pop
}
