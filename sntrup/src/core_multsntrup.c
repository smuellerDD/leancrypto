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

#include "params.h"
#include "sntrup_int8.h"

/* always represented as -(q-1)/2...(q-1)/2 */

/* works for -7000000 < x < 7000000 if q in 4591, 4621, 5167, 6343, 7177, 7879 */
static Fq Fq_freeze(int32_t x)
{
	x -= q * ((q18 * x) >> 18);
	x -= q * ((q27 * x + 67108864) >> 27);
	return (Fq)x;
}

void sntrup_core_mult(uint8_t *outbytes, const uint8_t *inbytes,
		      const uint8_t *kbytes, const uint8_t *cbytes,
		      struct ws_core_mult *ws)
{
	unsigned int i, j;

	(void)kbytes;
	(void)cbytes;

	sntrup_decode_pxint16(ws->f, inbytes);
	for (i = 0; i < p; ++i)
		ws->f32[i] = Fq_freeze(ws->f[i]);

	for (i = 0; i < p + p - 1; ++i)
		ws->fg[i] = 0;
	for (j = 0; j < p; ++j) {
		small gjx = (small)kbytes[j];
		small gj0 = sntrup_int8_bottombit_01(gjx);
		int32_t gj = gj0 - (gjx & (gj0 << 1));
		for (i = 0; i < p; ++i)
			ws->fg[i + j] += ws->f32[i] * gj;
	}
	for (i = p; i < p + p - 1; ++i)
		ws->fg[i - p] += ws->fg[i];
	for (i = p; i < p + p - 1; ++i)
		ws->fg[i - p + 1] += ws->fg[i];
	for (i = 0; i < p; ++i)
		ws->h[i] = Fq_freeze(ws->fg[i]);

	sntrup_encode_pxint16(outbytes, ws->h);
}
