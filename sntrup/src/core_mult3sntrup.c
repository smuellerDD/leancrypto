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

/* works for -16384 <= x < 16384 */
static small F3_freeze(int16_t x)
{
	return (small)(x - 3 * ((10923 * x + 16384) >> 15));
}

void sntrup_core_mult3(uint8_t *outbytes, const uint8_t *inbytes,
		       const uint8_t *kbytes, const uint8_t *cbytes,
		       struct ws_core_mutl3 *ws)
{
	small *h = (small *)outbytes;
	unsigned int i, j;

	(void)cbytes;

	for (i = 0; i < p; ++i) {
		small fi = (small)inbytes[i];
		small fi0 = sntrup_int8_bottombit_01(fi);
		ws->f[i] = (small)(fi0 - (fi & (fi0 << 1)));
	}
	for (i = 0; i < p; ++i) {
		small gi = (small)kbytes[i];
		small gi0 = sntrup_int8_bottombit_01(gi);
		ws->g[i] = gi0 - (small)(gi & (gi0 << 1));
	}

	//TODO memset(0)
	for (i = 0; i < p + p - 1; ++i)
		ws->fg[i] = 0;
	for (i = 0; i < p; ++i)
		for (j = 0; j < p; ++j)
			ws->fg[i + j] +=
				(int16_t)(ws->f[i] * (int16_t)ws->g[j]);
	for (i = p; i < p + p - 1; ++i)
		ws->fg[i - p] += ws->fg[i];
	for (i = p; i < p + p - 1; ++i)
		ws->fg[i - p + 1] += ws->fg[i];
	for (i = 0; i < p; ++i)
		h[i] = F3_freeze(ws->fg[i]);
}
