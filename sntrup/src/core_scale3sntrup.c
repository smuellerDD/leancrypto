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
#include "sntrup_int16.h"

/* out = 3*in in Rq */
void sntrup_core_scale3(uint8_t *outbytes, const uint8_t *inbytes,
			const uint8_t *kbytes, const uint8_t *cbytes,
			struct ws_core_scale3 *ws)
{
	unsigned int i;

	(void)kbytes;
	(void)cbytes;

	sntrup_decode_pxint16(ws->f, inbytes);
	for (i = 0; i < p; ++i) {
		Fq x = ws->f[i];
		x *= 3; /* (-3q+3)/2 ... (3q-3)/2 */
		x -= (q + 1) / 2; /* -2q+1 ... q-2 */
		x += (Fq)(q & sntrup_int16_negative_mask(x)); /* -q+1 ... q-1 */
		x += (Fq)(q & sntrup_int16_negative_mask(x)); /* 0 ... q-1 */
		x -= (q - 1) / 2; /* -(q-1)/2 ... (q-1)/2 */
		ws->f[i] = x;
	}
	sntrup_encode_pxint16(outbytes, ws->f);
}
