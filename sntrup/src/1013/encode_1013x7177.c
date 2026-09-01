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

void sntrup_encode_1013x7177(uint8_t *out, const void *v)
{
	const int16_t *R0 = (const int16_t *)v;
	/* XXX: caller could overlap R with input */
	uint16_t R[507];
	long i;
	uint16_t r0, r1;
	uint32_t r2;

	for (i = 0; i < 506; ++i) {
		r0 = (R0[2 * i] + 3588) & 16383;
		r1 = (R0[2 * i + 1] + 3588) & 16383;
		r2 = r0 + r1 * (uint32_t)7177;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[506] = (R0[1012] + 3588) & 16383;

	for (i = 0; i < 253; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)786;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[253] = R[506];

	for (i = 0; i < 127; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)2414;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 63; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)89;
		R[i] = (uint16_t)r2;
	}
	R[63] = R[126];

	for (i = 0; i < 31; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)7921;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	r0 = R[62];
	r1 = R[63];
	r2 = r0 + r1 * (uint32_t)7921;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[31] = (uint16_t)r2;

	for (i = 0; i < 15; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)958;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	r0 = R[30];
	r1 = R[31];
	r2 = r0 + r1 * (uint32_t)958;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[15] = (uint16_t)r2;

	for (i = 0; i < 7; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)3586;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	r0 = R[14];
	r1 = R[15];
	r2 = r0 + r1 * (uint32_t)3586;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[7] = (uint16_t)r2;

	for (i = 0; i < 4; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)197;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 2; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)152;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	r0 = R[0];
	r1 = R[1];
	r2 = r0 + r1 * (uint32_t)91;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[0] = (uint16_t)r2;

	r0 = R[0];
	*out++ = (uint8_t)r0;
	r0 >>= 8;
	*out++ = (uint8_t)r0;
}
