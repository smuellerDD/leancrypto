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

void sntrup_encode_857x5167(uint8_t *out, const void *v)
{
	const int16_t *R0 = (const int16_t *)v;
	/* XXX: caller could overlap R with input */
	uint16_t R[429];
	long i;
	uint16_t r0, r1;
	uint32_t r2;

	for (i = 0; i < 428; ++i) {
		r0 = (R0[2 * i] + 2583) & 16383;
		r1 = (R0[2 * i + 1] + 2583) & 16383;
		r2 = r0 + r1 * (uint32_t)5167;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[428] = (R0[856] + 2583) & 16383;

	for (i = 0; i < 214; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)408;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[214] = R[428];

	for (i = 0; i < 107; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)651;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[107] = R[214];

	for (i = 0; i < 53; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)1656;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	r0 = R[106];
	r1 = R[107];
	r2 = r0 + r1 * (uint32_t)1656;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[53] = (uint16_t)r2;

	for (i = 0; i < 26; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)10713;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	r0 = R[52];
	r1 = R[53];
	r2 = r0 + r1 * (uint32_t)10713;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[26] = (uint16_t)r2;

	for (i = 0; i < 13; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)1752;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[13] = R[26];

	for (i = 0; i < 7; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)11991;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 3; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)2194;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[3] = R[6];

	r0 = R[0];
	r1 = R[1];
	r2 = r0 + r1 * (uint32_t)74;
	R[0] = (uint16_t)r2;
	r0 = R[2];
	r1 = R[3];
	r2 = r0 + r1 * (uint32_t)74;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[1] = (uint16_t)r2;

	r0 = R[0];
	r1 = R[1];
	r2 = r0 + r1 * (uint32_t)5476;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[0] = (uint16_t)r2;

	r0 = R[0];
	*out++ = (uint8_t)r0;
	r0 >>= 8;
	*out++ = (uint8_t)r0;
}
