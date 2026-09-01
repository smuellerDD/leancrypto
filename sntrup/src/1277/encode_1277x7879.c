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

void sntrup_encode_1277x7879(uint8_t *out, const void *v)
{
	const int16_t *R0 = (const int16_t *)v;
	/* XXX: caller could overlap R with input */
	uint16_t R[639];
	long i;
	uint16_t r0, r1;
	uint32_t r2;

	for (i = 0; i < 638; ++i) {
		r0 = (R0[2 * i] + 3939) & 16383;
		r1 = (R0[2 * i + 1] + 3939) & 16383;
		r2 = r0 + r1 * (uint32_t)7879;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[638] = (R0[1276] + 3939) & 16383;

	for (i = 0; i < 319; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)948;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[319] = R[638];

	for (i = 0; i < 160; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)3511;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 80; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)189;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 40; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)140;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 20; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)77;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 10; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)5929;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 5; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)537;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}

	for (i = 0; i < 2; ++i) {
		r0 = R[2 * i];
		r1 = R[2 * i + 1];
		r2 = r0 + r1 * (uint32_t)1127;
		*out++ = (uint8_t)r2;
		r2 >>= 8;
		R[i] = (uint16_t)r2;
	}
	R[2] = R[4];

	r0 = R[0];
	r1 = R[1];
	r2 = r0 + r1 * (uint32_t)4962;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[0] = (uint16_t)r2;
	R[1] = R[2];

	r0 = R[0];
	r1 = R[1];
	r2 = r0 + r1 * (uint32_t)376;
	*out++ = (uint8_t)r2;
	r2 >>= 8;
	R[0] = (uint16_t)r2;

	r0 = R[0];
	*out++ = (uint8_t)r0;
	r0 >>= 8;
	*out++ = (uint8_t)r0;
}
