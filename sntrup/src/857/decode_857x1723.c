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

static int16_t mullo(int16_t x, int16_t y)
{
	return x * y;
}

static int16_t mulhi(int16_t x, int16_t y)
{
	return (int16_t)((x * (int32_t)y) >> 16);
}

void sntrup_decode_857x1723(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_857x1723_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 -= 160; /* -160...95 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 160); /* 0...159 */
	R[0] = a1;

	/* reconstruct mod 1*[743]+[14044] */

	ri = R[0];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -22580);
	a0 = mulhi(ri, 276) - mulhi(lo, 743); /* -372...440 */
	a0 += s1; /* -372...695 */
	lo = mullo(a0, -22580);
	a0 = mulhi(a0, 276) - mulhi(lo, 743); /* -374...374 */
	a0 += s0; /* -374...629 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 743); /* 0...742 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, -3881);

	/* invalid inputs might need reduction mod 14044 */
	a1 -= 14044;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 14044);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[436]+[8246] */

	ri = R[1];
	s0 = *--s;
	lo = mullo(ri, 27056);
	a0 = mulhi(ri, -64) - mulhi(lo, 436); /* -234...218 */
	a0 += s0; /* -234...473 */
	a0 -= 436; /* -670..>37 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 436); /* -234...435 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 436); /* 0...435 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, 2405);

	/* invalid inputs might need reduction mod 8246 */
	a1 -= 8246;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 8246);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 27056);
		a0 = mulhi(ri, -64) - mulhi(lo, 436); /* -234...218 */
		a0 += s0; /* -234...473 */
		a0 -= 436; /* -670..>37 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				436); /* -234...435 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				436); /* 0...435 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, 2405);

		/* invalid inputs might need reduction mod 436 */
		a1 -= 436;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 436);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 6*[334]+[8246] */

	R[6] = R[3];
	for (i = 2; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 15305);
		a0 = mulhi(ri, 62) - mulhi(lo, 334); /* -167...182 */
		a0 += s0; /* -167...437 */
		a0 -= 334; /* -501..>103 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				334); /* -167...333 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				334); /* 0...333 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -22761);

		/* invalid inputs might need reduction mod 334 */
		a1 -= 334;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 334);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 13*[292]+[7229] */

	ri = R[6];
	s0 = *--s;
	lo = mullo(ri, 8080);
	a0 = mulhi(ri, 64) - mulhi(lo, 292); /* -146...162 */
	a0 += s0; /* -146...417 */
	a0 -= 292; /* -438..>125 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 292); /* -146...291 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 292); /* 0...291 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -3591);

	/* invalid inputs might need reduction mod 7229 */
	a1 -= 7229;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7229);

	R[12] = a0;
	R[13] = a1;
	for (i = 5; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 8080);
		a0 = mulhi(ri, 64) - mulhi(lo, 292); /* -146...162 */
		a0 += s0; /* -146...417 */
		a0 -= 292; /* -438..>125 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				292); /* -146...291 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				292); /* 0...291 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -3591);

		/* invalid inputs might need reduction mod 292 */
		a1 -= 292;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 292);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 26*[273]+[7229] */

	R[26] = R[13];
	for (i = 12; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 4081);
		a0 = mulhi(ri, 1) - mulhi(lo, 273); /* -137...136 */
		a0 += s0; /* -137...391 */
		a0 -= 273; /* -410..>118 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				273); /* -137...272 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				273); /* 0...272 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 4081);

		/* invalid inputs might need reduction mod 273 */
		a1 -= 273;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 273);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 53*[4225]+[438] */

	ri = R[26];
	s0 = *--s;
	lo = mullo(ri, -3971);
	a0 = mulhi(ri, -259) - mulhi(lo, 4225); /* -2178...2112 */
	a0 += s0; /* -2178...2367 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 4225); /* 0...4224 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 12161);

	/* invalid inputs might need reduction mod 438 */
	a1 -= 438;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 438);

	R[52] = a0;
	R[53] = a1;
	for (i = 25; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -3971);
		a0 = mulhi(ri, -259) - mulhi(lo, 4225); /* -2178...2112 */
		a0 += s1; /* -2178...2367 */
		lo = mullo(a0, -3971);
		a0 = mulhi(a0, -259) - mulhi(lo, 4225); /* -2122...2121 */
		a0 += s0; /* -2122...2376 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				4225); /* 0...4224 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 12161);

		/* invalid inputs might need reduction mod 4225 */
		a1 -= 4225;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 4225);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 107*[65]+[1723] */

	ri = R[53];
	s0 = *--s;
	lo = mullo(ri, 4033);
	a0 = mulhi(ri, 1) - mulhi(lo, 65); /* -33...32 */
	a0 += s0; /* -33...287 */
	lo = mullo(a0, -1008);
	a0 = mulhi(a0, 16) - mulhi(lo, 65); /* -33...32 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 65); /* 0...64 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 4033);

	/* invalid inputs might need reduction mod 1723 */
	a1 -= 1723;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1723);

	R[106] = a0;
	R[107] = a1;
	for (i = 52; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -1008);
		a0 = mulhi(a0, 16) - mulhi(lo, 65); /* -33...36 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				65); /* 0...64 */
		a1 = (ri - a0) >> 0;
		a1 = mullo(a1, 4033);

		/* invalid inputs might need reduction mod 65 */
		a1 -= 65;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 65);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 214*[2053]+[1723] */

	R[214] = R[107];
	for (i = 106; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -8172);
		a0 = mulhi(ri, 100) - mulhi(lo, 2053); /* -1027...1051 */
		a0 += s1; /* -1027...1306 */
		lo = mullo(a0, -8172);
		a0 = mulhi(a0, 100) - mulhi(lo, 2053); /* -1029...1028 */
		a0 += s0; /* -1029...1283 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2053); /* 0...2052 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -31539);

		/* invalid inputs might need reduction mod 2053 */
		a1 -= 2053;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2053);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 428*[11597]+[1723] */

	R[428] = R[214];
	for (i = 213; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1447);
		a0 = mulhi(ri, -3643) - mulhi(lo, 11597); /* -6710...5798 */
		a0 += s1; /* -6710...6053 */
		lo = mullo(a0, -1447);
		a0 = mulhi(a0, -3643) - mulhi(lo, 11597); /* -6135...6171 */
		a0 += s0; /* -6135...6426 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				11597); /* 0...11596 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -11387);

		/* invalid inputs might need reduction mod 11597 */
		a1 -= 11597;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 11597);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 857*[1723] */

	R[856] = (int16_t)(3 * R[428] - 2583);
	for (i = 427; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -9737);
		a0 = mulhi(ri, 365) - mulhi(lo, 1723); /* -862...952 */
		a0 += s0; /* -862...1207 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1723); /* 0...1722 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 20083);

		/* invalid inputs might need reduction mod 1723 */
		a1 -= 1723;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1723);

		R[2 * i] = (int16_t)(3 * a0 - 2583);
		R[2 * i + 1] = (int16_t)(3 * a1 - 2583);
	}
}
