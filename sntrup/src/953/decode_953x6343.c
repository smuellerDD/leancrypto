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

void sntrup_decode_953x6343(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_953x6343_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, -1336);
	a1 = mulhi(a1, -272) - mulhi(lo, 12558);
	a1 += *--s; /* -6279...6532 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 12558); /* 0...12557 */
	R[0] = a1;

	/* reconstruct mod 1*[2383]+[1349] */

	ri = R[0];
	s0 = *--s;
	lo = mullo(ri, -7040);
	a0 = mulhi(ri, 896) - mulhi(lo, 2383); /* -1192...1415 */
	a0 += s0; /* -1192...1670 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 2383); /* 0...2382 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 28079);

	/* invalid inputs might need reduction mod 1349 */
	a1 -= 1349;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1349);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[781]+[442] */

	ri = R[1];
	s0 = *--s;
	lo = mullo(ri, -21482);
	a0 = mulhi(ri, -226) - mulhi(lo, 781); /* -447...390 */
	a0 += s0; /* -447...645 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 781); /* 0...780 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -31803);

	/* invalid inputs might need reduction mod 442 */
	a1 -= 442;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 442);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -21482);
		a0 = mulhi(ri, -226) - mulhi(lo, 781); /* -447...390 */
		a0 += s0; /* -447...645 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				781); /* 0...780 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -31803);

		/* invalid inputs might need reduction mod 781 */
		a1 -= 781;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 781);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 7*[447]+[253] */

	ri = R[3];
	s0 = *--s;
	lo = mullo(ri, 28003);
	a0 = mulhi(ri, -35) - mulhi(lo, 447); /* -233...223 */
	a0 += s0; /* -233...478 */
	a0 -= 447; /* -680..>31 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 447); /* -233...446 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 447); /* 0...446 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -4545);

	/* invalid inputs might need reduction mod 253 */
	a1 -= 253;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 253);

	R[6] = a0;
	R[7] = a1;
	for (i = 2; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 28003);
		a0 = mulhi(ri, -35) - mulhi(lo, 447); /* -233...223 */
		a0 += s0; /* -233...478 */
		a0 -= 447; /* -680..>31 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				447); /* -233...446 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				447); /* 0...446 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -4545);

		/* invalid inputs might need reduction mod 447 */
		a1 -= 447;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 447);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 14*[338]+[253] */

	R[14] = R[7];
	for (i = 6; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 15899);
		a0 = mulhi(ri, -90) - mulhi(lo, 338); /* -192...169 */
		a0 += s0; /* -192...424 */
		a0 -= 338; /* -530..>86 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				338); /* -192...337 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				338); /* 0...337 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -23655);

		/* invalid inputs might need reduction mod 338 */
		a1 -= 338;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 338);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 29*[4701]+[3519] */

	ri = R[14];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -3569);
	a0 = mulhi(ri, -653) - mulhi(lo, 4701); /* -2514...2350 */
	a0 += s1; /* -2514...2605 */
	lo = mullo(a0, -3569);
	a0 = mulhi(a0, -653) - mulhi(lo, 4701); /* -2377...2375 */
	a0 += s0; /* -2377...2630 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 4701); /* 0...4700 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, 20981);

	/* invalid inputs might need reduction mod 3519 */
	a1 -= 3519;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3519);

	R[28] = a0;
	R[29] = a1;
	for (i = 13; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -3569);
		a0 = mulhi(ri, -653) - mulhi(lo, 4701); /* -2514...2350 */
		a0 += s1; /* -2514...2605 */
		lo = mullo(a0, -3569);
		a0 = mulhi(a0, -653) - mulhi(lo, 4701); /* -2377...2375 */
		a0 += s0; /* -2377...2630 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				4701); /* 0...4700 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 20981);

		/* invalid inputs might need reduction mod 4701 */
		a1 -= 4701;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 4701);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 59*[1097]+[821] */

	ri = R[29];
	s0 = *--s;
	lo = mullo(ri, -15294);
	a0 = mulhi(ri, -302) - mulhi(lo, 1097); /* -624...548 */
	a0 += s0; /* -624...803 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1097); /* 0...1096 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 11769);

	/* invalid inputs might need reduction mod 821 */
	a1 -= 821;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 821);

	R[58] = a0;
	R[59] = a1;
	for (i = 28; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -15294);
		a0 = mulhi(ri, -302) - mulhi(lo, 1097); /* -624...548 */
		a0 += s0; /* -624...803 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1097); /* 0...1096 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 11769);

		/* invalid inputs might need reduction mod 1097 */
		a1 -= 1097;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1097);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 119*[8476]+[6343] */

	ri = R[59];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1979);
	a0 = mulhi(ri, 3212) - mulhi(lo, 8476); /* -4238...5041 */
	a0 += s1; /* -4238...5296 */
	lo = mullo(a0, -1979);
	a0 = mulhi(a0, 3212) - mulhi(lo, 8476); /* -4446...4497 */
	a0 += s0; /* -4446...4752 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 8476); /* 0...8475 */
	a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, 8567);

	/* invalid inputs might need reduction mod 6343 */
	a1 -= 6343;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 6343);

	R[118] = a0;
	R[119] = a1;
	for (i = 58; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1979);
		a0 = mulhi(ri, 3212) - mulhi(lo, 8476); /* -4238...5041 */
		a0 += s1; /* -4238...5296 */
		lo = mullo(a0, -1979);
		a0 = mulhi(a0, 3212) - mulhi(lo, 8476); /* -4446...4497 */
		a0 += s0; /* -4446...4752 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				8476); /* 0...8475 */
		a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, 8567);

		/* invalid inputs might need reduction mod 8476 */
		a1 -= 8476;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 8476);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 238*[1473]+[6343] */

	R[238] = R[119];
	for (i = 118; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -11390);
		a0 = mulhi(ri, -254) - mulhi(lo, 1473); /* -800...736 */
		a0 += s0; /* -800...991 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1473); /* 0...1472 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 2625);

		/* invalid inputs might need reduction mod 1473 */
		a1 -= 1473;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1473);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 476*[614]+[6343] */

	R[476] = R[238];
	for (i = 237; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -27324);
		a0 = mulhi(ri, 280) - mulhi(lo, 614); /* -307...377 */
		a0 += s0; /* -307...632 */
		a0 -= 614; /* -921..>18 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				614); /* -307...613 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				614); /* 0...613 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -7685);

		/* invalid inputs might need reduction mod 614 */
		a1 -= 614;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 614);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 953*[6343] */

	R[952] = R[476] - 3171;
	for (i = 475; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2645);
		a0 = mulhi(ri, -19) - mulhi(lo, 6343); /* -3177...3171 */
		a0 += s1; /* -3177...3426 */
		lo = mullo(a0, -2645);
		a0 = mulhi(a0, -19) - mulhi(lo, 6343); /* -3173...3172 */
		a0 += s0; /* -3173...3427 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				6343); /* 0...6342 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 10487);

		/* invalid inputs might need reduction mod 6343 */
		a1 -= 6343;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 6343);

		R[2 * i] = a0 - 3171;
		R[2 * i + 1] = a1 - 3171;
	}
}
