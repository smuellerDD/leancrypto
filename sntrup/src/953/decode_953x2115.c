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

void sntrup_decode_953x2115(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_953x2115_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 -= 124; /* -124...131 */
	a1 -= 124; /* -248...7 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 124); /* -124...123 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 124); /* 0...123 */
	R[0] = a1;

	/* reconstruct mod 1*[3846]+[2107] */

	ri = R[0];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -4362);
	a0 = mulhi(ri, 964) - mulhi(lo, 3846); /* -1923...2164 */
	a0 += s1; /* -1923...2419 */
	lo = mullo(a0, -4362);
	a0 = mulhi(a0, 964) - mulhi(lo, 3846); /* -1952...1958 */
	a0 += s0; /* -1952...2213 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 3846); /* 0...3845 */
	a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, -16597);

	/* invalid inputs might need reduction mod 2107 */
	a1 -= 2107;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2107);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[15876]+[8694] */

	ri = R[1];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1057);
	a0 = mulhi(ri, -3716) - mulhi(lo, 15876); /* -8867...7938 */
	a0 += s1; /* -8867...8193 */
	lo = mullo(a0, -1057);
	a0 = mulhi(a0, -3716) - mulhi(lo, 15876); /* -8403...8440 */
	a0 += s0; /* -8403...8695 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 15876); /* 0...15875 */
	a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, 12417);

	/* invalid inputs might need reduction mod 8694 */
	a1 -= 8694;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 8694);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1057);
		a0 = mulhi(ri, -3716) - mulhi(lo, 15876); /* -8867...7938 */
		a0 += s1; /* -8867...8193 */
		lo = mullo(a0, -1057);
		a0 = mulhi(a0, -3716) - mulhi(lo, 15876); /* -8403...8440 */
		a0 += s0; /* -8403...8695 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				15876); /* 0...15875 */
		a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, 12417);

		/* invalid inputs might need reduction mod 15876 */
		a1 -= 15876;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 15876);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 7*[126]+[69] */

	ri = R[3];
	a0 = ri;
	lo = mullo(a0, -520);
	a0 = mulhi(a0, 16) - mulhi(lo, 126); /* -63...67 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 126); /* 0...125 */
	a1 = (int16_t)((ri - a0) >> 1);
	a1 = mullo(a1, -4161);

	/* invalid inputs might need reduction mod 69 */
	a1 -= 69;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 69);

	R[6] = a0;
	R[7] = a1;
	for (i = 2; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -520);
		a0 = mulhi(a0, 16) - mulhi(lo, 126); /* -63...67 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				126); /* 0...125 */
		a1 = (int16_t)((ri - a0) >> 1);
		a1 = mullo(a1, -4161);

		/* invalid inputs might need reduction mod 126 */
		a1 -= 126;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 126);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 14*[2863]+[69] */

	R[14] = R[7];
	for (i = 6; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -5860);
		a0 = mulhi(ri, 36) - mulhi(lo, 2863); /* -1432...1440 */
		a0 += s1; /* -1432...1695 */
		lo = mullo(a0, -5860);
		a0 = mulhi(a0, 36) - mulhi(lo, 2863); /* -1433...1432 */
		a0 += s0; /* -1433...1687 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2863); /* 0...2862 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 7119);

		/* invalid inputs might need reduction mod 2863 */
		a1 -= 2863;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2863);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 29*[856]+[5227] */

	ri = R[14];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -19600);
	a0 = mulhi(ri, -384) - mulhi(lo, 856); /* -524...428 */
	a0 += s1; /* -524...683 */
	lo = mullo(a0, -19600);
	a0 = mulhi(a0, -384) - mulhi(lo, 856); /* -433...431 */
	a0 += s0; /* -433...686 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 856); /* 0...855 */
	a1 = (int16_t)((ri << 13) + (s1 << 5) + ((s0 - a0) >> 3));
	a1 = mullo(a1, -21437);

	/* invalid inputs might need reduction mod 5227 */
	a1 -= 5227;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5227);

	R[28] = a0;
	R[29] = a1;
	for (i = 13; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -19600);
		a0 = mulhi(ri, -384) - mulhi(lo, 856); /* -524...428 */
		a0 += s0; /* -524...683 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				856); /* 0...855 */
		a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, -21437);

		/* invalid inputs might need reduction mod 856 */
		a1 -= 856;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 856);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 59*[468]+[2859] */

	ri = R[29];
	s0 = *--s;
	lo = mullo(ri, 29687);
	a0 = mulhi(ri, -116) - mulhi(lo, 468); /* -263...234 */
	a0 += s0; /* -263...489 */
	a0 -= 468; /* -731..>21 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 468); /* -263...467 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 468); /* 0...467 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -12323);

	/* invalid inputs might need reduction mod 2859 */
	a1 -= 2859;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2859);

	R[58] = a0;
	R[59] = a1;
	for (i = 28; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 29687);
		a0 = mulhi(ri, -116) - mulhi(lo, 468); /* -263...234 */
		a0 += s0; /* -263...489 */
		a0 -= 468; /* -731..>21 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				468); /* -263...467 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				468); /* 0...467 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -12323);

		/* invalid inputs might need reduction mod 468 */
		a1 -= 468;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 468);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 119*[346]+[2115] */

	ri = R[59];
	s0 = *--s;
	lo = mullo(ri, 17047);
	a0 = mulhi(ri, 22) - mulhi(lo, 346); /* -173...178 */
	a0 += s0; /* -173...433 */
	a0 -= 346; /* -519..>87 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 346); /* -173...345 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 346); /* 0...345 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 25381);

	/* invalid inputs might need reduction mod 2115 */
	a1 -= 2115;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2115);

	R[118] = a0;
	R[119] = a1;
	for (i = 58; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 17047);
		a0 = mulhi(ri, 22) - mulhi(lo, 346); /* -173...178 */
		a0 += s0; /* -173...433 */
		a0 -= 346; /* -519..>87 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				346); /* -173...345 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				346); /* 0...345 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, 25381);

		/* invalid inputs might need reduction mod 346 */
		a1 -= 346;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 346);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 238*[4761]+[2115] */

	R[238] = R[119];
	for (i = 118; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -3524);
		a0 = mulhi(ri, -548) - mulhi(lo, 4761); /* -2518...2380 */
		a0 += s1; /* -2518...2635 */
		lo = mullo(a0, -3524);
		a0 = mulhi(a0, -548) - mulhi(lo, 4761); /* -2403...2401 */
		a0 += s0; /* -2403...2656 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				4761); /* 0...4760 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 8617);

		/* invalid inputs might need reduction mod 4761 */
		a1 -= 4761;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 4761);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 476*[69]+[2115] */

	R[476] = R[238];
	for (i = 237; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -950);
		a0 = mulhi(a0, -14) - mulhi(lo, 69); /* -38...34 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				69); /* 0...68 */
		a1 = (ri - a0) >> 0;
		a1 = mullo(a1, 4749);

		/* invalid inputs might need reduction mod 69 */
		a1 -= 69;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 69);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 953*[2115] */

	R[952] = (int16_t)(3 * R[476] - 3171);
	for (i = 475; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -7932);
		a0 = mulhi(ri, 1036) - mulhi(lo, 2115); /* -1058...1316 */
		a0 += s1; /* -1058...1571 */
		lo = mullo(a0, -7932);
		a0 = mulhi(a0, 1036) - mulhi(lo, 2115); /* -1075...1082 */
		a0 += s0; /* -1075...1337 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2115); /* 0...2114 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -31637);

		/* invalid inputs might need reduction mod 2115 */
		a1 -= 2115;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2115);

		R[2 * i] = (int16_t)(3 * a0 - 3171);
		R[2 * i + 1] = (int16_t)(3 * a1 - 3171);
	}
}
