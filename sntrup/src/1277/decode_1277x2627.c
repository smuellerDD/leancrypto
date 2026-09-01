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

void sntrup_decode_1277x2627(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_1277x2627_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, 1986);
	a1 = mulhi(a1, 16) - mulhi(lo, 264);
	a1 += *--s; /* -132...387 */
	a1 -= 264; /* -396...123 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 264); /* -132...263 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 264); /* 0...263 */
	R[0] = a1;

	/* reconstruct mod 1*[7744]+[2229] */

	ri = R[0];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -2166);
	a0 = mulhi(ri, 3712) - mulhi(lo, 7744); /* -3872...4800 */
	a0 += s1; /* -3872...5055 */
	lo = mullo(a0, -2166);
	a0 = mulhi(a0, 3712) - mulhi(lo, 7744); /* -4092...4158 */
	a0 += s0; /* -4092...4413 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 7744); /* 0...7743 */
	a1 = (int16_t)((ri << 10) + (s1 << 2) + ((s0 - a0) >> 6));
	a1 = mullo(a1, 27081);

	/* invalid inputs might need reduction mod 2229 */
	a1 -= 2229;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2229);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 2*[1408]+[2229] */

	R[2] = R[1];
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -11916);
		a0 = mulhi(ri, -512) - mulhi(lo, 1408); /* -832...704 */
		a0 += s0; /* -832...959 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1408); /* 0...1407 */
		a1 = (int16_t)((ri << 1) + ((s0 - a0) >> 7));
		a1 = mullo(a1, -29789);

		/* invalid inputs might need reduction mod 1408 */
		a1 -= 1408;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1408);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 4*[9604]+[2229] */

	R[4] = R[2];
	for (i = 1; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1747);
		a0 = mulhi(ri, -972) - mulhi(lo, 9604); /* -5045...4802 */
		a0 += s1; /* -5045...5057 */
		lo = mullo(a0, -1747);
		a0 = mulhi(a0, -972) - mulhi(lo, 9604); /* -4878...4876 */
		a0 += s0; /* -4878...5131 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				9604); /* 0...9603 */
		a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, 23201);

		/* invalid inputs might need reduction mod 9604 */
		a1 -= 9604;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 9604);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 9*[98]+[5822] */

	ri = R[4];
	s0 = *--s;
	lo = mullo(ri, 25412);
	a0 = mulhi(ri, 8) - mulhi(lo, 98); /* -49...51 */
	a0 += s0; /* -49...306 */
	lo = mullo(a0, -669);
	a0 = mulhi(a0, -26) - mulhi(lo, 98); /* -50...49 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 98); /* 0...97 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 22737);

	/* invalid inputs might need reduction mod 5822 */
	a1 -= 5822;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5822);

	R[8] = a0;
	R[9] = a1;
	for (i = 3; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -669);
		a0 = mulhi(a0, -26) - mulhi(lo, 98); /* -56...49 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				98); /* 0...97 */
		a1 = (int16_t)((ri - a0) >> 1);
		a1 = mullo(a1, 22737);

		/* invalid inputs might need reduction mod 98 */
		a1 -= 98;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 98);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 19*[158]+[9433] */

	ri = R[9];
	s0 = *--s;
	lo = mullo(ri, 24887);
	a0 = mulhi(ri, -14) - mulhi(lo, 158); /* -83...79 */
	a0 += s0; /* -83...334 */
	lo = mullo(a0, -415);
	a0 = mulhi(a0, -34) - mulhi(lo, 158); /* -80...79 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 158); /* 0...157 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 5807);

	/* invalid inputs might need reduction mod 9433 */
	a1 -= 9433;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 9433);

	R[18] = a0;
	R[19] = a1;
	for (i = 8; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 24887);
		a0 = mulhi(ri, -14) - mulhi(lo, 158); /* -83...79 */
		a0 += s0; /* -83...334 */
		lo = mullo(a0, -415);
		a0 = mulhi(a0, -34) - mulhi(lo, 158); /* -80...79 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				158); /* 0...157 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, 5807);

		/* invalid inputs might need reduction mod 158 */
		a1 -= 158;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 158);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 39*[3211]+[752] */

	ri = R[19];
	s0 = *--s;
	lo = mullo(ri, -5225);
	a0 = mulhi(ri, -259) - mulhi(lo, 3211); /* -1671...1605 */
	a0 += s0; /* -1671...1860 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 3211); /* 0...3210 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -1245);

	/* invalid inputs might need reduction mod 752 */
	a1 -= 752;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 752);

	R[38] = a0;
	R[39] = a1;
	for (i = 18; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -5225);
		a0 = mulhi(ri, -259) - mulhi(lo, 3211); /* -1671...1605 */
		a0 += s1; /* -1671...1860 */
		lo = mullo(a0, -5225);
		a0 = mulhi(a0, -259) - mulhi(lo, 3211); /* -1613...1612 */
		a0 += s0; /* -1613...1867 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				3211); /* 0...3210 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -1245);

		/* invalid inputs might need reduction mod 3211 */
		a1 -= 3211;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3211);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 79*[14506]+[3395] */

	ri = R[39];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1157);
	a0 = mulhi(ri, -6226) - mulhi(lo, 14506); /* -8810...7253 */
	a0 += s1; /* -8810...7508 */
	lo = mullo(a0, -1157);
	a0 = mulhi(a0, -6226) - mulhi(lo, 14506); /* -7967...8089 */
	a0 += s0; /* -7967...8344 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 14506); /* 0...14505 */
	a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 253);

	/* invalid inputs might need reduction mod 3395 */
	a1 -= 3395;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3395);

	R[78] = a0;
	R[79] = a1;
	for (i = 38; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1157);
		a0 = mulhi(ri, -6226) - mulhi(lo, 14506); /* -8810...7253 */
		a0 += s1; /* -8810...7508 */
		lo = mullo(a0, -1157);
		a0 = mulhi(a0, -6226) - mulhi(lo, 14506); /* -7967...8089 */
		a0 += s0; /* -7967...8344 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				14506); /* 0...14505 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, 253);

		/* invalid inputs might need reduction mod 14506 */
		a1 -= 14506;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 14506);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 159*[1927]+[451] */

	ri = R[79];
	s0 = *--s;
	lo = mullo(ri, -8706);
	a0 = mulhi(ri, 754) - mulhi(lo, 1927); /* -964...1152 */
	a0 += s0; /* -964...1407 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1927); /* 0...1926 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 3639);

	/* invalid inputs might need reduction mod 451 */
	a1 -= 451;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 451);

	R[158] = a0;
	R[159] = a1;
	for (i = 78; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -8706);
		a0 = mulhi(ri, 754) - mulhi(lo, 1927); /* -964...1152 */
		a0 += s0; /* -964...1407 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1927); /* 0...1926 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 3639);

		/* invalid inputs might need reduction mod 1927 */
		a1 -= 1927;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1927);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 319*[11236]+[2627] */

	ri = R[159];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1493);
	a0 = mulhi(ri, 1868) - mulhi(lo, 11236); /* -5618...6085 */
	a0 += s1; /* -5618...6340 */
	lo = mullo(a0, -1493);
	a0 = mulhi(a0, 1868) - mulhi(lo, 11236); /* -5779...5798 */
	a0 += s0; /* -5779...6053 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 11236); /* 0...11235 */
	a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -26807);

	/* invalid inputs might need reduction mod 2627 */
	a1 -= 2627;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2627);

	R[318] = a0;
	R[319] = a1;
	for (i = 158; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1493);
		a0 = mulhi(ri, 1868) - mulhi(lo, 11236); /* -5618...6085 */
		a0 += s1; /* -5618...6340 */
		lo = mullo(a0, -1493);
		a0 = mulhi(a0, 1868) - mulhi(lo, 11236); /* -5779...5798 */
		a0 += s0; /* -5779...6053 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				11236); /* 0...11235 */
		a1 = (int16_t)((ri << 14) + (s1 << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -26807);

		/* invalid inputs might need reduction mod 11236 */
		a1 -= 11236;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 11236);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 638*[106]+[2627] */

	R[638] = R[319];
	for (i = 318; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -618);
		a0 = mulhi(a0, 28) - mulhi(lo, 106); /* -53...60 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				106); /* 0...105 */
		a1 = (int16_t)((ri - a0) >> 1);
		a1 = mullo(a1, 21021);

		/* invalid inputs might need reduction mod 106 */
		a1 -= 106;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 106);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 1277*[2627] */

	R[1276] = (int16_t)(3 * R[638] - 3939);
	for (i = 637; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -6386);
		a0 = mulhi(ri, 1194) - mulhi(lo, 2627); /* -1314...1612 */
		a0 += s1; /* -1314...1867 */
		lo = mullo(a0, -6386);
		a0 = mulhi(a0, 1194) - mulhi(lo, 2627); /* -1338...1347 */
		a0 += s0; /* -1338...1602 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2627); /* 0...2626 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 4715);

		/* invalid inputs might need reduction mod 2627 */
		a1 -= 2627;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2627);

		R[2 * i] = (int16_t)(3 * a0 - 3939);
		R[2 * i + 1] = (int16_t)(3 * a1 - 3939);
	}
}
