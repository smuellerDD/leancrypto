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

void sntrup_decode_1277x7879(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_1277x7879_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, -4539);
	a1 = mulhi(a1, 1072) - mulhi(lo, 3696);
	a1 += *--s; /* -1848...2107 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3696); /* 0...3695 */
	R[0] = a1;

	/* reconstruct mod 1*[376]+[2516] */

	ri = R[0];
	s0 = *--s;
	lo = mullo(ri, 20916);
	a0 = mulhi(ri, 96) - mulhi(lo, 376); /* -188...212 */
	a0 += s0; /* -188...467 */
	a0 -= 376; /* -564..>91 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 376); /* -188...375 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 376); /* 0...375 */
	a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
	a1 = mullo(a1, 18127);

	/* invalid inputs might need reduction mod 2516 */
	a1 -= 2516;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2516);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 2*[4962]+[2516] */

	R[2] = R[1];
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -3381);
		a0 = mulhi(ri, 694) - mulhi(lo, 4962); /* -2481...2654 */
		a0 += s1; /* -2481...2909 */
		lo = mullo(a0, -3381);
		a0 = mulhi(a0, 694) - mulhi(lo, 4962); /* -2508...2511 */
		a0 += s0; /* -2508...2766 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				4962); /* 0...4961 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -24751);

		/* invalid inputs might need reduction mod 4962 */
		a1 -= 4962;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 4962);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 4*[1127]+[2516] */

	R[4] = R[2];
	for (i = 1; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -14887);
		a0 = mulhi(ri, -433) - mulhi(lo, 1127); /* -672...563 */
		a0 += s0; /* -672...818 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1127); /* 0...1126 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -10409);

		/* invalid inputs might need reduction mod 1127 */
		a1 -= 1127;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1127);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 9*[537]+[1199] */

	ri = R[4];
	s0 = *--s;
	lo = mullo(ri, -31242);
	a0 = mulhi(ri, 262) - mulhi(lo, 537); /* -269...334 */
	a0 += s0; /* -269...589 */
	a0 -= 537; /* -806..>52 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 537); /* -269...536 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 537); /* 0...536 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 14889);

	/* invalid inputs might need reduction mod 1199 */
	a1 -= 1199;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1199);

	R[8] = a0;
	R[9] = a1;
	for (i = 3; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -31242);
		a0 = mulhi(ri, 262) - mulhi(lo, 537); /* -269...334 */
		a0 += s0; /* -269...589 */
		a0 -= 537; /* -806..>52 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				537); /* -269...536 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				537); /* 0...536 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 14889);

		/* invalid inputs might need reduction mod 537 */
		a1 -= 537;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 537);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 19*[5929]+[13244] */

	ri = R[9];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -2830);
	a0 = mulhi(ri, -1854) - mulhi(lo, 5929); /* -3428...2964 */
	a0 += s1; /* -3428...3219 */
	lo = mullo(a0, -2830);
	a0 = mulhi(a0, -1854) - mulhi(lo, 5929); /* -3056...3061 */
	a0 += s0; /* -3056...3316 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 5929); /* 0...5928 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, 29977);

	/* invalid inputs might need reduction mod 13244 */
	a1 -= 13244;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 13244);

	R[18] = a0;
	R[19] = a1;
	for (i = 8; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2830);
		a0 = mulhi(ri, -1854) - mulhi(lo, 5929); /* -3428...2964 */
		a0 += s1; /* -3428...3219 */
		lo = mullo(a0, -2830);
		a0 = mulhi(a0, -1854) - mulhi(lo, 5929); /* -3056...3061 */
		a0 += s0; /* -3056...3316 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				5929); /* 0...5928 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 29977);

		/* invalid inputs might need reduction mod 5929 */
		a1 -= 5929;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5929);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 39*[77]+[172] */

	ri = R[19];
	a0 = ri;
	lo = mullo(a0, -851);
	a0 = mulhi(a0, 9) - mulhi(lo, 77); /* -39...40 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 77); /* 0...76 */
	a1 = (ri - a0) >> 0;
	a1 = mullo(a1, 14469);

	/* invalid inputs might need reduction mod 172 */
	a1 -= 172;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 172);

	R[38] = a0;
	R[39] = a1;
	for (i = 18; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -851);
		a0 = mulhi(a0, 9) - mulhi(lo, 77); /* -39...40 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				77); /* 0...76 */
		a1 = (ri - a0) >> 0;
		a1 = mullo(a1, 14469);

		/* invalid inputs might need reduction mod 77 */
		a1 -= 77;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 77);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 79*[140]+[313] */

	ri = R[39];
	s0 = *--s;
	lo = mullo(ri, 11235);
	a0 = mulhi(ri, 36) - mulhi(lo, 140); /* -70...79 */
	a0 += s0; /* -70...334 */
	lo = mullo(a0, -468);
	a0 = mulhi(a0, 16) - mulhi(lo, 140); /* -71...70 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 140); /* 0...139 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -20597);

	/* invalid inputs might need reduction mod 313 */
	a1 -= 313;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 313);

	R[78] = a0;
	R[79] = a1;
	for (i = 38; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 11235);
		a0 = mulhi(ri, 36) - mulhi(lo, 140); /* -70...79 */
		a0 += s0; /* -70...334 */
		lo = mullo(a0, -468);
		a0 = mulhi(a0, 16) - mulhi(lo, 140); /* -71...70 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				140); /* 0...139 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -20597);

		/* invalid inputs might need reduction mod 140 */
		a1 -= 140;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 140);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 159*[189]+[423] */

	ri = R[79];
	s0 = *--s;
	lo = mullo(ri, -23232);
	a0 = mulhi(ri, 64) - mulhi(lo, 189); /* -95...110 */
	a0 += s0; /* -95...365 */
	a0 -= 189; /* -284..>176 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 189); /* -95...188 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 189); /* 0...188 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -1387);

	/* invalid inputs might need reduction mod 423 */
	a1 -= 423;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 423);

	R[158] = a0;
	R[159] = a1;
	for (i = 78; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -23232);
		a0 = mulhi(ri, 64) - mulhi(lo, 189); /* -95...110 */
		a0 += s0; /* -95...365 */
		a0 -= 189; /* -284..>176 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				189); /* -95...188 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				189); /* 0...188 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -1387);

		/* invalid inputs might need reduction mod 189 */
		a1 -= 189;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 189);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 319*[3511]+[7879] */

	ri = R[159];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -4778);
	a0 = mulhi(ri, 1658) - mulhi(lo, 3511); /* -1756...2170 */
	a0 += s1; /* -1756...2425 */
	lo = mullo(a0, -4778);
	a0 = mulhi(a0, 1658) - mulhi(lo, 3511); /* -1800...1816 */
	a0 += s0; /* -1800...2071 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 3511); /* 0...3510 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, 24583);

	/* invalid inputs might need reduction mod 7879 */
	a1 -= 7879;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7879);

	R[318] = a0;
	R[319] = a1;
	for (i = 158; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -4778);
		a0 = mulhi(ri, 1658) - mulhi(lo, 3511); /* -1756...2170 */
		a0 += s1; /* -1756...2425 */
		lo = mullo(a0, -4778);
		a0 = mulhi(a0, 1658) - mulhi(lo, 3511); /* -1800...1816 */
		a0 += s0; /* -1800...2071 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				3511); /* 0...3510 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 24583);

		/* invalid inputs might need reduction mod 3511 */
		a1 -= 3511;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3511);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 638*[948]+[7879] */

	R[638] = R[319];
	for (i = 318; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -17697);
		a0 = mulhi(ri, 460) - mulhi(lo, 948); /* -474...589 */
		a0 += s0; /* -474...844 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				948); /* 0...947 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, 23781);

		/* invalid inputs might need reduction mod 948 */
		a1 -= 948;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 948);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 1277*[7879] */

	R[1276] = R[638] - 3939;
	for (i = 637; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2129);
		a0 = mulhi(ri, 2825) - mulhi(lo, 7879); /* -3940...4645 */
		a0 += s1; /* -3940...4900 */
		lo = mullo(a0, -2129);
		a0 = mulhi(a0, 2825) - mulhi(lo, 7879); /* -4110...4150 */
		a0 += s0; /* -4110...4405 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				7879); /* 0...7878 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 17143);

		/* invalid inputs might need reduction mod 7879 */
		a1 -= 7879;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7879);

		R[2 * i] = a0 - 3939;
		R[2 * i + 1] = a1 - 3939;
	}
}
