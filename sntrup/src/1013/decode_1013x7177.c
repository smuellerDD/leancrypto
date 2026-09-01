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

void sntrup_decode_1013x7177(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_1013x7177_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, 4305);
	a1 = mulhi(a1, -78) - mulhi(lo, 274);
	a1 += *--s; /* -137...391 */
	a1 -= 274; /* -411...117 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 274); /* -137...273 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 274); /* 0...273 */
	R[0] = a1;

	/* reconstruct mod 1*[91]+[769] */

	ri = R[0];
	s0 = *--s;
	lo = mullo(ri, 12243);
	a0 = mulhi(ri, 1) - mulhi(lo, 91); /* -46...45 */
	a0 += s0; /* -46...300 */
	lo = mullo(a0, -720);
	a0 = mulhi(a0, 16) - mulhi(lo, 91); /* -46...45 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 91); /* 0...90 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 12243);

	/* invalid inputs might need reduction mod 769 */
	a1 -= 769;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 769);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[152]+[1294] */

	ri = R[1];
	s0 = *--s;
	lo = mullo(ri, 20696);
	a0 = mulhi(ri, 64) - mulhi(lo, 152); /* -76...92 */
	a0 += s0; /* -76...347 */
	lo = mullo(a0, -431);
	a0 = mulhi(a0, 24) - mulhi(lo, 152); /* -77...76 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 152); /* 0...151 */
	a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
	a1 = mullo(a1, -13797);

	/* invalid inputs might need reduction mod 1294 */
	a1 -= 1294;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1294);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 20696);
		a0 = mulhi(ri, 64) - mulhi(lo, 152); /* -76...92 */
		a0 += s0; /* -76...347 */
		lo = mullo(a0, -431);
		a0 = mulhi(a0, 24) - mulhi(lo, 152); /* -77...76 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				152); /* 0...151 */
		a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, -13797);

		/* invalid inputs might need reduction mod 152 */
		a1 -= 152;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 152);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 7*[197]+[1681] */

	ri = R[3];
	s0 = *--s;
	lo = mullo(ri, -19628);
	a0 = mulhi(ri, -92) - mulhi(lo, 197); /* -122...98 */
	a0 += s0; /* -122...353 */
	a0 -= 197; /* -319..>156 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 197); /* -122...196 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 197); /* 0...196 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 32269);

	/* invalid inputs might need reduction mod 1681 */
	a1 -= 1681;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1681);

	R[6] = a0;
	R[7] = a1;
	for (i = 2; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -19628);
		a0 = mulhi(ri, -92) - mulhi(lo, 197); /* -122...98 */
		a0 += s0; /* -122...353 */
		a0 -= 197; /* -319..>156 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				197); /* -122...196 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				197); /* 0...196 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 32269);

		/* invalid inputs might need reduction mod 197 */
		a1 -= 197;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 197);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 15*[3586]+[120] */

	ri = R[7];
	s0 = *--s;
	lo = mullo(ri, -4679);
	a0 = mulhi(ri, -1678) - mulhi(lo, 3586); /* -2213...1793 */
	a0 += s0; /* -2213...2048 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 3586); /* 0...3585 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, -1791);

	/* invalid inputs might need reduction mod 120 */
	a1 -= 120;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 120);

	R[14] = a0;
	R[15] = a1;
	for (i = 6; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -4679);
		a0 = mulhi(ri, -1678) - mulhi(lo, 3586); /* -2213...1793 */
		a0 += s1; /* -2213...2048 */
		lo = mullo(a0, -4679);
		a0 = mulhi(a0, -1678) - mulhi(lo, 3586); /* -1846...1849 */
		a0 += s0; /* -1846...2104 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				3586); /* 0...3585 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -1791);

		/* invalid inputs might need reduction mod 3586 */
		a1 -= 3586;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3586);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 31*[958]+[8200] */

	ri = R[15];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -17513);
	a0 = mulhi(ri, -238) - mulhi(lo, 958); /* -539...479 */
	a0 += s1; /* -539...734 */
	lo = mullo(a0, -17513);
	a0 = mulhi(a0, -238) - mulhi(lo, 958); /* -482...480 */
	a0 += s0; /* -482...735 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 958); /* 0...957 */
	a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, -1505);

	/* invalid inputs might need reduction mod 8200 */
	a1 -= 8200;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 8200);

	R[30] = a0;
	R[31] = a1;
	for (i = 14; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -17513);
		a0 = mulhi(ri, -238) - mulhi(lo, 958); /* -539...479 */
		a0 += s0; /* -539...734 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				958); /* 0...957 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -1505);

		/* invalid inputs might need reduction mod 958 */
		a1 -= 958;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 958);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 63*[7921]+[265] */

	ri = R[31];
	s0 = *--s;
	lo = mullo(ri, -2118);
	a0 = mulhi(ri, 538) - mulhi(lo, 7921); /* -3961...4095 */
	a0 += s0; /* -3961...4350 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 7921); /* 0...7920 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 4625);

	/* invalid inputs might need reduction mod 265 */
	a1 -= 265;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 265);

	R[62] = a0;
	R[63] = a1;
	for (i = 30; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2118);
		a0 = mulhi(ri, 538) - mulhi(lo, 7921); /* -3961...4095 */
		a0 += s1; /* -3961...4350 */
		lo = mullo(a0, -2118);
		a0 = mulhi(a0, 538) - mulhi(lo, 7921); /* -3994...3996 */
		a0 += s0; /* -3994...4251 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				7921); /* 0...7920 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 4625);

		/* invalid inputs might need reduction mod 7921 */
		a1 -= 7921;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7921);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 126*[89]+[265] */

	R[126] = R[63];
	for (i = 62; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -736);
		a0 = mulhi(a0, 32) - mulhi(lo, 89); /* -45...52 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				89); /* 0...88 */
		a1 = (ri - a0) >> 0;
		a1 = mullo(a1, 18409);

		/* invalid inputs might need reduction mod 89 */
		a1 -= 89;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 89);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 253*[2414]+[7177] */

	ri = R[126];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -6950);
	a0 = mulhi(ri, -84) - mulhi(lo, 2414); /* -1228...1207 */
	a0 += s1; /* -1228...1462 */
	lo = mullo(a0, -6950);
	a0 = mulhi(a0, -84) - mulhi(lo, 2414); /* -1209...1208 */
	a0 += s0; /* -1209...1463 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 2414); /* 0...2413 */
	a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 6407);

	/* invalid inputs might need reduction mod 7177 */
	a1 -= 7177;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7177);

	R[252] = a0;
	R[253] = a1;
	for (i = 125; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -6950);
		a0 = mulhi(ri, -84) - mulhi(lo, 2414); /* -1228...1207 */
		a0 += s1; /* -1228...1462 */
		lo = mullo(a0, -6950);
		a0 = mulhi(a0, -84) - mulhi(lo, 2414); /* -1209...1208 */
		a0 += s0; /* -1209...1463 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2414); /* 0...2413 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, 6407);

		/* invalid inputs might need reduction mod 2414 */
		a1 -= 2414;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2414);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 506*[786]+[7177] */

	R[506] = R[253];
	for (i = 252; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -21345);
		a0 = mulhi(ri, 46) - mulhi(lo, 786); /* -393...404 */
		a0 += s0; /* -393...659 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				786); /* 0...785 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -15175);

		/* invalid inputs might need reduction mod 786 */
		a1 -= 786;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 786);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 1013*[7177] */

	R[1012] = R[506] - 3588;
	for (i = 505; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2338);
		a0 = mulhi(ri, -2610) - mulhi(lo, 7177); /* -4241...3588 */
		a0 += s1; /* -4241...3843 */
		lo = mullo(a0, -2338);
		a0 = mulhi(a0, -2610) - mulhi(lo, 7177); /* -3742...3757 */
		a0 += s0; /* -3742...4012 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				7177); /* 0...7176 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 12857);

		/* invalid inputs might need reduction mod 7177 */
		a1 -= 7177;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7177);

		R[2 * i] = a0 - 3588;
		R[2 * i + 1] = a1 - 3588;
	}
}
