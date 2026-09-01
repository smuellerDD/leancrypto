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
#include "sntrup_int32.h"

static int16_t mullo(int16_t x, int16_t y)
{
	return x * y;
}

static int16_t mulhi(int16_t x, int16_t y)
{
	return (int16_t)((x * (int32_t)y) >> 16);
}

void sntrup_decode_1013x2393(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_1013x2393_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, 4749);
	a1 = mulhi(a1, 4) - mulhi(lo, 276);
	a1 += *--s; /* -138...393 */
	a1 -= 276; /* -414...117 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 276); /* -138...275 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 276); /* 0...275 */
	R[0] = a1;

	/* reconstruct mod 1*[14506]+[1243] */

	ri = R[0];
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

	/* invalid inputs might need reduction mod 1243 */
	a1 -= 1243;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1243);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[1927]+[165] */

	ri = R[1];
	s0 = *--s;
	lo = mullo(ri, -8706);
	a0 = mulhi(ri, 754) - mulhi(lo, 1927); /* -964...1152 */
	a0 += s0; /* -964...1407 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1927); /* 0...1926 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 3639);

	/* invalid inputs might need reduction mod 165 */
	a1 -= 165;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 165);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
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

	/* reconstruct mod 7*[11236]+[962] */

	ri = R[3];
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

	/* invalid inputs might need reduction mod 962 */
	a1 -= 962;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 962);

	R[6] = a0;
	R[7] = a1;
	for (i = 2; i >= 0; --i) {
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

	/* reconstruct mod 15*[106]+[2322] */

	ri = R[7];
	s0 = *--s;
	lo = mullo(ri, -27204);
	a0 = mulhi(ri, -40) - mulhi(lo, 106); /* -63...53 */
	a0 += s0; /* -63...308 */
	lo = mullo(a0, -618);
	a0 = mulhi(a0, 28) - mulhi(lo, 106); /* -54...53 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 106); /* 0...105 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 21021);

	/* invalid inputs might need reduction mod 2322 */
	a1 -= 2322;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2322);

	R[14] = a0;
	R[15] = a1;
	for (i = 6; i >= 0; --i) {
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

	/* reconstruct mod 31*[164]+[3624] */

	ri = R[15];
	s0 = *--s;
	lo = mullo(ri, 28772);
	a0 = mulhi(ri, 16) - mulhi(lo, 164); /* -82...86 */
	a0 += s0; /* -82...341 */
	lo = mullo(a0, -400);
	a0 = mulhi(a0, -64) - mulhi(lo, 164); /* -83...82 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 164); /* 0...163 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -25575);

	/* invalid inputs might need reduction mod 3624 */
	a1 -= 3624;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3624);

	R[30] = a0;
	R[31] = a1;
	for (i = 14; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 28772);
		a0 = mulhi(ri, 16) - mulhi(lo, 164); /* -82...86 */
		a0 += s0; /* -82...341 */
		lo = mullo(a0, -400);
		a0 = mulhi(a0, -64) - mulhi(lo, 164); /* -83...82 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				164); /* 0...163 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -25575);

		/* invalid inputs might need reduction mod 164 */
		a1 -= 164;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 164);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 63*[3278]+[283] */

	ri = R[31];
	s0 = *--s;
	lo = mullo(ri, -5118);
	a0 = mulhi(ri, 412) - mulhi(lo, 3278); /* -1639...1742 */
	a0 += s0; /* -1639...1997 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 3278); /* 0...3277 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, -19113);

	/* invalid inputs might need reduction mod 283 */
	a1 -= 283;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 283);

	R[62] = a0;
	R[63] = a1;
	for (i = 30; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -5118);
		a0 = mulhi(ri, 412) - mulhi(lo, 3278); /* -1639...1742 */
		a0 += s1; /* -1639...1997 */
		lo = mullo(a0, -5118);
		a0 = mulhi(a0, 412) - mulhi(lo, 3278); /* -1650...1651 */
		a0 += s0; /* -1650...1906 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				3278); /* 0...3277 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -19113);

		/* invalid inputs might need reduction mod 3278 */
		a1 -= 3278;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3278);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 126*[916]+[283] */

	R[126] = R[63];
	for (i = 62; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -18316);
		a0 = mulhi(ri, -240) - mulhi(lo, 916); /* -518...458 */
		a0 += s0; /* -518...713 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				916); /* 0...915 */
		a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
		a1 = mullo(a1, -17171);

		/* invalid inputs might need reduction mod 916 */
		a1 -= 916;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 916);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 253*[7744]+[2393] */

	ri = R[126];
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

	/* invalid inputs might need reduction mod 2393 */
	a1 -= 2393;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2393);

	R[252] = a0;
	R[253] = a1;
	for (i = 125; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2166);
		a0 = mulhi(ri, 3712) - mulhi(lo, 7744); /* -3872...4800 */
		a0 += s1; /* -3872...5055 */
		lo = mullo(a0, -2166);
		a0 = mulhi(a0, 3712) - mulhi(lo, 7744); /* -4092...4158 */
		a0 += s0; /* -4092...4413 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				7744); /* 0...7743 */
		a1 = (int16_t)((ri << 10) + (s1 << 2) + ((s0 - a0) >> 6));
		a1 = mullo(a1, 27081);

		/* invalid inputs might need reduction mod 7744 */
		a1 -= 7744;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 7744);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 506*[88]+[2393] */

	R[506] = R[253];
	for (i = 252; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -745);
		a0 = mulhi(a0, -24) - mulhi(lo, 88); /* -50...44 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				88); /* 0...87 */
		a1 = (int16_t)((ri - a0) >> 3);
		a1 = mullo(a1, -29789);

		/* invalid inputs might need reduction mod 88 */
		a1 -= 88;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 88);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 1013*[2393] */

	R[1012] = (int16_t)(3 * R[506] - 3588);
	for (i = 505; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -7011);
		a0 = mulhi(ri, -107) - mulhi(lo, 2393); /* -1224...1196 */
		a0 += s1; /* -1224...1451 */
		lo = mullo(a0, -7011);
		a0 = mulhi(a0, -107) - mulhi(lo, 2393); /* -1199...1198 */
		a0 += s0; /* -1199...1453 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2393); /* 0...2392 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -20759);

		/* invalid inputs might need reduction mod 2393 */
		a1 -= 2393;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2393);

		R[2 * i] = (int16_t)(3 * a0 - 3588);
		R[2 * i + 1] = (int16_t)(3 * a1 - 3588);
	}
}
