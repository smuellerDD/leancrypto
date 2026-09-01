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

void sntrup_decode_857x5167(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_857x5167_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, -2695);
	a1 = mulhi(a1, 841) - mulhi(lo, 6225);
	a1 += *--s; /* -3113...3370 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 6225); /* 0...6224 */
	R[0] = a1;

	/* reconstruct mod 1*[5476]+[291] */

	ri = R[0];
	s0 = *--s;
	lo = mullo(ri, -3064);
	a0 = mulhi(ri, -1248) - mulhi(lo, 5476); /* -3050...2738 */
	a0 += s0; /* -3050...2993 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 5476); /* 0...5475 */
	a1 = (int16_t)((ri << 6) + ((s0 - a0) >> 2));
	a1 = mullo(a1, -3351);

	/* invalid inputs might need reduction mod 291 */
	a1 -= 291;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 291);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 3*[74]+[1004] */

	ri = R[1];
	s0 = *--s;
	lo = mullo(ri, -30111);
	a0 = mulhi(ri, 10) - mulhi(lo, 74); /* -37...39 */
	a0 += s0; /* -37...294 */
	lo = mullo(a0, -886);
	a0 = mulhi(a0, -28) - mulhi(lo, 74); /* -38...37 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 74); /* 0...73 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, 7085);

	/* invalid inputs might need reduction mod 1004 */
	a1 -= 1004;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1004);

	R[2] = a0;
	R[3] = a1;
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		a0 = ri;
		lo = mullo(a0, -886);
		a0 = mulhi(a0, -28) - mulhi(lo, 74); /* -44...37 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				74); /* 0...73 */
		a1 = (int16_t)((ri - a0) >> 1);
		a1 = mullo(a1, 7085);

		/* invalid inputs might need reduction mod 74 */
		a1 -= 74;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 74);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 6*[2194]+[1004] */

	R[6] = R[3];
	for (i = 2; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -7647);
		a0 = mulhi(ri, -302) - mulhi(lo, 2194); /* -1173...1097 */
		a0 += s1; /* -1173...1352 */
		lo = mullo(a0, -7647);
		a0 = mulhi(a0, -302) - mulhi(lo, 2194); /* -1104...1102 */
		a0 += s0; /* -1104...1357 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				2194); /* 0...2193 */
		a1 = (int16_t)((ri << 15) + (s1 << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, 11769);

		/* invalid inputs might need reduction mod 2194 */
		a1 -= 2194;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2194);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 13*[11991]+[5483] */

	ri = R[6];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1399);
	a0 = mulhi(ri, 1807) - mulhi(lo, 11991); /* -5996...6447 */
	a0 += s1; /* -5996...6702 */
	lo = mullo(a0, -1399);
	a0 = mulhi(a0, 1807) - mulhi(lo, 11991); /* -6161...6180 */
	a0 += s0; /* -6161...6435 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 11991); /* 0...11990 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, -23321);

	/* invalid inputs might need reduction mod 5483 */
	a1 -= 5483;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5483);

	R[12] = a0;
	R[13] = a1;
	for (i = 5; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1399);
		a0 = mulhi(ri, 1807) - mulhi(lo, 11991); /* -5996...6447 */
		a0 += s1; /* -5996...6702 */
		lo = mullo(a0, -1399);
		a0 = mulhi(a0, 1807) - mulhi(lo, 11991); /* -6161...6180 */
		a0 += s0; /* -6161...6435 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				11991); /* 0...11990 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -23321);

		/* invalid inputs might need reduction mod 11991 */
		a1 -= 11991;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 11991);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 26*[1752]+[5483] */

	R[26] = R[13];
	for (i = 12; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -9576);
		a0 = mulhi(ri, 64) - mulhi(lo, 1752); /* -876...892 */
		a0 += s0; /* -876...1147 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1752); /* 0...1751 */
		a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, -1197);

		/* invalid inputs might need reduction mod 1752 */
		a1 -= 1752;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1752);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 53*[10713]+[131] */

	ri = R[26];
	s0 = *--s;
	lo = mullo(ri, -1566);
	a0 = mulhi(ri, 658) - mulhi(lo, 10713); /* -5357...5521 */
	a0 += s0; /* -5357...5776 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 10713); /* 0...10712 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -14743);

	/* invalid inputs might need reduction mod 131 */
	a1 -= 131;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 131);

	R[52] = a0;
	R[53] = a1;
	for (i = 25; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1566);
		a0 = mulhi(ri, 658) - mulhi(lo, 10713); /* -5357...5521 */
		a0 += s1; /* -5357...5776 */
		lo = mullo(a0, -1566);
		a0 = mulhi(a0, 658) - mulhi(lo, 10713); /* -5411...5414 */
		a0 += s0; /* -5411...5669 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				10713); /* 0...10712 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -14743);

		/* invalid inputs might need reduction mod 10713 */
		a1 -= 10713;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 10713);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 107*[1656]+[5167] */

	ri = R[53];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -10131);
	a0 = mulhi(ri, 280) - mulhi(lo, 1656); /* -828...898 */
	a0 += s1; /* -828...1153 */
	lo = mullo(a0, -10131);
	a0 = mulhi(a0, 280) - mulhi(lo, 1656); /* -832...832 */
	a0 += s0; /* -832...1087 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1656); /* 0...1655 */
	a1 = (int16_t)((ri << 13) + (s1 << 5) + ((s0 - a0) >> 3));
	a1 = mullo(a1, 1583);

	/* invalid inputs might need reduction mod 5167 */
	a1 -= 5167;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5167);

	R[106] = a0;
	R[107] = a1;
	for (i = 52; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -10131);
		a0 = mulhi(ri, 280) - mulhi(lo, 1656); /* -828...898 */
		a0 += s0; /* -828...1153 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1656); /* 0...1655 */
		a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, 1583);

		/* invalid inputs might need reduction mod 1656 */
		a1 -= 1656;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1656);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 214*[651]+[5167] */

	R[214] = R[107];
	for (i = 106; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -25771);
		a0 = mulhi(ri, 295) - mulhi(lo, 651); /* -326...399 */
		a0 += s0; /* -326...654 */
		a0 -= 651; /* -977..>3 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				651); /* -326...650 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				651); /* 0...650 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -10973);

		/* invalid inputs might need reduction mod 651 */
		a1 -= 651;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 651);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 428*[408]+[5167] */

	R[428] = R[214];
	for (i = 213; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, 24415);
		a0 = mulhi(ri, -152) - mulhi(lo, 408); /* -242...204 */
		a0 += s0; /* -242...459 */
		a0 -= 408; /* -650..>51 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				408); /* -242...407 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				408); /* 0...407 */
		a1 = (int16_t)((ri << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, -1285);

		/* invalid inputs might need reduction mod 408 */
		a1 -= 408;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 408);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 857*[5167] */

	R[856] = R[428] - 2583;
	for (i = 427; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -3247);
		a0 = mulhi(ri, -33) - mulhi(lo, 5167); /* -2592...2583 */
		a0 += s1; /* -2592...2838 */
		lo = mullo(a0, -3247);
		a0 = mulhi(a0, -33) - mulhi(lo, 5167); /* -2585...2584 */
		a0 += s0; /* -2585...2839 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				5167); /* 0...5166 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, -19761);

		/* invalid inputs might need reduction mod 5167 */
		a1 -= 5167;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 5167);

		R[2 * i] = a0 - 2583;
		R[2 * i + 1] = a1 - 2583;
	}
}
