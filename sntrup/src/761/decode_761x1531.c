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

void sntrup_decode_761x1531(void *v, const uint8_t *s)
{
	int16_t *R = (int16_t *)v;
	long long i;
	int16_t a0, a1, ri, lo, s0, s1;

	s += sntrup_decode_761x1531_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	lo = mullo(a1, -4828);
	a1 = mulhi(a1, -84) - mulhi(lo, 3475);
	a1 += *--s; /* -1738...1992 */
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 3475); /* 0...3474 */
	R[0] = a1;

	/* reconstruct mod 1*[593]+[1500] */

	ri = R[0];
	s0 = *--s;
	lo = mullo(ri, -28292);
	a0 = mulhi(ri, 60) - mulhi(lo, 593); /* -297...311 */
	a0 += s0; /* -297...566 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 593); /* 0...592 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -31055);

	/* invalid inputs might need reduction mod 1500 */
	a1 -= 1500;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1500);

	R[0] = a0;
	R[1] = a1;

	/* reconstruct mod 2*[6232]+[1500] */

	R[2] = R[1];
	for (i = 0; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2692);
		a0 = mulhi(ri, 672) - mulhi(lo, 6232); /* -3116...3284 */
		a0 += s1; /* -3116...3539 */
		lo = mullo(a0, -2692);
		a0 = mulhi(a0, 672) - mulhi(lo, 6232); /* -3148...3152 */
		a0 += s0; /* -3148...3407 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				6232); /* 0...6231 */
		a1 = (int16_t)((ri << 13) + (s1 << 5) + ((s0 - a0) >> 3));
		a1 = mullo(a1, 12451);

		/* invalid inputs might need reduction mod 6232 */
		a1 -= 6232;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 6232);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 5*[1263]+[304] */

	ri = R[2];
	s0 = *--s;
	lo = mullo(ri, -13284);
	a0 = mulhi(ri, -476) - mulhi(lo, 1263); /* -751...631 */
	a0 += s0; /* -751...886 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1263); /* 0...1262 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, -22001);

	/* invalid inputs might need reduction mod 304 */
	a1 -= 304;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 304);

	R[4] = a0;
	R[5] = a1;
	for (i = 1; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -13284);
		a0 = mulhi(ri, -476) - mulhi(lo, 1263); /* -751...631 */
		a0 += s0; /* -751...886 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1263); /* 0...1262 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, -22001);

		/* invalid inputs might need reduction mod 1263 */
		a1 -= 1263;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1263);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 11*[9097]+[2188] */

	ri = R[5];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -1844);
	a0 = mulhi(ri, 2348) - mulhi(lo, 9097); /* -4549...5135 */
	a0 += s1; /* -4549...5390 */
	lo = mullo(a0, -1844);
	a0 = mulhi(a0, 2348) - mulhi(lo, 9097); /* -4712...4741 */
	a0 += s0; /* -4712...4996 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 9097); /* 0...9096 */
	a1 = (int16_t)((s1 << 8) + s0 - a0);
	a1 = mullo(a1, 17081);

	/* invalid inputs might need reduction mod 2188 */
	a1 -= 2188;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 2188);

	R[10] = a0;
	R[11] = a1;
	for (i = 4; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1844);
		a0 = mulhi(ri, 2348) - mulhi(lo, 9097); /* -4549...5135 */
		a0 += s1; /* -4549...5390 */
		lo = mullo(a0, -1844);
		a0 = mulhi(a0, 2348) - mulhi(lo, 9097); /* -4712...4741 */
		a0 += s0; /* -4712...4996 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				9097); /* 0...9096 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 17081);

		/* invalid inputs might need reduction mod 9097 */
		a1 -= 9097;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 9097);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 23*[1526]+[367] */

	ri = R[11];
	s0 = *--s;
	lo = mullo(ri, -10994);
	a0 = mulhi(ri, 372) - mulhi(lo, 1526); /* -763...856 */
	a0 += s0; /* -763...1111 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 1526); /* 0...1525 */
	a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
	a1 = mullo(a1, -18381);

	/* invalid inputs might need reduction mod 367 */
	a1 -= 367;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 367);

	R[22] = a0;
	R[23] = a1;
	for (i = 10; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -10994);
		a0 = mulhi(ri, 372) - mulhi(lo, 1526); /* -763...856 */
		a0 += s0; /* -763...1111 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1526); /* 0...1525 */
		a1 = (int16_t)((ri << 7) + ((s0 - a0) >> 1));
		a1 = mullo(a1, -18381);

		/* invalid inputs might need reduction mod 1526 */
		a1 -= 1526;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1526);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 47*[625]+[150] */

	ri = R[23];
	s0 = *--s;
	lo = mullo(ri, -26844);
	a0 = mulhi(ri, -284) - mulhi(lo, 625); /* -384...312 */
	a0 += s0; /* -384...567 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 625); /* 0...624 */
	a1 = (int16_t)((ri << 8) + s0 - a0);
	a1 = mullo(a1, 32401);

	/* invalid inputs might need reduction mod 150 */
	a1 -= 150;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 150);

	R[46] = a0;
	R[47] = a1;
	for (i = 22; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -26844);
		a0 = mulhi(ri, -284) - mulhi(lo, 625); /* -384...312 */
		a0 += s0; /* -384...567 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				625); /* 0...624 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 32401);

		/* invalid inputs might need reduction mod 625 */
		a1 -= 625;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 625);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 95*[6400]+[1531] */

	ri = R[47];
	s1 = *--s;
	s0 = *--s;
	lo = mullo(ri, -2621);
	a0 = mulhi(ri, 2816) - mulhi(lo, 6400); /* -3200...3904 */
	a0 += s1; /* -3200...4159 */
	lo = mullo(a0, -2621);
	a0 = mulhi(a0, 2816) - mulhi(lo, 6400); /* -3338...3378 */
	a0 += s0; /* -3338...3633 */
	a0 += (int16_t)(sntrup_int16_negative_mask(a0) & 6400); /* 0...6399 */
	a1 = (int16_t)((ri << 8) + s1 + ((s0 - a0) >> 8));
	a1 = mullo(a1, 23593);

	/* invalid inputs might need reduction mod 1531 */
	a1 -= 1531;
	a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1531);

	R[94] = a0;
	R[95] = a1;
	for (i = 46; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -2621);
		a0 = mulhi(ri, 2816) - mulhi(lo, 6400); /* -3200...3904 */
		a0 += s1; /* -3200...4159 */
		lo = mullo(a0, -2621);
		a0 = mulhi(a0, 2816) - mulhi(lo, 6400); /* -3338...3378 */
		a0 += s0; /* -3338...3633 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				6400); /* 0...6399 */
		a1 = (int16_t)((ri << 8) + s1 + ((s0 - a0) >> 8));
		a1 = mullo(a1, 23593);

		/* invalid inputs might need reduction mod 6400 */
		a1 -= 6400;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 6400);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 190*[1280]+[1531] */

	R[190] = R[95];
	for (i = 94; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -13107);
		a0 = mulhi(ri, 256) - mulhi(lo, 1280); /* -640...704 */
		a0 += s0; /* -640...959 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1280); /* 0...1279 */
		a1 = (int16_t)(ri + ((s0 - a0) >> 8));
		a1 = mullo(a1, -13107);

		/* invalid inputs might need reduction mod 1280 */
		a1 -= 1280;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1280);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 380*[9157]+[1531] */

	R[380] = R[190];
	for (i = 189; i >= 0; --i) {
		ri = R[i];
		s1 = *--s;
		s0 = *--s;
		lo = mullo(ri, -1832);
		a0 = mulhi(ri, 1592) - mulhi(lo, 9157); /* -4579...4976 */
		a0 += s1; /* -4579...5231 */
		lo = mullo(a0, -1832);
		a0 = mulhi(a0, 1592) - mulhi(lo, 9157); /* -4690...4705 */
		a0 += s0; /* -4690...4960 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				9157); /* 0...9156 */
		a1 = (int16_t)((s1 << 8) + s0 - a0);
		a1 = mullo(a1, 25357);

		/* invalid inputs might need reduction mod 9157 */
		a1 -= 9157;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 9157);

		R[2 * i] = a0;
		R[2 * i + 1] = a1;
	}

	/* reconstruct mod 761*[1531] */

	R[760] = (int16_t)(3 * R[380] - 2295);
	for (i = 379; i >= 0; --i) {
		ri = R[i];
		s0 = *--s;
		lo = mullo(ri, -10958);
		a0 = mulhi(ri, 518) - mulhi(lo, 1531); /* -766...895 */
		a0 += s0; /* -766...1150 */
		a0 += (int16_t)(sntrup_int16_negative_mask(a0) &
				1531); /* 0...1530 */
		a1 = (int16_t)((ri << 8) + s0 - a0);
		a1 = mullo(a1, 15667);

		/* invalid inputs might need reduction mod 1531 */
		a1 -= 1531;
		a1 += (int16_t)(sntrup_int16_negative_mask(a1) & 1531);

		R[2 * i] = (int16_t)(3 * a0 - 2295);
		R[2 * i + 1] = (int16_t)(3 * a1 - 2295);
	}
}
