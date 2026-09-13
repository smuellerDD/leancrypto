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
 * SPDX-License-Identifier: LicenseRef-PD-hp OR Cws->C0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#include "ext_headers_x86.h"
#include "sntrup_int16.h"
#include "params.h"

static inline int16_t mullo(int16_t x, int16_t y)
{
	return x * y;
}

static inline int16_t mulhi(int16_t x, int16_t y)
{
	return (int16_t)((x * (int32_t)y) >> 16);
}

static inline __m256i add(__m256i x, __m256i y)
{
	return _mm256_add_epi16(x, y);
}

static inline __m256i sub(__m256i x, __m256i y)
{
	return _mm256_sub_epi16(x, y);
}

static inline __m256i shiftleftconst(__m256i x, int16_t y)
{
	return _mm256_slli_epi16(x, y);
}

static inline __m256i signedshiftrightconst(__m256i x, int16_t y)
{
	return _mm256_srai_epi16(x, y);
}

static inline __m256i subconst(__m256i x, int16_t y)
{
	return sub(x, _mm256_set1_epi16(y));
}

static inline __m256i mulloconst(__m256i x, int16_t y)
{
	return _mm256_mullo_epi16(x, _mm256_set1_epi16(y));
}

static inline __m256i mulhiconst(__m256i x, int16_t y)
{
	return _mm256_mulhi_epi16(x, _mm256_set1_epi16(y));
}

static inline __m256i ifgesubconst(__m256i x, int16_t y)
{
	__m256i y16 = _mm256_set1_epi16(y);
	__m256i top16 = _mm256_set1_epi16(y - 1);
	return sub(x, _mm256_cmpgt_epi16(x, top16) & y16);
}

static inline __m256i ifnegaddconst(__m256i x, int16_t y)
{
	return add(x, signedshiftrightconst(x, 15) & _mm256_set1_epi16(y));
}

void sntrup_decode_761x1531_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_761x1531_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, -84) - mulhi(mullo(a1, -4828), 3475);
	a1 += *--s; /* -1738...1992 */
	a1 += (int16_t)(3475 & sntrup_int16_negative_mask(a1)); /* 0...3474 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[593]+[1500] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, 60) - mulhi(mullo(a0, -28292), 593); /* -297...311 */
	a0 += s[1 * i + 0]; /* -297...566 */
	a0 += (int16_t)(593 & sntrup_int16_negative_mask(a0)); /* 0...592 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -31055);

	/* invalid inputs might need reduction mod 1500 */
	a1 -= 1500;
	a1 += (int16_t)(1500 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 2*[6232]+[1500] */

	ws->R8[2] = ws->R9[1];
	s -= 2;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, 672) -
		     mulhi(mullo(a0, -2692), 6232); /* -3116...3284 */
		a0 += s[2 * i + 1]; /* -3116...3539 */
		a0 = mulhi(a0, 672) -
		     mulhi(mullo(a0, -2692), 6232); /* -3148...3152 */
		a0 += s[2 * i + 0]; /* -3148...3407 */
		a0 += (int16_t)(6232 &
				sntrup_int16_negative_mask(a0)); /* 0...6231 */
		a1 = (int16_t)((a2 << 13) + (s[2 * i + 1] << 5) +
			       ((s[2 * i] - a0) >> 3));
		a1 = mullo(a1, 12451);

		/* invalid inputs might need reduction mod 6232 */
		a1 -= 6232;
		a1 += (int16_t)(6232 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 5*[1263]+[304] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[2];
	a0 = mulhi(a0, -476) - mulhi(mullo(a0, -13284), 1263); /* -751...631 */
	a0 += s[1 * i + 0]; /* -751...886 */
	a0 += (int16_t)(1263 & sntrup_int16_negative_mask(a0)); /* 0...1262 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -22001);

	/* invalid inputs might need reduction mod 304 */
	a1 -= 304;
	a1 += (int16_t)(304 & sntrup_int16_negative_mask(a1));

	ws->R7[4] = a0;
	ws->R7[5] = a1;
	s -= 2;
	for (i = 1; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -476) -
		     mulhi(mullo(a0, -13284), 1263); /* -751...631 */
		a0 += s[1 * i + 0]; /* -751...886 */
		a0 += (int16_t)(1263 &
				sntrup_int16_negative_mask(a0)); /* 0...1262 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, -22001);

		/* invalid inputs might need reduction mod 1263 */
		a1 -= 1263;
		a1 += (int16_t)(1263 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 11*[9097]+[2188] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R7[5];
	a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097); /* -4549...5135 */
	a0 += s[2 * i + 1]; /* -4549...5390 */
	a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097); /* -4712...4741 */
	a0 += s[2 * i + 0]; /* -4712...4996 */
	a0 += (int16_t)(9097 & sntrup_int16_negative_mask(a0)); /* 0...9096 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, 17081);

	/* invalid inputs might need reduction mod 2188 */
	a1 -= 2188;
	a1 += (int16_t)(2188 & sntrup_int16_negative_mask(a1));

	ws->R6[10] = a0;
	ws->R6[11] = a1;
	s -= 10;
	for (i = 4; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, 2348) -
		     mulhi(mullo(a0, -1844), 9097); /* -4549...5135 */
		a0 += s[2 * i + 1]; /* -4549...5390 */
		a0 = mulhi(a0, 2348) -
		     mulhi(mullo(a0, -1844), 9097); /* -4712...4741 */
		a0 += s[2 * i + 0]; /* -4712...4996 */
		a0 += (int16_t)(9097 &
				sntrup_int16_negative_mask(a0)); /* 0...9096 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, 17081);

		/* invalid inputs might need reduction mod 9097 */
		a1 -= 9097;
		a1 += (int16_t)(9097 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 23*[1526]+[367] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R6[11];
	a0 = mulhi(a0, 372) - mulhi(mullo(a0, -10994), 1526); /* -763...856 */
	a0 += s[1 * i + 0]; /* -763...1111 */
	a0 += (int16_t)(1526 & sntrup_int16_negative_mask(a0)); /* 0...1525 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, -18381);

	/* invalid inputs might need reduction mod 367 */
	a1 -= 367;
	a1 += (int16_t)(367 & sntrup_int16_negative_mask(a1));

	ws->R5[22] = a0;
	ws->R5[23] = a1;
	s -= 11;
	for (i = 10; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, 372) -
		     mulhi(mullo(a0, -10994), 1526); /* -763...856 */
		a0 += s[1 * i + 0]; /* -763...1111 */
		a0 += (int16_t)(1526 &
				sntrup_int16_negative_mask(a0)); /* 0...1525 */
		a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
		a1 = mullo(a1, -18381);

		/* invalid inputs might need reduction mod 1526 */
		a1 -= 1526;
		a1 += (int16_t)(1526 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 47*[625]+[150] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[23];
	a0 = mulhi(a0, -284) - mulhi(mullo(a0, -26844), 625); /* -384...312 */
	a0 += s[1 * i + 0]; /* -384...567 */
	a0 += (int16_t)(625 & sntrup_int16_negative_mask(a0)); /* 0...624 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 32401);

	/* invalid inputs might need reduction mod 150 */
	a1 -= 150;
	a1 += (int16_t)(150 & sntrup_int16_negative_mask(a1));

	ws->R4[46] = a0;
	ws->R4[47] = a1;
	s -= 23;
	i = 7;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -284),
			     mulhiconst(mulloconst(ws->A0, -26844),
					625)); /* -384...312 */
		ws->A0 = add(ws->A0, ws->S0); /* -384...567 */
		ws->A0 = ifnegaddconst(ws->A0, 625); /* 0...624 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 32401);

		/* invalid inputs might need reduction mod 625 */
		ws->A1 = ifgesubconst(ws->A1, 625);

		/* ws->A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30 */
		/* ws->A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31 */
		ws->B0 = _mm256_unpacklo_epi16(ws->A0, ws->A1);
		ws->B1 = _mm256_unpackhi_epi16(ws->A0, ws->A1);
		/* ws->B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23 */
		/* ws->B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31 */
		ws->C0 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x20);
		ws->C1 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x31);
		/* ws->C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15 */
		/* ws->C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31 */
		_mm256_storeu_si256((__m256i *)(&ws->R4[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &ws->R4[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	/* ws->R4 ------> ws->R3: reconstruct mod 95*[6400]+[1531] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R4[47];
	a0 = mulhi(a0, 2816) - mulhi(mullo(a0, -2621), 6400); /* -3200...3904 */
	a0 += s[2 * i + 1]; /* -3200...4159 */
	a0 = mulhi(a0, 2816) - mulhi(mullo(a0, -2621), 6400); /* -3338...3378 */
	a0 += s[2 * i + 0]; /* -3338...3633 */
	a0 += (int16_t)(6400 & sntrup_int16_negative_mask(a0)); /* 0...6399 */
	a1 = (int16_t)((a2 << 8) + s[2 * i + 1] + ((s[2 * i] - a0) >> 8));
	a1 = mullo(a1, 23593);

	/* invalid inputs might need reduction mod 1531 */
	a1 -= 1531;
	a1 += (int16_t)(1531 & sntrup_int16_negative_mask(a1));

	ws->R3[94] = a0;
	ws->R3[95] = a1;
	s -= 94;
	i = 31;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 2816),
			     mulhiconst(mulloconst(ws->A0, -2621),
					6400)); /* -3200...3904 */
		ws->A0 = add(ws->A0, ws->S1); /* -3200...4159 */
		ws->A0 = sub(mulhiconst(ws->A0, 2816),
			     mulhiconst(mulloconst(ws->A0, -2621),
					6400)); /* -3338...3378 */
		ws->A0 = add(ws->A0, ws->S0); /* -3338...3633 */
		ws->A0 = ifnegaddconst(ws->A0, 6400); /* 0...6399 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 8), ws->S1),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 8));
		ws->A1 = mulloconst(ws->A1, 23593);

		/* invalid inputs might need reduction mod 6400 */
		ws->A1 = ifgesubconst(ws->A1, 6400);

		/* ws->A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30 */
		/* ws->A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31 */
		ws->B0 = _mm256_unpacklo_epi16(ws->A0, ws->A1);
		ws->B1 = _mm256_unpackhi_epi16(ws->A0, ws->A1);
		/* ws->B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23 */
		/* ws->B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31 */
		ws->C0 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x20);
		ws->C1 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x31);
		/* ws->C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15 */
		/* ws->C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31 */
		_mm256_storeu_si256((__m256i *)(&ws->R3[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &ws->R3[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	/* ws->R3 ------> ws->R2: reconstruct mod 190*[1280]+[1531] */

	ws->R2[190] = ws->R3[95];
	s -= 95;
	i = 79;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 256),
			     mulhiconst(mulloconst(ws->A0, -13107),
					1280)); /* -640...704 */
		ws->A0 = add(ws->A0, ws->S0); /* -640...959 */
		ws->A0 = ifnegaddconst(ws->A0, 1280); /* 0...1279 */
		ws->A1 = add(ws->A2,
			     signedshiftrightconst(sub(ws->S0, ws->A0), 8));
		ws->A1 = mulloconst(ws->A1, -13107);

		/* invalid inputs might need reduction mod 1280 */
		ws->A1 = ifgesubconst(ws->A1, 1280);

		/* ws->A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30 */
		/* ws->A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31 */
		ws->B0 = _mm256_unpacklo_epi16(ws->A0, ws->A1);
		ws->B1 = _mm256_unpackhi_epi16(ws->A0, ws->A1);
		/* ws->B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23 */
		/* ws->B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31 */
		ws->C0 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x20);
		ws->C1 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x31);
		/* ws->C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15 */
		/* ws->C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31 */
		_mm256_storeu_si256((__m256i *)(&ws->R2[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &ws->R2[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	/* ws->R2 ------> ws->R1: reconstruct mod 380*[9157]+[1531] */

	ws->R1[380] = ws->R2[190];
	s -= 380;
	i = 174;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1592),
			     mulhiconst(mulloconst(ws->A0, -1832),
					9157)); /* -4579...4976 */
		ws->A0 = add(ws->A0, ws->S1); /* -4579...5231 */
		ws->A0 = sub(mulhiconst(ws->A0, 1592),
			     mulhiconst(mulloconst(ws->A0, -1832),
					9157)); /* -4690...4705 */
		ws->A0 = add(ws->A0, ws->S0); /* -4690...4960 */
		ws->A0 = ifnegaddconst(ws->A0, 9157); /* 0...9156 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 25357);

		/* invalid inputs might need reduction mod 9157 */
		ws->A1 = ifgesubconst(ws->A1, 9157);

		/* ws->A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30 */
		/* ws->A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31 */
		ws->B0 = _mm256_unpacklo_epi16(ws->A0, ws->A1);
		ws->B1 = _mm256_unpackhi_epi16(ws->A0, ws->A1);
		/* ws->B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23 */
		/* ws->B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31 */
		ws->C0 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x20);
		ws->C1 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x31);
		/* ws->C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15 */
		/* ws->C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31 */
		_mm256_storeu_si256((__m256i *)(&ws->R1[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &ws->R1[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	/* ws->R1 ------> R0: reconstruct mod 761*[1531] */

	R0[760] = (int16_t)(3 * ws->R1[380] - 2295);
	s -= 380;
	i = 364;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 518),
			     mulhiconst(mulloconst(ws->A0, -10958),
					1531)); /* -766...895 */
		ws->A0 = add(ws->A0, ws->S0); /* -766...1150 */
		ws->A0 = ifnegaddconst(ws->A0, 1531); /* 0...1530 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 15667);

		/* invalid inputs might need reduction mod 1531 */
		ws->A1 = ifgesubconst(ws->A1, 1531);

		ws->A0 = mulloconst(ws->A0, 3);
		ws->A1 = mulloconst(ws->A1, 3);
		ws->A0 = subconst(ws->A0, 2295);
		ws->A1 = subconst(ws->A1, 2295);
		/* ws->A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30 */
		/* ws->A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31 */
		ws->B0 = _mm256_unpacklo_epi16(ws->A0, ws->A1);
		ws->B1 = _mm256_unpackhi_epi16(ws->A0, ws->A1);
		/* ws->B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23 */
		/* ws->B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31 */
		ws->C0 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x20);
		ws->C1 = _mm256_permute2x128_si256(ws->B0, ws->B1, 0x31);
		/* ws->C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15 */
		/* ws->C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31 */
		_mm256_storeu_si256((__m256i *)(&R0[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &R0[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	LC_FPU_DISABLE;

#pragma GCC diagnostic pop
}
