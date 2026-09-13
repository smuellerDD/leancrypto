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

void sntrup_decode_953x2115_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_953x2115_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 -= 124; /* -124...131 */
	a1 -= 124; /* -248...7 */
	a1 += (int16_t)(124 & sntrup_int16_negative_mask(a1)); /* -124...123 */
	a1 += (int16_t)(124 & sntrup_int16_negative_mask(a1)); /* 0...123 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[3846]+[2107] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, 964) - mulhi(mullo(a0, -4362), 3846); /* -1923...2164 */
	a0 += s[2 * i + 1]; /* -1923...2419 */
	a0 = mulhi(a0, 964) - mulhi(mullo(a0, -4362), 3846); /* -1952...1958 */
	a0 += s[2 * i + 0]; /* -1952...2213 */
	a0 += (int16_t)(3846 & sntrup_int16_negative_mask(a0)); /* 0...3845 */
	a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
		       ((s[2 * i] - a0) >> 1));
	a1 = mullo(a1, -16597);

	/* invalid inputs might need reduction mod 2107 */
	a1 -= 2107;
	a1 += (int16_t)(2107 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[15876]+[8694] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, -3716) -
	     mulhi(mullo(a0, -1057), 15876); /* -8867...7938 */
	a0 += s[2 * i + 1]; /* -8867...8193 */
	a0 = mulhi(a0, -3716) -
	     mulhi(mullo(a0, -1057), 15876); /* -8403...8440 */
	a0 += s[2 * i + 0]; /* -8403...8695 */
	a0 += (int16_t)(15876 & sntrup_int16_negative_mask(a0)); /* 0...15875 */
	a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
		       ((s[2 * i] - a0) >> 2));
	a1 = mullo(a1, 12417);

	/* invalid inputs might need reduction mod 8694 */
	a1 -= 8694;
	a1 += (int16_t)(8694 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 2;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -3716) -
		     mulhi(mullo(a0, -1057), 15876); /* -8867...7938 */
		a0 += s[2 * i + 1]; /* -8867...8193 */
		a0 = mulhi(a0, -3716) -
		     mulhi(mullo(a0, -1057), 15876); /* -8403...8440 */
		a0 += s[2 * i + 0]; /* -8403...8695 */
		a0 += (int16_t)(15876 &
				sntrup_int16_negative_mask(a0)); /* 0...15875 */
		a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
			       ((s[2 * i] - a0) >> 2));
		a1 = mullo(a1, 12417);

		/* invalid inputs might need reduction mod 15876 */
		a1 -= 15876;
		a1 += (int16_t)(15876 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 7*[126]+[69] */

	i = 0;
	s -= 0;
	a2 = a0 = ws->R8[3];
	a0 = mulhi(a0, 16) - mulhi(mullo(a0, -520), 126); /* -63...67 */
	a0 += (int16_t)(126 & sntrup_int16_negative_mask(a0)); /* 0...125 */
	a1 = (int16_t)((a2 - a0) >> 1);
	a1 = mullo(a1, -4161);

	/* invalid inputs might need reduction mod 69 */
	a1 -= 69;
	a1 += (int16_t)(69 & sntrup_int16_negative_mask(a1));

	ws->R7[6] = a0;
	ws->R7[7] = a1;
	s -= 0;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, 16) - mulhi(mullo(a0, -520), 126); /* -63...67 */
		a0 += (int16_t)(126 &
				sntrup_int16_negative_mask(a0)); /* 0...125 */
		a1 = (int16_t)((a2 - a0) >> 1);
		a1 = mullo(a1, -4161);

		/* invalid inputs might need reduction mod 126 */
		a1 -= 126;
		a1 += (int16_t)(126 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 14*[2863]+[69] */

	ws->R6[14] = ws->R7[7];
	s -= 14;
	for (i = 6; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, 36) -
		     mulhi(mullo(a0, -5860), 2863); /* -1432...1440 */
		a0 += s[2 * i + 1]; /* -1432...1695 */
		a0 = mulhi(a0, 36) -
		     mulhi(mullo(a0, -5860), 2863); /* -1433...1432 */
		a0 += s[2 * i + 0]; /* -1433...1687 */
		a0 += (int16_t)(2863 &
				sntrup_int16_negative_mask(a0)); /* 0...2862 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, 7119);

		/* invalid inputs might need reduction mod 2863 */
		a1 -= 2863;
		a1 += (int16_t)(2863 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 29*[856]+[5227] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R6[14];
	a0 = mulhi(a0, -384) - mulhi(mullo(a0, -19600), 856); /* -524...428 */
	a0 += s[2 * i + 1]; /* -524...683 */
	a0 = mulhi(a0, -384) - mulhi(mullo(a0, -19600), 856); /* -433...431 */
	a0 += s[2 * i + 0]; /* -433...686 */
	a0 += (int16_t)(856 & sntrup_int16_negative_mask(a0)); /* 0...855 */
	a1 = (int16_t)((a2 << 13) + (s[2 * i + 1] << 5) +
		       ((s[2 * i] - a0) >> 3));
	a1 = mullo(a1, -21437);

	/* invalid inputs might need reduction mod 5227 */
	a1 -= 5227;
	a1 += (int16_t)(5227 & sntrup_int16_negative_mask(a1));

	ws->R5[28] = a0;
	ws->R5[29] = a1;
	s -= 14;
	for (i = 13; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, -384) -
		     mulhi(mullo(a0, -19600), 856); /* -524...428 */
		a0 += s[1 * i + 0]; /* -524...683 */
		a0 += (int16_t)(856 &
				sntrup_int16_negative_mask(a0)); /* 0...855 */
		a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
		a1 = mullo(a1, -21437);

		/* invalid inputs might need reduction mod 856 */
		a1 -= 856;
		a1 += (int16_t)(856 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 59*[468]+[2859] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[29];
	a0 = mulhi(a0, -116) - mulhi(mullo(a0, 29687), 468); /* -263...234 */
	a0 += s[1 * i + 0]; /* -263...489 */
	a0 -= 468; /* -731..>21 */
	a0 += (int16_t)(468 & sntrup_int16_negative_mask(a0)); /* -263...467 */
	a0 += (int16_t)(468 & sntrup_int16_negative_mask(a0)); /* 0...467 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -12323);

	/* invalid inputs might need reduction mod 2859 */
	a1 -= 2859;
	a1 += (int16_t)(2859 & sntrup_int16_negative_mask(a1));

	ws->R4[58] = a0;
	ws->R4[59] = a1;
	s -= 29;
	i = 13;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -116),
			     mulhiconst(mulloconst(ws->A0, 29687),
					468)); /* -263...234 */
		ws->A0 = add(ws->A0, ws->S0); /* -263...489 */
		ws->A0 = subconst(ws->A0, 468); /* -731...21 */
		ws->A0 = ifnegaddconst(ws->A0, 468); /* -263...467 */
		ws->A0 = ifnegaddconst(ws->A0, 468); /* 0...467 */
		ws->A1 = add(shiftleftconst(ws->A2, 6),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, -12323);

		/* invalid inputs might need reduction mod 468 */
		ws->A1 = ifgesubconst(ws->A1, 468);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 119*[346]+[2115] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R4[59];
	a0 = mulhi(a0, 22) - mulhi(mullo(a0, 17047), 346); /* -173...178 */
	a0 += s[1 * i + 0]; /* -173...433 */
	a0 -= 346; /* -519..>87 */
	a0 += (int16_t)(346 & sntrup_int16_negative_mask(a0)); /* -173...345 */
	a0 += (int16_t)(346 & sntrup_int16_negative_mask(a0)); /* 0...345 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, 25381);

	/* invalid inputs might need reduction mod 2115 */
	a1 -= 2115;
	a1 += (int16_t)(2115 & sntrup_int16_negative_mask(a1));

	ws->R3[118] = a0;
	ws->R3[119] = a1;
	s -= 59;
	i = 43;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 22),
			     mulhiconst(mulloconst(ws->A0, 17047),
					346)); /* -173...178 */
		ws->A0 = add(ws->A0, ws->S0); /* -173...433 */
		ws->A0 = subconst(ws->A0, 346); /* -519...87 */
		ws->A0 = ifnegaddconst(ws->A0, 346); /* -173...345 */
		ws->A0 = ifnegaddconst(ws->A0, 346); /* 0...345 */
		ws->A1 = add(shiftleftconst(ws->A2, 7),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, 25381);

		/* invalid inputs might need reduction mod 346 */
		ws->A1 = ifgesubconst(ws->A1, 346);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 238*[4761]+[2115] */

	ws->R2[238] = ws->R3[119];
	s -= 238;
	i = 103;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -548),
			     mulhiconst(mulloconst(ws->A0, -3524),
					4761)); /* -2518...2380 */
		ws->A0 = add(ws->A0, ws->S1); /* -2518...2635 */
		ws->A0 = sub(mulhiconst(ws->A0, -548),
			     mulhiconst(mulloconst(ws->A0, -3524),
					4761)); /* -2403...2401 */
		ws->A0 = add(ws->A0, ws->S0); /* -2403...2656 */
		ws->A0 = ifnegaddconst(ws->A0, 4761); /* 0...4760 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 8617);

		/* invalid inputs might need reduction mod 4761 */
		ws->A1 = ifgesubconst(ws->A1, 4761);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 476*[69]+[2115] */

	ws->R1[476] = ws->R2[238];
	s -= 0;
	i = 222;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->A0 = sub(mulhiconst(ws->A0, -14),
			     mulhiconst(mulloconst(ws->A0, -950),
					69)); /* -38...34 */
		ws->A0 = ifnegaddconst(ws->A0, 69); /* 0...68 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 0);
		ws->A1 = mulloconst(ws->A1, 4749);

		/* invalid inputs might need reduction mod 69 */
		ws->A1 = ifgesubconst(ws->A1, 69);

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

	/* ws->R1 ------> R0: reconstruct mod 953*[2115] */

	R0[952] = (int16_t)(3 * ws->R1[476] - 3171);
	s -= 952;
	i = 460;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1036),
			     mulhiconst(mulloconst(ws->A0, -7932),
					2115)); /* -1058...1316 */
		ws->A0 = add(ws->A0, ws->S1); /* -1058...1571 */
		ws->A0 = sub(mulhiconst(ws->A0, 1036),
			     mulhiconst(mulloconst(ws->A0, -7932),
					2115)); /* -1075...1082 */
		ws->A0 = add(ws->A0, ws->S0); /* -1075...1337 */
		ws->A0 = ifnegaddconst(ws->A0, 2115); /* 0...2114 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -31637);

		/* invalid inputs might need reduction mod 2115 */
		ws->A1 = ifgesubconst(ws->A1, 2115);

		ws->A0 = mulloconst(ws->A0, 3);
		ws->A1 = mulloconst(ws->A1, 3);
		ws->A0 = subconst(ws->A0, 3171);
		ws->A1 = subconst(ws->A1, 3171);
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
