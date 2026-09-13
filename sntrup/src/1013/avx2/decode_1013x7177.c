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

void sntrup_decode_1013x7177_avx2(void *v, const uint8_t *s,
				  struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_1013x7177_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, -78) - mulhi(mullo(a1, 4305), 274);
	a1 += *--s; /* -137...391 */
	a1 -= 274; /* -411...117 */
	a1 += (int16_t)(274 & sntrup_int16_negative_mask(a1)); /* -137...273 */
	a1 += (int16_t)(274 & sntrup_int16_negative_mask(a1)); /* 0...273 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[91]+[769] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, 1) - mulhi(mullo(a0, 12243), 91); /* -46...45 */
	a0 += s[1 * i + 0]; /* -46...300 */
	a0 = mulhi(a0, 16) - mulhi(mullo(a0, -720), 91); /* -46...45 */
	a0 += (int16_t)(91 & sntrup_int16_negative_mask(a0)); /* 0...90 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 12243);

	/* invalid inputs might need reduction mod 769 */
	a1 -= 769;
	a1 += (int16_t)(769 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[152]+[1294] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, 64) - mulhi(mullo(a0, 20696), 152); /* -76...92 */
	a0 += s[1 * i + 0]; /* -76...347 */
	a0 = mulhi(a0, 24) - mulhi(mullo(a0, -431), 152); /* -77...76 */
	a0 += (int16_t)(152 & sntrup_int16_negative_mask(a0)); /* 0...151 */
	a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
	a1 = mullo(a1, -13797);

	/* invalid inputs might need reduction mod 1294 */
	a1 -= 1294;
	a1 += (int16_t)(1294 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, 64) -
		     mulhi(mullo(a0, 20696), 152); /* -76...92 */
		a0 += s[1 * i + 0]; /* -76...347 */
		a0 = mulhi(a0, 24) - mulhi(mullo(a0, -431), 152); /* -77...76 */
		a0 += (int16_t)(152 &
				sntrup_int16_negative_mask(a0)); /* 0...151 */
		a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
		a1 = mullo(a1, -13797);

		/* invalid inputs might need reduction mod 152 */
		a1 -= 152;
		a1 += (int16_t)(152 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 7*[197]+[1681] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[3];
	a0 = mulhi(a0, -92) - mulhi(mullo(a0, -19628), 197); /* -122...98 */
	a0 += s[1 * i + 0]; /* -122...353 */
	a0 -= 197; /* -319..>156 */
	a0 += (int16_t)(197 & sntrup_int16_negative_mask(a0)); /* -122...196 */
	a0 += (int16_t)(197 & sntrup_int16_negative_mask(a0)); /* 0...196 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 32269);

	/* invalid inputs might need reduction mod 1681 */
	a1 -= 1681;
	a1 += (int16_t)(1681 & sntrup_int16_negative_mask(a1));

	ws->R7[6] = a0;
	ws->R7[7] = a1;
	s -= 3;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -92) -
		     mulhi(mullo(a0, -19628), 197); /* -122...98 */
		a0 += s[1 * i + 0]; /* -122...353 */
		a0 -= 197; /* -319..>156 */
		a0 += (int16_t)(197 & sntrup_int16_negative_mask(
					      a0)); /* -122...196 */
		a0 += (int16_t)(197 &
				sntrup_int16_negative_mask(a0)); /* 0...196 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, 32269);

		/* invalid inputs might need reduction mod 197 */
		a1 -= 197;
		a1 += (int16_t)(197 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 15*[3586]+[120] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R7[7];
	a0 = mulhi(a0, -1678) -
	     mulhi(mullo(a0, -4679), 3586); /* -2213...1793 */
	a0 += s[1 * i + 0]; /* -2213...2048 */
	a0 += (int16_t)(3586 & sntrup_int16_negative_mask(a0)); /* 0...3585 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, -1791);

	/* invalid inputs might need reduction mod 120 */
	a1 -= 120;
	a1 += (int16_t)(120 & sntrup_int16_negative_mask(a1));

	ws->R6[14] = a0;
	ws->R6[15] = a1;
	s -= 14;
	for (i = 6; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, -1678) -
		     mulhi(mullo(a0, -4679), 3586); /* -2213...1793 */
		a0 += s[2 * i + 1]; /* -2213...2048 */
		a0 = mulhi(a0, -1678) -
		     mulhi(mullo(a0, -4679), 3586); /* -1846...1849 */
		a0 += s[2 * i + 0]; /* -1846...2104 */
		a0 += (int16_t)(3586 &
				sntrup_int16_negative_mask(a0)); /* 0...3585 */
		a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
			       ((s[2 * i] - a0) >> 1));
		a1 = mullo(a1, -1791);

		/* invalid inputs might need reduction mod 3586 */
		a1 -= 3586;
		a1 += (int16_t)(3586 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 31*[958]+[8200] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R6[15];
	a0 = mulhi(a0, -238) - mulhi(mullo(a0, -17513), 958); /* -539...479 */
	a0 += s[2 * i + 1]; /* -539...734 */
	a0 = mulhi(a0, -238) - mulhi(mullo(a0, -17513), 958); /* -482...480 */
	a0 += s[2 * i + 0]; /* -482...735 */
	a0 += (int16_t)(958 & sntrup_int16_negative_mask(a0)); /* 0...957 */
	a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
		       ((s[2 * i] - a0) >> 1));
	a1 = mullo(a1, -1505);

	/* invalid inputs might need reduction mod 8200 */
	a1 -= 8200;
	a1 += (int16_t)(8200 & sntrup_int16_negative_mask(a1));

	ws->R5[30] = a0;
	ws->R5[31] = a1;
	s -= 15;
	for (i = 14; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, -238) -
		     mulhi(mullo(a0, -17513), 958); /* -539...479 */
		a0 += s[1 * i + 0]; /* -539...734 */
		a0 += (int16_t)(958 &
				sntrup_int16_negative_mask(a0)); /* 0...957 */
		a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
		a1 = mullo(a1, -1505);

		/* invalid inputs might need reduction mod 958 */
		a1 -= 958;
		a1 += (int16_t)(958 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 63*[7921]+[265] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[31];
	a0 = mulhi(a0, 538) - mulhi(mullo(a0, -2118), 7921); /* -3961...4095 */
	a0 += s[1 * i + 0]; /* -3961...4350 */
	a0 += (int16_t)(7921 & sntrup_int16_negative_mask(a0)); /* 0...7920 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 4625);

	/* invalid inputs might need reduction mod 265 */
	a1 -= 265;
	a1 += (int16_t)(265 & sntrup_int16_negative_mask(a1));

	ws->R4[62] = a0;
	ws->R4[63] = a1;
	s -= 62;
	i = 15;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 538),
			     mulhiconst(mulloconst(ws->A0, -2118),
					7921)); /* -3961...4095 */
		ws->A0 = add(ws->A0, ws->S1); /* -3961...4350 */
		ws->A0 = sub(mulhiconst(ws->A0, 538),
			     mulhiconst(mulloconst(ws->A0, -2118),
					7921)); /* -3994...3996 */
		ws->A0 = add(ws->A0, ws->S0); /* -3994...4251 */
		ws->A0 = ifnegaddconst(ws->A0, 7921); /* 0...7920 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 4625);

		/* invalid inputs might need reduction mod 7921 */
		ws->A1 = ifgesubconst(ws->A1, 7921);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 126*[89]+[265] */

	ws->R3[126] = ws->R4[63];
	s -= 0;
	i = 47;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->A0 = sub(mulhiconst(ws->A0, 32),
			     mulhiconst(mulloconst(ws->A0, -736),
					89)); /* -45...52 */
		ws->A0 = ifnegaddconst(ws->A0, 89); /* 0...88 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 0);
		ws->A1 = mulloconst(ws->A1, 18409);

		/* invalid inputs might need reduction mod 89 */
		ws->A1 = ifgesubconst(ws->A1, 89);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 253*[2414]+[7177] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R3[126];
	a0 = mulhi(a0, -84) - mulhi(mullo(a0, -6950), 2414); /* -1228...1207 */
	a0 += s[2 * i + 1]; /* -1228...1462 */
	a0 = mulhi(a0, -84) - mulhi(mullo(a0, -6950), 2414); /* -1209...1208 */
	a0 += s[2 * i + 0]; /* -1209...1463 */
	a0 += (int16_t)(2414 & sntrup_int16_negative_mask(a0)); /* 0...2413 */
	a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
		       ((s[2 * i] - a0) >> 1));
	a1 = mullo(a1, 6407);

	/* invalid inputs might need reduction mod 7177 */
	a1 -= 7177;
	a1 += (int16_t)(7177 & sntrup_int16_negative_mask(a1));

	ws->R2[252] = a0;
	ws->R2[253] = a1;
	s -= 252;
	i = 110;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -84),
			     mulhiconst(mulloconst(ws->A0, -6950),
					2414)); /* -1228...1207 */
		ws->A0 = add(ws->A0, ws->S1); /* -1228...1462 */
		ws->A0 = sub(mulhiconst(ws->A0, -84),
			     mulhiconst(mulloconst(ws->A0, -6950),
					2414)); /* -1209...1208 */
		ws->A0 = add(ws->A0, ws->S0); /* -1209...1463 */
		ws->A0 = ifnegaddconst(ws->A0, 2414); /* 0...2413 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 15),
				 shiftleftconst(ws->S1, 7)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, 6407);

		/* invalid inputs might need reduction mod 2414 */
		ws->A1 = ifgesubconst(ws->A1, 2414);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 506*[786]+[7177] */

	ws->R1[506] = ws->R2[253];
	s -= 253;
	i = 237;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 46),
			     mulhiconst(mulloconst(ws->A0, -21345),
					786)); /* -393...404 */
		ws->A0 = add(ws->A0, ws->S0); /* -393...659 */
		ws->A0 = ifnegaddconst(ws->A0, 786); /* 0...785 */
		ws->A1 = add(shiftleftconst(ws->A2, 7),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, -15175);

		/* invalid inputs might need reduction mod 786 */
		ws->A1 = ifgesubconst(ws->A1, 786);

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

	/* ws->R1 ------> R0: reconstruct mod 1013*[7177] */

	R0[1012] = ws->R1[506] - 3588;
	s -= 1012;
	i = 490;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -2610),
			     mulhiconst(mulloconst(ws->A0, -2338),
					7177)); /* -4241...3588 */
		ws->A0 = add(ws->A0, ws->S1); /* -4241...3843 */
		ws->A0 = sub(mulhiconst(ws->A0, -2610),
			     mulhiconst(mulloconst(ws->A0, -2338),
					7177)); /* -3742...3757 */
		ws->A0 = add(ws->A0, ws->S0); /* -3742...4012 */
		ws->A0 = ifnegaddconst(ws->A0, 7177); /* 0...7176 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 12857);

		/* invalid inputs might need reduction mod 7177 */
		ws->A1 = ifgesubconst(ws->A1, 7177);

		ws->A0 = subconst(ws->A0, 3588);
		ws->A1 = subconst(ws->A1, 3588);
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
