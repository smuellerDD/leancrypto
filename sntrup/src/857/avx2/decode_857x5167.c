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

void sntrup_decode_857x5167_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_857x5167_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, 841) - mulhi(mullo(a1, -2695), 6225);
	a1 += *--s; /* -3113...3370 */
	a1 += (int16_t)(6225 & sntrup_int16_negative_mask(a1)); /* 0...6224 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[5476]+[291] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, -1248) -
	     mulhi(mullo(a0, -3064), 5476); /* -3050...2738 */
	a0 += s[1 * i + 0]; /* -3050...2993 */
	a0 += (int16_t)(5476 & sntrup_int16_negative_mask(a0)); /* 0...5475 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -3351);

	/* invalid inputs might need reduction mod 291 */
	a1 -= 291;
	a1 += (int16_t)(291 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[74]+[1004] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, 10) - mulhi(mullo(a0, -30111), 74); /* -37...39 */
	a0 += s[1 * i + 0]; /* -37...294 */
	a0 = mulhi(a0, -28) - mulhi(mullo(a0, -886), 74); /* -38...37 */
	a0 += (int16_t)(74 & sntrup_int16_negative_mask(a0)); /* 0...73 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, 7085);

	/* invalid inputs might need reduction mod 1004 */
	a1 -= 1004;
	a1 += (int16_t)(1004 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 0;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -28) - mulhi(mullo(a0, -886), 74); /* -44...37 */
		a0 += (int16_t)(74 &
				sntrup_int16_negative_mask(a0)); /* 0...73 */
		a1 = (int16_t)((a2 - a0) >> 1);
		a1 = mullo(a1, 7085);

		/* invalid inputs might need reduction mod 74 */
		a1 -= 74;
		a1 += (int16_t)(74 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 6*[2194]+[1004] */

	ws->R7[6] = ws->R8[3];
	s -= 6;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -302) -
		     mulhi(mullo(a0, -7647), 2194); /* -1173...1097 */
		a0 += s[2 * i + 1]; /* -1173...1352 */
		a0 = mulhi(a0, -302) -
		     mulhi(mullo(a0, -7647), 2194); /* -1104...1102 */
		a0 += s[2 * i + 0]; /* -1104...1357 */
		a0 += (int16_t)(2194 &
				sntrup_int16_negative_mask(a0)); /* 0...2193 */
		a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
			       ((s[2 * i] - a0) >> 1));
		a1 = mullo(a1, 11769);

		/* invalid inputs might need reduction mod 2194 */
		a1 -= 2194;
		a1 += (int16_t)(2194 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 13*[11991]+[5483] */

	i = 0;
	s -= 2;
	//a2 = a0 = ws->R7[6];
	a0 = ws->R7[6];
	a0 = mulhi(a0, 1807) -
	     mulhi(mullo(a0, -1399), 11991); /* -5996...6447 */
	a0 += s[2 * i + 1]; /* -5996...6702 */
	a0 = mulhi(a0, 1807) -
	     mulhi(mullo(a0, -1399), 11991); /* -6161...6180 */
	a0 += s[2 * i + 0]; /* -6161...6435 */
	a0 += (int16_t)(11991 & sntrup_int16_negative_mask(a0)); /* 0...11990 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, -23321);

	/* invalid inputs might need reduction mod 5483 */
	a1 -= 5483;
	a1 += (int16_t)(5483 & sntrup_int16_negative_mask(a1));

	ws->R6[12] = a0;
	ws->R6[13] = a1;
	s -= 12;
	for (i = 5; i >= 0; --i) {
		//a2 = a0 = ws->R7[i];
		a0 = ws->R7[i];
		a0 = mulhi(a0, 1807) -
		     mulhi(mullo(a0, -1399), 11991); /* -5996...6447 */
		a0 += s[2 * i + 1]; /* -5996...6702 */
		a0 = mulhi(a0, 1807) -
		     mulhi(mullo(a0, -1399), 11991); /* -6161...6180 */
		a0 += s[2 * i + 0]; /* -6161...6435 */
		a0 += (int16_t)(11991 &
				sntrup_int16_negative_mask(a0)); /* 0...11990 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, -23321);

		/* invalid inputs might need reduction mod 11991 */
		a1 -= 11991;
		a1 += (int16_t)(11991 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 26*[1752]+[5483] */

	ws->R5[26] = ws->R6[13];
	s -= 13;
	for (i = 12; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, 64) -
		     mulhi(mullo(a0, -9576), 1752); /* -876...892 */
		a0 += s[1 * i + 0]; /* -876...1147 */
		a0 += (int16_t)(1752 &
				sntrup_int16_negative_mask(a0)); /* 0...1751 */
		a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
		a1 = mullo(a1, -1197);

		/* invalid inputs might need reduction mod 1752 */
		a1 -= 1752;
		a1 += (int16_t)(1752 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 53*[10713]+[131] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[26];
	a0 = mulhi(a0, 658) - mulhi(mullo(a0, -1566), 10713); /* -5357...5521 */
	a0 += s[1 * i + 0]; /* -5357...5776 */
	a0 += (int16_t)(10713 & sntrup_int16_negative_mask(a0)); /* 0...10712 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -14743);

	/* invalid inputs might need reduction mod 131 */
	a1 -= 131;
	a1 += (int16_t)(131 & sntrup_int16_negative_mask(a1));

	ws->R4[52] = a0;
	ws->R4[53] = a1;
	s -= 52;
	i = 10;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 658),
			     mulhiconst(mulloconst(ws->A0, -1566),
					10713)); /* -5357...5521 */
		ws->A0 = add(ws->A0, ws->S1); /* -5357...5776 */
		ws->A0 = sub(mulhiconst(ws->A0, 658),
			     mulhiconst(mulloconst(ws->A0, -1566),
					10713)); /* -5411...5414 */
		ws->A0 = add(ws->A0, ws->S0); /* -5411...5669 */
		ws->A0 = ifnegaddconst(ws->A0, 10713); /* 0...10712 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -14743);

		/* invalid inputs might need reduction mod 10713 */
		ws->A1 = ifgesubconst(ws->A1, 10713);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 107*[1656]+[5167] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R4[53];
	a0 = mulhi(a0, 280) - mulhi(mullo(a0, -10131), 1656); /* -828...898 */
	a0 += s[2 * i + 1]; /* -828...1153 */
	a0 = mulhi(a0, 280) - mulhi(mullo(a0, -10131), 1656); /* -832...832 */
	a0 += s[2 * i + 0]; /* -832...1087 */
	a0 += (int16_t)(1656 & sntrup_int16_negative_mask(a0)); /* 0...1655 */
	a1 = (int16_t)((a2 << 13) + (s[2 * i + 1] << 5) +
		       ((s[2 * i] - a0) >> 3));
	a1 = mullo(a1, 1583);

	/* invalid inputs might need reduction mod 5167 */
	a1 -= 5167;
	a1 += (int16_t)(5167 & sntrup_int16_negative_mask(a1));

	ws->R3[106] = a0;
	ws->R3[107] = a1;
	s -= 53;
	i = 37;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 280),
			     mulhiconst(mulloconst(ws->A0, -10131),
					1656)); /* -828...898 */
		ws->A0 = add(ws->A0, ws->S0); /* -828...1153 */
		ws->A0 = ifnegaddconst(ws->A0, 1656); /* 0...1655 */
		ws->A1 = add(shiftleftconst(ws->A2, 5),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 3));
		ws->A1 = mulloconst(ws->A1, 1583);

		/* invalid inputs might need reduction mod 1656 */
		ws->A1 = ifgesubconst(ws->A1, 1656);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 214*[651]+[5167] */

	ws->R2[214] = ws->R3[107];
	s -= 107;
	i = 91;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 295),
			     mulhiconst(mulloconst(ws->A0, -25771),
					651)); /* -326...399 */
		ws->A0 = add(ws->A0, ws->S0); /* -326...654 */
		ws->A0 = subconst(ws->A0, 651); /* -977...3 */
		ws->A0 = ifnegaddconst(ws->A0, 651); /* -326...650 */
		ws->A0 = ifnegaddconst(ws->A0, 651); /* 0...650 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -10973);

		/* invalid inputs might need reduction mod 651 */
		ws->A1 = ifgesubconst(ws->A1, 651);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 428*[408]+[5167] */

	ws->R1[428] = ws->R2[214];
	s -= 214;
	i = 198;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -152),
			     mulhiconst(mulloconst(ws->A0, 24415),
					408)); /* -242...204 */
		ws->A0 = add(ws->A0, ws->S0); /* -242...459 */
		ws->A0 = subconst(ws->A0, 408); /* -650...51 */
		ws->A0 = ifnegaddconst(ws->A0, 408); /* -242...407 */
		ws->A0 = ifnegaddconst(ws->A0, 408); /* 0...407 */
		ws->A1 = add(shiftleftconst(ws->A2, 5),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 3));
		ws->A1 = mulloconst(ws->A1, -1285);

		/* invalid inputs might need reduction mod 408 */
		ws->A1 = ifgesubconst(ws->A1, 408);

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

	/* ws->R1 ------> R0: reconstruct mod 857*[5167] */

	R0[856] = ws->R1[428] - 2583;
	s -= 856;
	i = 412;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -33),
			     mulhiconst(mulloconst(ws->A0, -3247),
					5167)); /* -2592...2583 */
		ws->A0 = add(ws->A0, ws->S1); /* -2592...2838 */
		ws->A0 = sub(mulhiconst(ws->A0, -33),
			     mulhiconst(mulloconst(ws->A0, -3247),
					5167)); /* -2585...2584 */
		ws->A0 = add(ws->A0, ws->S0); /* -2585...2839 */
		ws->A0 = ifnegaddconst(ws->A0, 5167); /* 0...5166 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -19761);

		/* invalid inputs might need reduction mod 5167 */
		ws->A1 = ifgesubconst(ws->A1, 5167);

		ws->A0 = subconst(ws->A0, 2583);
		ws->A1 = subconst(ws->A1, 2583);
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
