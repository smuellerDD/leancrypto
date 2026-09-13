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

void sntrup_decode_857x1723_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_857x1723_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 -= 160; /* -160...95 */
	a1 += (int16_t)(160 & sntrup_int16_negative_mask(a1)); /* 0...159 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[743]+[14044] */

	i = 0;
	s -= 2;
	//a2 = a0 = ws->R10[0];
	a0 = ws->R10[0];
	a0 = mulhi(a0, 276) - mulhi(mullo(a0, -22580), 743); /* -372...440 */
	a0 += s[2 * i + 1]; /* -372...695 */
	a0 = mulhi(a0, 276) - mulhi(mullo(a0, -22580), 743); /* -374...374 */
	a0 += s[2 * i + 0]; /* -374...629 */
	a0 += (int16_t)(743 & sntrup_int16_negative_mask(a0)); /* 0...742 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, -3881);

	/* invalid inputs might need reduction mod 14044 */
	a1 -= 14044;
	a1 += (int16_t)(14044 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[436]+[8246] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, -64) - mulhi(mullo(a0, 27056), 436); /* -234...218 */
	a0 += s[1 * i + 0]; /* -234...473 */
	a0 -= 436; /* -670..>37 */
	a0 += (int16_t)(436 & sntrup_int16_negative_mask(a0)); /* -234...435 */
	a0 += (int16_t)(436 & sntrup_int16_negative_mask(a0)); /* 0...435 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, 2405);

	/* invalid inputs might need reduction mod 8246 */
	a1 -= 8246;
	a1 += (int16_t)(8246 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -64) -
		     mulhi(mullo(a0, 27056), 436); /* -234...218 */
		a0 += s[1 * i + 0]; /* -234...473 */
		a0 -= 436; /* -670..>37 */
		a0 += (int16_t)(436 & sntrup_int16_negative_mask(
					      a0)); /* -234...435 */
		a0 += (int16_t)(436 &
				sntrup_int16_negative_mask(a0)); /* 0...435 */
		a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
		a1 = mullo(a1, 2405);

		/* invalid inputs might need reduction mod 436 */
		a1 -= 436;
		a1 += (int16_t)(436 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 6*[334]+[8246] */

	ws->R7[6] = ws->R8[3];
	s -= 3;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, 62) -
		     mulhi(mullo(a0, 15305), 334); /* -167...182 */
		a0 += s[1 * i + 0]; /* -167...437 */
		a0 -= 334; /* -501..>103 */
		a0 += (int16_t)(334 & sntrup_int16_negative_mask(
					      a0)); /* -167...333 */
		a0 += (int16_t)(334 &
				sntrup_int16_negative_mask(a0)); /* 0...333 */
		a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
		a1 = mullo(a1, -22761);

		/* invalid inputs might need reduction mod 334 */
		a1 -= 334;
		a1 += (int16_t)(334 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 13*[292]+[7229] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R7[6];
	a0 = mulhi(a0, 64) - mulhi(mullo(a0, 8080), 292); /* -146...162 */
	a0 += s[1 * i + 0]; /* -146...417 */
	a0 -= 292; /* -438..>125 */
	a0 += (int16_t)(292 & sntrup_int16_negative_mask(a0)); /* -146...291 */
	a0 += (int16_t)(292 & sntrup_int16_negative_mask(a0)); /* 0...291 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -3591);

	/* invalid inputs might need reduction mod 7229 */
	a1 -= 7229;
	a1 += (int16_t)(7229 & sntrup_int16_negative_mask(a1));

	ws->R6[12] = a0;
	ws->R6[13] = a1;
	s -= 6;
	for (i = 5; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, 64) -
		     mulhi(mullo(a0, 8080), 292); /* -146...162 */
		a0 += s[1 * i + 0]; /* -146...417 */
		a0 -= 292; /* -438..>125 */
		a0 += (int16_t)(292 & sntrup_int16_negative_mask(
					      a0)); /* -146...291 */
		a0 += (int16_t)(292 &
				sntrup_int16_negative_mask(a0)); /* 0...291 */
		a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
		a1 = mullo(a1, -3591);

		/* invalid inputs might need reduction mod 292 */
		a1 -= 292;
		a1 += (int16_t)(292 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 26*[273]+[7229] */

	ws->R5[26] = ws->R6[13];
	s -= 13;
	for (i = 12; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, 1) -
		     mulhi(mullo(a0, 4081), 273); /* -137...136 */
		a0 += s[1 * i + 0]; /* -137...391 */
		a0 -= 273; /* -410..>118 */
		a0 += (int16_t)(273 & sntrup_int16_negative_mask(
					      a0)); /* -137...272 */
		a0 += (int16_t)(273 &
				sntrup_int16_negative_mask(a0)); /* 0...272 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, 4081);

		/* invalid inputs might need reduction mod 273 */
		a1 -= 273;
		a1 += (int16_t)(273 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 53*[4225]+[438] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[26];
	a0 = mulhi(a0, -259) - mulhi(mullo(a0, -3971), 4225); /* -2178...2112 */
	a0 += s[1 * i + 0]; /* -2178...2367 */
	a0 += (int16_t)(4225 & sntrup_int16_negative_mask(a0)); /* 0...4224 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 12161);

	/* invalid inputs might need reduction mod 438 */
	a1 -= 438;
	a1 += (int16_t)(438 & sntrup_int16_negative_mask(a1));

	ws->R4[52] = a0;
	ws->R4[53] = a1;
	s -= 52;
	i = 10;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -259),
			     mulhiconst(mulloconst(ws->A0, -3971),
					4225)); /* -2178...2112 */
		ws->A0 = add(ws->A0, ws->S1); /* -2178...2367 */
		ws->A0 = sub(mulhiconst(ws->A0, -259),
			     mulhiconst(mulloconst(ws->A0, -3971),
					4225)); /* -2122...2121 */
		ws->A0 = add(ws->A0, ws->S0); /* -2122...2376 */
		ws->A0 = ifnegaddconst(ws->A0, 4225); /* 0...4224 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 12161);

		/* invalid inputs might need reduction mod 4225 */
		ws->A1 = ifgesubconst(ws->A1, 4225);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 107*[65]+[1723] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R4[53];
	a0 = mulhi(a0, 1) - mulhi(mullo(a0, 4033), 65); /* -33...32 */
	a0 += s[1 * i + 0]; /* -33...287 */
	a0 = mulhi(a0, 16) - mulhi(mullo(a0, -1008), 65); /* -33...32 */
	a0 += (int16_t)(65 & sntrup_int16_negative_mask(a0)); /* 0...64 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 4033);

	/* invalid inputs might need reduction mod 1723 */
	a1 -= 1723;
	a1 += (int16_t)(1723 & sntrup_int16_negative_mask(a1));

	ws->R3[106] = a0;
	ws->R3[107] = a1;
	s -= 0;
	i = 37;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->A0 = sub(mulhiconst(ws->A0, 16),
			     mulhiconst(mulloconst(ws->A0, -1008),
					65)); /* -33...36 */
		ws->A0 = ifnegaddconst(ws->A0, 65); /* 0...64 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 0);
		ws->A1 = mulloconst(ws->A1, 4033);

		/* invalid inputs might need reduction mod 65 */
		ws->A1 = ifgesubconst(ws->A1, 65);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 214*[2053]+[1723] */

	ws->R2[214] = ws->R3[107];
	s -= 214;
	i = 91;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 100),
			     mulhiconst(mulloconst(ws->A0, -8172),
					2053)); /* -1027...1051 */
		ws->A0 = add(ws->A0, ws->S1); /* -1027...1306 */
		ws->A0 = sub(mulhiconst(ws->A0, 100),
			     mulhiconst(mulloconst(ws->A0, -8172),
					2053)); /* -1029...1028 */
		ws->A0 = add(ws->A0, ws->S0); /* -1029...1283 */
		ws->A0 = ifnegaddconst(ws->A0, 2053); /* 0...2052 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -31539);

		/* invalid inputs might need reduction mod 2053 */
		ws->A1 = ifgesubconst(ws->A1, 2053);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 428*[11597]+[1723] */

	ws->R1[428] = ws->R2[214];
	s -= 428;
	i = 198;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -3643),
			     mulhiconst(mulloconst(ws->A0, -1447),
					11597)); /* -6710...5798 */
		ws->A0 = add(ws->A0, ws->S1); /* -6710...6053 */
		ws->A0 = sub(mulhiconst(ws->A0, -3643),
			     mulhiconst(mulloconst(ws->A0, -1447),
					11597)); /* -6135...6171 */
		ws->A0 = add(ws->A0, ws->S0); /* -6135...6426 */
		ws->A0 = ifnegaddconst(ws->A0, 11597); /* 0...11596 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -11387);

		/* invalid inputs might need reduction mod 11597 */
		ws->A1 = ifgesubconst(ws->A1, 11597);

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

	/* ws->R1 ------> R0: reconstruct mod 857*[1723] */

	R0[856] = (int16_t)(3 * ws->R1[428] - 2583);
	s -= 428;
	i = 412;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 365),
			     mulhiconst(mulloconst(ws->A0, -9737),
					1723)); /* -862...952 */
		ws->A0 = add(ws->A0, ws->S0); /* -862...1207 */
		ws->A0 = ifnegaddconst(ws->A0, 1723); /* 0...1722 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 20083);

		/* invalid inputs might need reduction mod 1723 */
		ws->A1 = ifgesubconst(ws->A1, 1723);

		ws->A0 = mulloconst(ws->A0, 3);
		ws->A1 = mulloconst(ws->A1, 3);
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
