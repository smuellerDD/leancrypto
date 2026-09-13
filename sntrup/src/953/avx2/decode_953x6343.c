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

void sntrup_decode_953x6343_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_953x6343_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, -272) - mulhi(mullo(a1, -1336), 12558);
	a1 += *--s; /* -6279...6532 */
	a1 += (int16_t)(12558 & sntrup_int16_negative_mask(a1)); /* 0...12557 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[2383]+[1349] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, 896) - mulhi(mullo(a0, -7040), 2383); /* -1192...1415 */
	a0 += s[1 * i + 0]; /* -1192...1670 */
	a0 += (int16_t)(2383 & sntrup_int16_negative_mask(a0)); /* 0...2382 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 28079);

	/* invalid inputs might need reduction mod 1349 */
	a1 -= 1349;
	a1 += (int16_t)(1349 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[781]+[442] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, -226) - mulhi(mullo(a0, -21482), 781); /* -447...390 */
	a0 += s[1 * i + 0]; /* -447...645 */
	a0 += (int16_t)(781 & sntrup_int16_negative_mask(a0)); /* 0...780 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -31803);

	/* invalid inputs might need reduction mod 442 */
	a1 -= 442;
	a1 += (int16_t)(442 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -226) -
		     mulhi(mullo(a0, -21482), 781); /* -447...390 */
		a0 += s[1 * i + 0]; /* -447...645 */
		a0 += (int16_t)(781 &
				sntrup_int16_negative_mask(a0)); /* 0...780 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, -31803);

		/* invalid inputs might need reduction mod 781 */
		a1 -= 781;
		a1 += (int16_t)(781 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 7*[447]+[253] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[3];
	a0 = mulhi(a0, -35) - mulhi(mullo(a0, 28003), 447); /* -233...223 */
	a0 += s[1 * i + 0]; /* -233...478 */
	a0 -= 447; /* -680..>31 */
	a0 += (int16_t)(447 & sntrup_int16_negative_mask(a0)); /* -233...446 */
	a0 += (int16_t)(447 & sntrup_int16_negative_mask(a0)); /* 0...446 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -4545);

	/* invalid inputs might need reduction mod 253 */
	a1 -= 253;
	a1 += (int16_t)(253 & sntrup_int16_negative_mask(a1));

	ws->R7[6] = a0;
	ws->R7[7] = a1;
	s -= 3;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -35) -
		     mulhi(mullo(a0, 28003), 447); /* -233...223 */
		a0 += s[1 * i + 0]; /* -233...478 */
		a0 -= 447; /* -680..>31 */
		a0 += (int16_t)(447 & sntrup_int16_negative_mask(
					      a0)); /* -233...446 */
		a0 += (int16_t)(447 &
				sntrup_int16_negative_mask(a0)); /* 0...446 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, -4545);

		/* invalid inputs might need reduction mod 447 */
		a1 -= 447;
		a1 += (int16_t)(447 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 14*[338]+[253] */

	ws->R6[14] = ws->R7[7];
	s -= 7;
	for (i = 6; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, -90) -
		     mulhi(mullo(a0, 15899), 338); /* -192...169 */
		a0 += s[1 * i + 0]; /* -192...424 */
		a0 -= 338; /* -530..>86 */
		a0 += (int16_t)(338 & sntrup_int16_negative_mask(
					      a0)); /* -192...337 */
		a0 += (int16_t)(338 &
				sntrup_int16_negative_mask(a0)); /* 0...337 */
		a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
		a1 = mullo(a1, -23655);

		/* invalid inputs might need reduction mod 338 */
		a1 -= 338;
		a1 += (int16_t)(338 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 29*[4701]+[3519] */

	i = 0;
	s -= 2;
	//a2 = a0 = ws->R6[14];
	a0 = ws->R6[14];
	a0 = mulhi(a0, -653) - mulhi(mullo(a0, -3569), 4701); /* -2514...2350 */
	a0 += s[2 * i + 1]; /* -2514...2605 */
	a0 = mulhi(a0, -653) - mulhi(mullo(a0, -3569), 4701); /* -2377...2375 */
	a0 += s[2 * i + 0]; /* -2377...2630 */
	a0 += (int16_t)(4701 & sntrup_int16_negative_mask(a0)); /* 0...4700 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, 20981);

	/* invalid inputs might need reduction mod 3519 */
	a1 -= 3519;
	a1 += (int16_t)(3519 & sntrup_int16_negative_mask(a1));

	ws->R5[28] = a0;
	ws->R5[29] = a1;
	s -= 28;
	for (i = 13; i >= 0; --i) {
		//a2 = a0 = ws->R6[i];
		a0 = ws->R6[i];
		a0 = mulhi(a0, -653) -
		     mulhi(mullo(a0, -3569), 4701); /* -2514...2350 */
		a0 += s[2 * i + 1]; /* -2514...2605 */
		a0 = mulhi(a0, -653) -
		     mulhi(mullo(a0, -3569), 4701); /* -2377...2375 */
		a0 += s[2 * i + 0]; /* -2377...2630 */
		a0 += (int16_t)(4701 &
				sntrup_int16_negative_mask(a0)); /* 0...4700 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, 20981);

		/* invalid inputs might need reduction mod 4701 */
		a1 -= 4701;
		a1 += (int16_t)(4701 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 59*[1097]+[821] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[29];
	a0 = mulhi(a0, -302) - mulhi(mullo(a0, -15294), 1097); /* -624...548 */
	a0 += s[1 * i + 0]; /* -624...803 */
	a0 += (int16_t)(1097 & sntrup_int16_negative_mask(a0)); /* 0...1096 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 11769);

	/* invalid inputs might need reduction mod 821 */
	a1 -= 821;
	a1 += (int16_t)(821 & sntrup_int16_negative_mask(a1));

	ws->R4[58] = a0;
	ws->R4[59] = a1;
	s -= 29;
	i = 13;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -302),
			     mulhiconst(mulloconst(ws->A0, -15294),
					1097)); /* -624...548 */
		ws->A0 = add(ws->A0, ws->S0); /* -624...803 */
		ws->A0 = ifnegaddconst(ws->A0, 1097); /* 0...1096 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 11769);

		/* invalid inputs might need reduction mod 1097 */
		ws->A1 = ifgesubconst(ws->A1, 1097);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 119*[8476]+[6343] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R4[59];
	a0 = mulhi(a0, 3212) - mulhi(mullo(a0, -1979), 8476); /* -4238...5041 */
	a0 += s[2 * i + 1]; /* -4238...5296 */
	a0 = mulhi(a0, 3212) - mulhi(mullo(a0, -1979), 8476); /* -4446...4497 */
	a0 += s[2 * i + 0]; /* -4446...4752 */
	a0 += (int16_t)(8476 & sntrup_int16_negative_mask(a0)); /* 0...8475 */
	a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
		       ((s[2 * i] - a0) >> 2));
	a1 = mullo(a1, 8567);

	/* invalid inputs might need reduction mod 6343 */
	a1 -= 6343;
	a1 += (int16_t)(6343 & sntrup_int16_negative_mask(a1));

	ws->R3[118] = a0;
	ws->R3[119] = a1;
	s -= 118;
	i = 43;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 3212),
			     mulhiconst(mulloconst(ws->A0, -1979),
					8476)); /* -4238...5041 */
		ws->A0 = add(ws->A0, ws->S1); /* -4238...5296 */
		ws->A0 = sub(mulhiconst(ws->A0, 3212),
			     mulhiconst(mulloconst(ws->A0, -1979),
					8476)); /* -4446...4497 */
		ws->A0 = add(ws->A0, ws->S0); /* -4446...4752 */
		ws->A0 = ifnegaddconst(ws->A0, 8476); /* 0...8475 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 14),
				 shiftleftconst(ws->S1, 6)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, 8567);

		/* invalid inputs might need reduction mod 8476 */
		ws->A1 = ifgesubconst(ws->A1, 8476);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 238*[1473]+[6343] */

	ws->R2[238] = ws->R3[119];
	s -= 119;
	i = 103;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -254),
			     mulhiconst(mulloconst(ws->A0, -11390),
					1473)); /* -800...736 */
		ws->A0 = add(ws->A0, ws->S0); /* -800...991 */
		ws->A0 = ifnegaddconst(ws->A0, 1473); /* 0...1472 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 2625);

		/* invalid inputs might need reduction mod 1473 */
		ws->A1 = ifgesubconst(ws->A1, 1473);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 476*[614]+[6343] */

	ws->R1[476] = ws->R2[238];
	s -= 238;
	i = 222;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 280),
			     mulhiconst(mulloconst(ws->A0, -27324),
					614)); /* -307...377 */
		ws->A0 = add(ws->A0, ws->S0); /* -307...632 */
		ws->A0 = subconst(ws->A0, 614); /* -921...18 */
		ws->A0 = ifnegaddconst(ws->A0, 614); /* -307...613 */
		ws->A0 = ifnegaddconst(ws->A0, 614); /* 0...613 */
		ws->A1 = add(shiftleftconst(ws->A2, 7),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, -7685);

		/* invalid inputs might need reduction mod 614 */
		ws->A1 = ifgesubconst(ws->A1, 614);

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

	/* ws->R1 ------> R0: reconstruct mod 953*[6343] */

	R0[952] = ws->R1[476] - 3171;
	s -= 952;
	i = 460;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -19),
			     mulhiconst(mulloconst(ws->A0, -2645),
					6343)); /* -3177...3171 */
		ws->A0 = add(ws->A0, ws->S1); /* -3177...3426 */
		ws->A0 = sub(mulhiconst(ws->A0, -19),
			     mulhiconst(mulloconst(ws->A0, -2645),
					6343)); /* -3173...3172 */
		ws->A0 = add(ws->A0, ws->S0); /* -3173...3427 */
		ws->A0 = ifnegaddconst(ws->A0, 6343); /* 0...6342 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 10487);

		/* invalid inputs might need reduction mod 6343 */
		ws->A1 = ifgesubconst(ws->A1, 6343);

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
