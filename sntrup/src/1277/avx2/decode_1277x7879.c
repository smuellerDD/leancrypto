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

void sntrup_decode_1277x7879_avx2(void *v, const uint8_t *s,
				  struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_1277x7879_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, 1072) - mulhi(mullo(a1, -4539), 3696);
	a1 += *--s; /* -1848...2107 */
	a1 += (int16_t)(3696 & sntrup_int16_negative_mask(a1)); /* 0...3695 */
	ws->R11[0] = a1;

	/* ws->R11 ------> ws->R10: reconstruct mod 1*[376]+[2516] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R11[0];
	a0 = mulhi(a0, 96) - mulhi(mullo(a0, 20916), 376); /* -188...212 */
	a0 += s[1 * i + 0]; /* -188...467 */
	a0 -= 376; /* -564..>91 */
	a0 += (int16_t)(376 & sntrup_int16_negative_mask(a0)); /* -188...375 */
	a0 += (int16_t)(376 & sntrup_int16_negative_mask(a0)); /* 0...375 */
	a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
	a1 = mullo(a1, 18127);

	/* invalid inputs might need reduction mod 2516 */
	a1 -= 2516;
	a1 += (int16_t)(2516 & sntrup_int16_negative_mask(a1));

	ws->R10[0] = a0;
	ws->R10[1] = a1;
	s -= 0;

	/* ws->R10 ------> ws->R9: reconstruct mod 2*[4962]+[2516] */

	ws->R9[2] = ws->R10[1];
	s -= 2;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R10[i];
		a0 = mulhi(a0, 694) -
		     mulhi(mullo(a0, -3381), 4962); /* -2481...2654 */
		a0 += s[2 * i + 1]; /* -2481...2909 */
		a0 = mulhi(a0, 694) -
		     mulhi(mullo(a0, -3381), 4962); /* -2508...2511 */
		a0 += s[2 * i + 0]; /* -2508...2766 */
		a0 += (int16_t)(4962 &
				sntrup_int16_negative_mask(a0)); /* 0...4961 */
		a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
			       ((s[2 * i] - a0) >> 1));
		a1 = mullo(a1, -24751);

		/* invalid inputs might need reduction mod 4962 */
		a1 -= 4962;
		a1 += (int16_t)(4962 & sntrup_int16_negative_mask(a1));

		ws->R9[2 * i] = a0;
		ws->R9[2 * i + 1] = a1;
	}

	/* ws->R9 ------> ws->R8: reconstruct mod 4*[1127]+[2516] */

	ws->R8[4] = ws->R9[2];
	s -= 2;
	for (i = 1; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -433) -
		     mulhi(mullo(a0, -14887), 1127); /* -672...563 */
		a0 += s[1 * i + 0]; /* -672...818 */
		a0 += (int16_t)(1127 &
				sntrup_int16_negative_mask(a0)); /* 0...1126 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, -10409);

		/* invalid inputs might need reduction mod 1127 */
		a1 -= 1127;
		a1 += (int16_t)(1127 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 9*[537]+[1199] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[4];
	a0 = mulhi(a0, 262) - mulhi(mullo(a0, -31242), 537); /* -269...334 */
	a0 += s[1 * i + 0]; /* -269...589 */
	a0 -= 537; /* -806..>52 */
	a0 += (int16_t)(537 & sntrup_int16_negative_mask(a0)); /* -269...536 */
	a0 += (int16_t)(537 & sntrup_int16_negative_mask(a0)); /* 0...536 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 14889);

	/* invalid inputs might need reduction mod 1199 */
	a1 -= 1199;
	a1 += (int16_t)(1199 & sntrup_int16_negative_mask(a1));

	ws->R7[8] = a0;
	ws->R7[9] = a1;
	s -= 4;
	for (i = 3; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, 262) -
		     mulhi(mullo(a0, -31242), 537); /* -269...334 */
		a0 += s[1 * i + 0]; /* -269...589 */
		a0 -= 537; /* -806..>52 */
		a0 += (int16_t)(537 & sntrup_int16_negative_mask(
					      a0)); /* -269...536 */
		a0 += (int16_t)(537 &
				sntrup_int16_negative_mask(a0)); /* 0...536 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, 14889);

		/* invalid inputs might need reduction mod 537 */
		a1 -= 537;
		a1 += (int16_t)(537 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 19*[5929]+[13244] */

	i = 0;
	s -= 2;
	//a2 = a0 = ws->R7[9];
	a0 = ws->R7[9];
	a0 = mulhi(a0, -1854) -
	     mulhi(mullo(a0, -2830), 5929); /* -3428...2964 */
	a0 += s[2 * i + 1]; /* -3428...3219 */
	a0 = mulhi(a0, -1854) -
	     mulhi(mullo(a0, -2830), 5929); /* -3056...3061 */
	a0 += s[2 * i + 0]; /* -3056...3316 */
	a0 += (int16_t)(5929 & sntrup_int16_negative_mask(a0)); /* 0...5928 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, 29977);

	/* invalid inputs might need reduction mod 13244 */
	a1 -= 13244;
	a1 += (int16_t)(13244 & sntrup_int16_negative_mask(a1));

	ws->R6[18] = a0;
	ws->R6[19] = a1;
	s -= 18;
	for (i = 8; i >= 0; --i) {
		//a2 = a0 = ws->R7[i];
		a0 = ws->R7[i];
		a0 = mulhi(a0, -1854) -
		     mulhi(mullo(a0, -2830), 5929); /* -3428...2964 */
		a0 += s[2 * i + 1]; /* -3428...3219 */
		a0 = mulhi(a0, -1854) -
		     mulhi(mullo(a0, -2830), 5929); /* -3056...3061 */
		a0 += s[2 * i + 0]; /* -3056...3316 */
		a0 += (int16_t)(5929 &
				sntrup_int16_negative_mask(a0)); /* 0...5928 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, 29977);

		/* invalid inputs might need reduction mod 5929 */
		a1 -= 5929;
		a1 += (int16_t)(5929 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 39*[77]+[172] */

	//i = 0;
	s -= 0;
	a2 = a0 = ws->R6[19];
	a0 = mulhi(a0, 9) - mulhi(mullo(a0, -851), 77); /* -39...40 */
	a0 += (int16_t)(77 & sntrup_int16_negative_mask(a0)); /* 0...76 */
	a1 = (a2 - a0) >> 0;
	a1 = mullo(a1, 14469);

	/* invalid inputs might need reduction mod 172 */
	a1 -= 172;
	a1 += (int16_t)(172 & sntrup_int16_negative_mask(a1));

	ws->R5[38] = a0;
	ws->R5[39] = a1;
	s -= 0;
	i = 3;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R6[i]);
		ws->A0 = sub(mulhiconst(ws->A0, 9),
			     mulhiconst(mulloconst(ws->A0, -851),
					77)); /* -39...40 */
		ws->A0 = ifnegaddconst(ws->A0, 77); /* 0...76 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 0);
		ws->A1 = mulloconst(ws->A1, 14469);

		/* invalid inputs might need reduction mod 77 */
		ws->A1 = ifgesubconst(ws->A1, 77);

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
		_mm256_storeu_si256((__m256i *)(&ws->R5[2 * i]), ws->C0);
		_mm256_storeu_si256((__m256i *)(16 + &ws->R5[2 * i]), ws->C1);
		if (!i)
			break;
		i = -16 - ((~15) & -i);
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 79*[140]+[313] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[39];
	a0 = mulhi(a0, 36) - mulhi(mullo(a0, 11235), 140); /* -70...79 */
	a0 += s[1 * i + 0]; /* -70...334 */
	a0 = mulhi(a0, 16) - mulhi(mullo(a0, -468), 140); /* -71...70 */
	a0 += (int16_t)(140 & sntrup_int16_negative_mask(a0)); /* 0...139 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -20597);

	/* invalid inputs might need reduction mod 313 */
	a1 -= 313;
	a1 += (int16_t)(313 & sntrup_int16_negative_mask(a1));

	ws->R4[78] = a0;
	ws->R4[79] = a1;
	s -= 39;
	i = 23;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 36),
			     mulhiconst(mulloconst(ws->A0, 11235),
					140)); /* -70...79 */
		ws->A0 = add(ws->A0, ws->S0); /* -70...334 */
		ws->A0 = sub(mulhiconst(ws->A0, 16),
			     mulhiconst(mulloconst(ws->A0, -468),
					140)); /* -71...70 */
		ws->A0 = ifnegaddconst(ws->A0, 140); /* 0...139 */
		ws->A1 = add(shiftleftconst(ws->A2, 6),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, -20597);

		/* invalid inputs might need reduction mod 140 */
		ws->A1 = ifgesubconst(ws->A1, 140);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 159*[189]+[423] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R4[79];
	a0 = mulhi(a0, 64) - mulhi(mullo(a0, -23232), 189); /* -95...110 */
	a0 += s[1 * i + 0]; /* -95...365 */
	a0 -= 189; /* -284..>176 */
	a0 += (int16_t)(189 & sntrup_int16_negative_mask(a0)); /* -95...188 */
	a0 += (int16_t)(189 & sntrup_int16_negative_mask(a0)); /* 0...188 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -1387);

	/* invalid inputs might need reduction mod 423 */
	a1 -= 423;
	a1 += (int16_t)(423 & sntrup_int16_negative_mask(a1));

	ws->R3[158] = a0;
	ws->R3[159] = a1;
	s -= 79;
	i = 63;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 64),
			     mulhiconst(mulloconst(ws->A0, -23232),
					189)); /* -95...110 */
		ws->A0 = add(ws->A0, ws->S0); /* -95...365 */
		ws->A0 = subconst(ws->A0, 189); /* -284...176 */
		ws->A0 = ifnegaddconst(ws->A0, 189); /* -95...188 */
		ws->A0 = ifnegaddconst(ws->A0, 189); /* 0...188 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -1387);

		/* invalid inputs might need reduction mod 189 */
		ws->A1 = ifgesubconst(ws->A1, 189);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 319*[3511]+[7879] */

	i = 0;
	s -= 2;
	//a2 = a0 = ws->R3[159];
	a0 = ws->R3[159];
	a0 = mulhi(a0, 1658) - mulhi(mullo(a0, -4778), 3511); /* -1756...2170 */
	a0 += s[2 * i + 1]; /* -1756...2425 */
	a0 = mulhi(a0, 1658) - mulhi(mullo(a0, -4778), 3511); /* -1800...1816 */
	a0 += s[2 * i + 0]; /* -1800...2071 */
	a0 += (int16_t)(3511 & sntrup_int16_negative_mask(a0)); /* 0...3510 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, 24583);

	/* invalid inputs might need reduction mod 7879 */
	a1 -= 7879;
	a1 += (int16_t)(7879 & sntrup_int16_negative_mask(a1));

	ws->R2[318] = a0;
	ws->R2[319] = a1;
	s -= 318;
	i = 143;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1658),
			     mulhiconst(mulloconst(ws->A0, -4778),
					3511)); /* -1756...2170 */
		ws->A0 = add(ws->A0, ws->S1); /* -1756...2425 */
		ws->A0 = sub(mulhiconst(ws->A0, 1658),
			     mulhiconst(mulloconst(ws->A0, -4778),
					3511)); /* -1800...1816 */
		ws->A0 = add(ws->A0, ws->S0); /* -1800...2071 */
		ws->A0 = ifnegaddconst(ws->A0, 3511); /* 0...3510 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 24583);

		/* invalid inputs might need reduction mod 3511 */
		ws->A1 = ifgesubconst(ws->A1, 3511);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 638*[948]+[7879] */

	ws->R1[638] = ws->R2[319];
	s -= 319;
	i = 303;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 460),
			     mulhiconst(mulloconst(ws->A0, -17697),
					948)); /* -474...589 */
		ws->A0 = add(ws->A0, ws->S0); /* -474...844 */
		ws->A0 = ifnegaddconst(ws->A0, 948); /* 0...947 */
		ws->A1 = add(shiftleftconst(ws->A2, 6),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, 23781);

		/* invalid inputs might need reduction mod 948 */
		ws->A1 = ifgesubconst(ws->A1, 948);

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

	/* ws->R1 ------> R0: reconstruct mod 1277*[7879] */

	R0[1276] = ws->R1[638] - 3939;
	s -= 1276;
	i = 622;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 2825),
			     mulhiconst(mulloconst(ws->A0, -2129),
					7879)); /* -3940...4645 */
		ws->A0 = add(ws->A0, ws->S1); /* -3940...4900 */
		ws->A0 = sub(mulhiconst(ws->A0, 2825),
			     mulhiconst(mulloconst(ws->A0, -2129),
					7879)); /* -4110...4150 */
		ws->A0 = add(ws->A0, ws->S0); /* -4110...4405 */
		ws->A0 = ifnegaddconst(ws->A0, 7879); /* 0...7878 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 17143);

		/* invalid inputs might need reduction mod 7879 */
		ws->A1 = ifgesubconst(ws->A1, 7879);

		ws->A0 = subconst(ws->A0, 3939);
		ws->A1 = subconst(ws->A1, 3939);
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
