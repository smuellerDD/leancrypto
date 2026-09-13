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

void sntrup_decode_1277x2627_avx2(void *v, const uint8_t *s,
				  struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_1277x2627_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, 16) - mulhi(mullo(a1, 1986), 264);
	a1 += *--s; /* -132...387 */
	a1 -= 264; /* -396...123 */
	a1 += (int16_t)(264 & sntrup_int16_negative_mask(a1)); /* -132...263 */
	a1 += (int16_t)(264 & sntrup_int16_negative_mask(a1)); /* 0...263 */
	ws->R11[0] = a1;

	/* ws->R11 ------> ws->R10: reconstruct mod 1*[7744]+[2229] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R11[0];
	a0 = mulhi(a0, 3712) - mulhi(mullo(a0, -2166), 7744); /* -3872...4800 */
	a0 += s[2 * i + 1]; /* -3872...5055 */
	a0 = mulhi(a0, 3712) - mulhi(mullo(a0, -2166), 7744); /* -4092...4158 */
	a0 += s[2 * i + 0]; /* -4092...4413 */
	a0 += (int16_t)(7744 & sntrup_int16_negative_mask(a0)); /* 0...7743 */
	a1 = (int16_t)((a2 << 10) + (s[2 * i + 1] << 2) +
		       ((s[2 * i] - a0) >> 6));
	a1 = mullo(a1, 27081);

	/* invalid inputs might need reduction mod 2229 */
	a1 -= 2229;
	a1 += (int16_t)(2229 & sntrup_int16_negative_mask(a1));

	ws->R10[0] = a0;
	ws->R10[1] = a1;
	s -= 0;

	/* ws->R10 ------> ws->R9: reconstruct mod 2*[1408]+[2229] */

	ws->R9[2] = ws->R10[1];
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R10[i];
		a0 = mulhi(a0, -512) -
		     mulhi(mullo(a0, -11916), 1408); /* -832...704 */
		a0 += s[1 * i + 0]; /* -832...959 */
		a0 += (int16_t)(1408 &
				sntrup_int16_negative_mask(a0)); /* 0...1407 */
		a1 = (int16_t)((a2 << 1) + ((s[i] - a0) >> 7));
		a1 = mullo(a1, -29789);

		/* invalid inputs might need reduction mod 1408 */
		a1 -= 1408;
		a1 += (int16_t)(1408 & sntrup_int16_negative_mask(a1));

		ws->R9[2 * i] = a0;
		ws->R9[2 * i + 1] = a1;
	}

	/* ws->R9 ------> ws->R8: reconstruct mod 4*[9604]+[2229] */

	ws->R8[4] = ws->R9[2];
	s -= 4;
	for (i = 1; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, -972) -
		     mulhi(mullo(a0, -1747), 9604); /* -5045...4802 */
		a0 += s[2 * i + 1]; /* -5045...5057 */
		a0 = mulhi(a0, -972) -
		     mulhi(mullo(a0, -1747), 9604); /* -4878...4876 */
		a0 += s[2 * i + 0]; /* -4878...5131 */
		a0 += (int16_t)(9604 &
				sntrup_int16_negative_mask(a0)); /* 0...9603 */
		a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
			       ((s[2 * i] - a0) >> 2));
		a1 = mullo(a1, 23201);

		/* invalid inputs might need reduction mod 9604 */
		a1 -= 9604;
		a1 += (int16_t)(9604 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 9*[98]+[5822] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[4];
	a0 = mulhi(a0, 8) - mulhi(mullo(a0, 25412), 98); /* -49...51 */
	a0 += s[1 * i + 0]; /* -49...306 */
	a0 = mulhi(a0, -26) - mulhi(mullo(a0, -669), 98); /* -50...49 */
	a0 += (int16_t)(98 & sntrup_int16_negative_mask(a0)); /* 0...97 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, 22737);

	/* invalid inputs might need reduction mod 5822 */
	a1 -= 5822;
	a1 += (int16_t)(5822 & sntrup_int16_negative_mask(a1));

	ws->R7[8] = a0;
	ws->R7[9] = a1;
	s -= 0;
	for (i = 3; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -26) - mulhi(mullo(a0, -669), 98); /* -56...49 */
		a0 += (int16_t)(98 &
				sntrup_int16_negative_mask(a0)); /* 0...97 */
		a1 = (int16_t)((a2 - a0) >> 1);
		a1 = mullo(a1, 22737);

		/* invalid inputs might need reduction mod 98 */
		a1 -= 98;
		a1 += (int16_t)(98 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 19*[158]+[9433] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R7[9];
	a0 = mulhi(a0, -14) - mulhi(mullo(a0, 24887), 158); /* -83...79 */
	a0 += s[1 * i + 0]; /* -83...334 */
	a0 = mulhi(a0, -34) - mulhi(mullo(a0, -415), 158); /* -80...79 */
	a0 += (int16_t)(158 & sntrup_int16_negative_mask(a0)); /* 0...157 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, 5807);

	/* invalid inputs might need reduction mod 9433 */
	a1 -= 9433;
	a1 += (int16_t)(9433 & sntrup_int16_negative_mask(a1));

	ws->R6[18] = a0;
	ws->R6[19] = a1;
	s -= 9;
	for (i = 8; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, -14) -
		     mulhi(mullo(a0, 24887), 158); /* -83...79 */
		a0 += s[1 * i + 0]; /* -83...334 */
		a0 = mulhi(a0, -34) -
		     mulhi(mullo(a0, -415), 158); /* -80...79 */
		a0 += (int16_t)(158 &
				sntrup_int16_negative_mask(a0)); /* 0...157 */
		a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
		a1 = mullo(a1, 5807);

		/* invalid inputs might need reduction mod 158 */
		a1 -= 158;
		a1 += (int16_t)(158 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 39*[3211]+[752] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R6[19];
	a0 = mulhi(a0, -259) - mulhi(mullo(a0, -5225), 3211); /* -1671...1605 */
	a0 += s[1 * i + 0]; /* -1671...1860 */
	a0 += (int16_t)(3211 & sntrup_int16_negative_mask(a0)); /* 0...3210 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -1245);

	/* invalid inputs might need reduction mod 752 */
	a1 -= 752;
	a1 += (int16_t)(752 & sntrup_int16_negative_mask(a1));

	ws->R5[38] = a0;
	ws->R5[39] = a1;
	s -= 38;
	i = 3;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R6[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -259),
			     mulhiconst(mulloconst(ws->A0, -5225),
					3211)); /* -1671...1605 */
		ws->A0 = add(ws->A0, ws->S1); /* -1671...1860 */
		ws->A0 = sub(mulhiconst(ws->A0, -259),
			     mulhiconst(mulloconst(ws->A0, -5225),
					3211)); /* -1613...1612 */
		ws->A0 = add(ws->A0, ws->S0); /* -1613...1867 */
		ws->A0 = ifnegaddconst(ws->A0, 3211); /* 0...3210 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -1245);

		/* invalid inputs might need reduction mod 3211 */
		ws->A1 = ifgesubconst(ws->A1, 3211);

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

	/* ws->R5 ------> ws->R4: reconstruct mod 79*[14506]+[3395] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R5[39];
	a0 = mulhi(a0, -6226) -
	     mulhi(mullo(a0, -1157), 14506); /* -8810...7253 */
	a0 += s[2 * i + 1]; /* -8810...7508 */
	a0 = mulhi(a0, -6226) -
	     mulhi(mullo(a0, -1157), 14506); /* -7967...8089 */
	a0 += s[2 * i + 0]; /* -7967...8344 */
	a0 += (int16_t)(14506 & sntrup_int16_negative_mask(a0)); /* 0...14505 */
	a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
		       ((s[2 * i] - a0) >> 1));
	a1 = mullo(a1, 253);

	/* invalid inputs might need reduction mod 3395 */
	a1 -= 3395;
	a1 += (int16_t)(3395 & sntrup_int16_negative_mask(a1));

	ws->R4[78] = a0;
	ws->R4[79] = a1;
	s -= 78;
	i = 23;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -6226),
			     mulhiconst(mulloconst(ws->A0, -1157),
					14506)); /* -8810...7253 */
		ws->A0 = add(ws->A0, ws->S1); /* -8810...7508 */
		ws->A0 = sub(mulhiconst(ws->A0, -6226),
			     mulhiconst(mulloconst(ws->A0, -1157),
					14506)); /* -7967...8089 */
		ws->A0 = add(ws->A0, ws->S0); /* -7967...8344 */
		ws->A0 = ifnegaddconst(ws->A0, 14506); /* 0...14505 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 15),
				 shiftleftconst(ws->S1, 7)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, 253);

		/* invalid inputs might need reduction mod 14506 */
		ws->A1 = ifgesubconst(ws->A1, 14506);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 159*[1927]+[451] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R4[79];
	a0 = mulhi(a0, 754) - mulhi(mullo(a0, -8706), 1927); /* -964...1152 */
	a0 += s[1 * i + 0]; /* -964...1407 */
	a0 += (int16_t)(1927 & sntrup_int16_negative_mask(a0)); /* 0...1926 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 3639);

	/* invalid inputs might need reduction mod 451 */
	a1 -= 451;
	a1 += (int16_t)(451 & sntrup_int16_negative_mask(a1));

	ws->R3[158] = a0;
	ws->R3[159] = a1;
	s -= 79;
	i = 63;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 754),
			     mulhiconst(mulloconst(ws->A0, -8706),
					1927)); /* -964...1152 */
		ws->A0 = add(ws->A0, ws->S0); /* -964...1407 */
		ws->A0 = ifnegaddconst(ws->A0, 1927); /* 0...1926 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 3639);

		/* invalid inputs might need reduction mod 1927 */
		ws->A1 = ifgesubconst(ws->A1, 1927);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 319*[11236]+[2627] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R3[159];
	a0 = mulhi(a0, 1868) -
	     mulhi(mullo(a0, -1493), 11236); /* -5618...6085 */
	a0 += s[2 * i + 1]; /* -5618...6340 */
	a0 = mulhi(a0, 1868) -
	     mulhi(mullo(a0, -1493), 11236); /* -5779...5798 */
	a0 += s[2 * i + 0]; /* -5779...6053 */
	a0 += (int16_t)(11236 & sntrup_int16_negative_mask(a0)); /* 0...11235 */
	a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
		       ((s[2 * i] - a0) >> 2));
	a1 = mullo(a1, -26807);

	/* invalid inputs might need reduction mod 2627 */
	a1 -= 2627;
	a1 += (int16_t)(2627 & sntrup_int16_negative_mask(a1));

	ws->R2[318] = a0;
	ws->R2[319] = a1;
	s -= 318;
	i = 143;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1868),
			     mulhiconst(mulloconst(ws->A0, -1493),
					11236)); /* -5618...6085 */
		ws->A0 = add(ws->A0, ws->S1); /* -5618...6340 */
		ws->A0 = sub(mulhiconst(ws->A0, 1868),
			     mulhiconst(mulloconst(ws->A0, -1493),
					11236)); /* -5779...5798 */
		ws->A0 = add(ws->A0, ws->S0); /* -5779...6053 */
		ws->A0 = ifnegaddconst(ws->A0, 11236); /* 0...11235 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 14),
				 shiftleftconst(ws->S1, 6)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, -26807);

		/* invalid inputs might need reduction mod 11236 */
		ws->A1 = ifgesubconst(ws->A1, 11236);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 638*[106]+[2627] */

	ws->R1[638] = ws->R2[319];
	s -= 0;
	i = 303;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->A0 = sub(mulhiconst(ws->A0, 28),
			     mulhiconst(mulloconst(ws->A0, -618),
					106)); /* -53...60 */
		ws->A0 = ifnegaddconst(ws->A0, 106); /* 0...105 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 1);
		ws->A1 = mulloconst(ws->A1, 21021);

		/* invalid inputs might need reduction mod 106 */
		ws->A1 = ifgesubconst(ws->A1, 106);

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

	/* ws->R1 ------> R0: reconstruct mod 1277*[2627] */

	R0[1276] = (int16_t)(3 * ws->R1[638] - 3939);
	s -= 1276;
	i = 622;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1194),
			     mulhiconst(mulloconst(ws->A0, -6386),
					2627)); /* -1314...1612 */
		ws->A0 = add(ws->A0, ws->S1); /* -1314...1867 */
		ws->A0 = sub(mulhiconst(ws->A0, 1194),
			     mulhiconst(mulloconst(ws->A0, -6386),
					2627)); /* -1338...1347 */
		ws->A0 = add(ws->A0, ws->S0); /* -1338...1602 */
		ws->A0 = ifnegaddconst(ws->A0, 2627); /* 0...2626 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 4715);

		/* invalid inputs might need reduction mod 2627 */
		ws->A1 = ifgesubconst(ws->A1, 2627);

		ws->A0 = mulloconst(ws->A0, 3);
		ws->A1 = mulloconst(ws->A1, 3);
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
