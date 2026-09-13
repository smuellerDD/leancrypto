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

void sntrup_decode_1013x2393_avx2(void *v, const uint8_t *s,
				  struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_1013x2393_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, 4) - mulhi(mullo(a1, 4749), 276);
	a1 += *--s; /* -138...393 */
	a1 -= 276; /* -414...117 */
	a1 += (int16_t)(276 & sntrup_int16_negative_mask(a1)); /* -138...275 */
	a1 += (int16_t)(276 & sntrup_int16_negative_mask(a1)); /* 0...275 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[14506]+[1243] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R10[0];
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

	/* invalid inputs might need reduction mod 1243 */
	a1 -= 1243;
	a1 += (int16_t)(1243 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 3*[1927]+[165] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R9[1];
	a0 = mulhi(a0, 754) - mulhi(mullo(a0, -8706), 1927); /* -964...1152 */
	a0 += s[1 * i + 0]; /* -964...1407 */
	a0 += (int16_t)(1927 & sntrup_int16_negative_mask(a0)); /* 0...1926 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 3639);

	/* invalid inputs might need reduction mod 165 */
	a1 -= 165;
	a1 += (int16_t)(165 & sntrup_int16_negative_mask(a1));

	ws->R8[2] = a0;
	ws->R8[3] = a1;
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, 754) -
		     mulhi(mullo(a0, -8706), 1927); /* -964...1152 */
		a0 += s[1 * i + 0]; /* -964...1407 */
		a0 += (int16_t)(1927 &
				sntrup_int16_negative_mask(a0)); /* 0...1926 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, 3639);

		/* invalid inputs might need reduction mod 1927 */
		a1 -= 1927;
		a1 += (int16_t)(1927 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 7*[11236]+[962] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R8[3];
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

	/* invalid inputs might need reduction mod 962 */
	a1 -= 962;
	a1 += (int16_t)(962 & sntrup_int16_negative_mask(a1));

	ws->R7[6] = a0;
	ws->R7[7] = a1;
	s -= 6;
	for (i = 2; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, 1868) -
		     mulhi(mullo(a0, -1493), 11236); /* -5618...6085 */
		a0 += s[2 * i + 1]; /* -5618...6340 */
		a0 = mulhi(a0, 1868) -
		     mulhi(mullo(a0, -1493), 11236); /* -5779...5798 */
		a0 += s[2 * i + 0]; /* -5779...6053 */
		a0 += (int16_t)(11236 &
				sntrup_int16_negative_mask(a0)); /* 0...11235 */
		a1 = (int16_t)((a2 << 14) + (s[2 * i + 1] << 6) +
			       ((s[2 * i] - a0) >> 2));
		a1 = mullo(a1, -26807);

		/* invalid inputs might need reduction mod 11236 */
		a1 -= 11236;
		a1 += (int16_t)(11236 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 15*[106]+[2322] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R7[7];
	a0 = mulhi(a0, -40) - mulhi(mullo(a0, -27204), 106); /* -63...53 */
	a0 += s[1 * i + 0]; /* -63...308 */
	a0 = mulhi(a0, 28) - mulhi(mullo(a0, -618), 106); /* -54...53 */
	a0 += (int16_t)(106 & sntrup_int16_negative_mask(a0)); /* 0...105 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, 21021);

	/* invalid inputs might need reduction mod 2322 */
	a1 -= 2322;
	a1 += (int16_t)(2322 & sntrup_int16_negative_mask(a1));

	ws->R6[14] = a0;
	ws->R6[15] = a1;
	s -= 0;
	for (i = 6; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, 28) - mulhi(mullo(a0, -618), 106); /* -53...60 */
		a0 += (int16_t)(106 &
				sntrup_int16_negative_mask(a0)); /* 0...105 */
		a1 = (int16_t)((a2 - a0) >> 1);
		a1 = mullo(a1, 21021);

		/* invalid inputs might need reduction mod 106 */
		a1 -= 106;
		a1 += (int16_t)(106 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 31*[164]+[3624] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R6[15];
	a0 = mulhi(a0, 16) - mulhi(mullo(a0, 28772), 164); /* -82...86 */
	a0 += s[1 * i + 0]; /* -82...341 */
	a0 = mulhi(a0, -64) - mulhi(mullo(a0, -400), 164); /* -83...82 */
	a0 += (int16_t)(164 & sntrup_int16_negative_mask(a0)); /* 0...163 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -25575);

	/* invalid inputs might need reduction mod 3624 */
	a1 -= 3624;
	a1 += (int16_t)(3624 & sntrup_int16_negative_mask(a1));

	ws->R5[30] = a0;
	ws->R5[31] = a1;
	s -= 15;
	for (i = 14; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, 16) -
		     mulhi(mullo(a0, 28772), 164); /* -82...86 */
		a0 += s[1 * i + 0]; /* -82...341 */
		a0 = mulhi(a0, -64) -
		     mulhi(mullo(a0, -400), 164); /* -83...82 */
		a0 += (int16_t)(164 &
				sntrup_int16_negative_mask(a0)); /* 0...163 */
		a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
		a1 = mullo(a1, -25575);

		/* invalid inputs might need reduction mod 164 */
		a1 -= 164;
		a1 += (int16_t)(164 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 63*[3278]+[283] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R5[31];
	a0 = mulhi(a0, 412) - mulhi(mullo(a0, -5118), 3278); /* -1639...1742 */
	a0 += s[1 * i + 0]; /* -1639...1997 */
	a0 += (int16_t)(3278 & sntrup_int16_negative_mask(a0)); /* 0...3277 */
	a1 = (int16_t)((a2 << 7) + ((s[i] - a0) >> 1));
	a1 = mullo(a1, -19113);

	/* invalid inputs might need reduction mod 283 */
	a1 -= 283;
	a1 += (int16_t)(283 & sntrup_int16_negative_mask(a1));

	ws->R4[62] = a0;
	ws->R4[63] = a1;
	s -= 62;
	i = 15;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 412),
			     mulhiconst(mulloconst(ws->A0, -5118),
					3278)); /* -1639...1742 */
		ws->A0 = add(ws->A0, ws->S1); /* -1639...1997 */
		ws->A0 = sub(mulhiconst(ws->A0, 412),
			     mulhiconst(mulloconst(ws->A0, -5118),
					3278)); /* -1650...1651 */
		ws->A0 = add(ws->A0, ws->S0); /* -1650...1906 */
		ws->A0 = ifnegaddconst(ws->A0, 3278); /* 0...3277 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 15),
				 shiftleftconst(ws->S1, 7)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, -19113);

		/* invalid inputs might need reduction mod 3278 */
		ws->A1 = ifgesubconst(ws->A1, 3278);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 126*[916]+[283] */

	ws->R3[126] = ws->R4[63];
	s -= 63;
	i = 47;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -240),
			     mulhiconst(mulloconst(ws->A0, -18316),
					916)); /* -518...458 */
		ws->A0 = add(ws->A0, ws->S0); /* -518...713 */
		ws->A0 = ifnegaddconst(ws->A0, 916); /* 0...915 */
		ws->A1 = add(shiftleftconst(ws->A2, 6),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, -17171);

		/* invalid inputs might need reduction mod 916 */
		ws->A1 = ifgesubconst(ws->A1, 916);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 253*[7744]+[2393] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R3[126];
	a0 = mulhi(a0, 3712) - mulhi(mullo(a0, -2166), 7744); /* -3872...4800 */
	a0 += s[2 * i + 1]; /* -3872...5055 */
	a0 = mulhi(a0, 3712) - mulhi(mullo(a0, -2166), 7744); /* -4092...4158 */
	a0 += s[2 * i + 0]; /* -4092...4413 */
	a0 += (int16_t)(7744 & sntrup_int16_negative_mask(a0)); /* 0...7743 */
	a1 = (int16_t)((a2 << 10) + (s[2 * i + 1] << 2) +
		       ((s[2 * i] - a0) >> 6));
	a1 = mullo(a1, 27081);

	/* invalid inputs might need reduction mod 2393 */
	a1 -= 2393;
	a1 += (int16_t)(2393 & sntrup_int16_negative_mask(a1));

	ws->R2[252] = a0;
	ws->R2[253] = a1;
	s -= 252;
	i = 110;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 3712),
			     mulhiconst(mulloconst(ws->A0, -2166),
					7744)); /* -3872...4800 */
		ws->A0 = add(ws->A0, ws->S1); /* -3872...5055 */
		ws->A0 = sub(mulhiconst(ws->A0, 3712),
			     mulhiconst(mulloconst(ws->A0, -2166),
					7744)); /* -4092...4158 */
		ws->A0 = add(ws->A0, ws->S0); /* -4092...4413 */
		ws->A0 = ifnegaddconst(ws->A0, 7744); /* 0...7743 */
		ws->A1 = add(add(shiftleftconst(ws->A2, 10),
				 shiftleftconst(ws->S1, 2)),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 6));
		ws->A1 = mulloconst(ws->A1, 27081);

		/* invalid inputs might need reduction mod 7744 */
		ws->A1 = ifgesubconst(ws->A1, 7744);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 506*[88]+[2393] */

	ws->R1[506] = ws->R2[253];
	s -= 0;
	i = 237;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->A0 = sub(mulhiconst(ws->A0, -24),
			     mulhiconst(mulloconst(ws->A0, -745),
					88)); /* -50...44 */
		ws->A0 = ifnegaddconst(ws->A0, 88); /* 0...87 */
		ws->A1 = signedshiftrightconst(sub(ws->A2, ws->A0), 3);
		ws->A1 = mulloconst(ws->A1, -29789);

		/* invalid inputs might need reduction mod 88 */
		ws->A1 = ifgesubconst(ws->A1, 88);

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

	/* ws->R1 ------> R0: reconstruct mod 1013*[2393] */

	R0[1012] = (int16_t)(3 * ws->R1[506] - 3588);
	s -= 1012;
	i = 490;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, -107),
			     mulhiconst(mulloconst(ws->A0, -7011),
					2393)); /* -1224...1196 */
		ws->A0 = add(ws->A0, ws->S1); /* -1224...1451 */
		ws->A0 = sub(mulhiconst(ws->A0, -107),
			     mulhiconst(mulloconst(ws->A0, -7011),
					2393)); /* -1199...1198 */
		ws->A0 = add(ws->A0, ws->S0); /* -1199...1453 */
		ws->A0 = ifnegaddconst(ws->A0, 2393); /* 0...2392 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -20759);

		/* invalid inputs might need reduction mod 2393 */
		ws->A1 = ifgesubconst(ws->A1, 2393);

		ws->A0 = mulloconst(ws->A0, 3);
		ws->A1 = mulloconst(ws->A1, 3);
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
