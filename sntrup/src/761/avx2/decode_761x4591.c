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

void sntrup_decode_761x4591_avx2(void *v, const uint8_t *s,
				 struct ws_decode *ws_full)
{
	struct ws_decode_avx2 *ws = &ws_full->u.avx2;
	int16_t *R0 = (int16_t *)v;
	long long i;
	int16_t a0, a1, a2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	LC_FPU_ENABLE;

	s += sntrup_decode_761x4591_STRBYTES;
	a1 = 0;
	a1 += *--s; /* 0...255 */
	a1 = mulhi(a1, -656) - mulhi(mullo(a1, -10434), 1608);
	a1 += *--s; /* -804...1056 */
	a1 += (int16_t)(1608 & sntrup_int16_negative_mask(a1)); /* 0...1607 */
	ws->R10[0] = a1;

	/* ws->R10 ------> ws->R9: reconstruct mod 1*[9470]+[11127] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R10[0];
	a0 = mulhi(a0, -3624) -
	     mulhi(mullo(a0, -1772), 9470); /* -5641...4735 */
	a0 += s[2 * i + 1]; /* -5641...4990 */
	a0 = mulhi(a0, -3624) -
	     mulhi(mullo(a0, -1772), 9470); /* -5011...5046 */
	a0 += s[2 * i + 0]; /* -5011...5301 */
	a0 += (int16_t)(9470 & sntrup_int16_negative_mask(a0)); /* 0...9469 */
	a1 = (int16_t)((a2 << 15) + (s[2 * i + 1] << 7) +
		       ((s[2 * i] - a0) >> 1));
	a1 = mullo(a1, -21121);

	/* invalid inputs might need reduction mod 11127 */
	a1 -= 11127;
	a1 += (int16_t)(11127 & sntrup_int16_negative_mask(a1));

	ws->R9[0] = a0;
	ws->R9[1] = a1;
	s -= 0;

	/* ws->R9 ------> ws->R8: reconstruct mod 2*[1557]+[11127] */

	ws->R8[2] = ws->R9[1];
	s -= 1;
	for (i = 0; i >= 0; --i) {
		a2 = a0 = ws->R9[i];
		a0 = mulhi(a0, 541) -
		     mulhi(mullo(a0, -10775), 1557); /* -779...913 */
		a0 += s[1 * i + 0]; /* -779...1168 */
		a0 += (int16_t)(1557 &
				sntrup_int16_negative_mask(a0)); /* 0...1556 */
		a1 = (int16_t)((a2 << 8) + s[i] - a0);
		a1 = mullo(a1, -26307);

		/* invalid inputs might need reduction mod 1557 */
		a1 -= 1557;
		a1 += (int16_t)(1557 & sntrup_int16_negative_mask(a1));

		ws->R8[2 * i] = a0;
		ws->R8[2 * i + 1] = a1;
	}

	/* ws->R8 ------> ws->R7: reconstruct mod 5*[10101]+[282] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R8[2];
	a0 = mulhi(a0, -545) -
	     mulhi(mullo(a0, -1661), 10101); /* -5187...5050 */
	a0 += s[1 * i + 0]; /* -5187...5305 */
	a0 += (int16_t)(10101 & sntrup_int16_negative_mask(a0)); /* 0...10100 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, 12509);

	/* invalid inputs might need reduction mod 282 */
	a1 -= 282;
	a1 += (int16_t)(282 & sntrup_int16_negative_mask(a1));

	ws->R7[4] = a0;
	ws->R7[5] = a1;
	s -= 4;
	for (i = 1; i >= 0; --i) {
		a2 = a0 = ws->R8[i];
		a0 = mulhi(a0, -545) -
		     mulhi(mullo(a0, -1661), 10101); /* -5187...5050 */
		a0 += s[2 * i + 1]; /* -5187...5305 */
		a0 = mulhi(a0, -545) -
		     mulhi(mullo(a0, -1661), 10101); /* -5095...5093 */
		a0 += s[2 * i + 0]; /* -5095...5348 */
		a0 += (int16_t)(10101 &
				sntrup_int16_negative_mask(a0)); /* 0...10100 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, 12509);

		/* invalid inputs might need reduction mod 10101 */
		a1 -= 10101;
		a1 += (int16_t)(10101 & sntrup_int16_negative_mask(a1));

		ws->R7[2 * i] = a0;
		ws->R7[2 * i + 1] = a1;
	}

	/* ws->R7 ------> ws->R6: reconstruct mod 11*[1608]+[11468] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R7[5];
	a0 = mulhi(a0, -656) - mulhi(mullo(a0, -10434), 1608); /* -968...804 */
	a0 += s[2 * i + 1]; /* -968...1059 */
	a0 = mulhi(a0, -656) - mulhi(mullo(a0, -10434), 1608); /* -815...813 */
	a0 += s[2 * i + 0]; /* -815...1068 */
	a0 += (int16_t)(1608 & sntrup_int16_negative_mask(a0)); /* 0...1607 */
	a1 = (int16_t)((a2 << 13) + (s[2 * i + 1] << 5) +
		       ((s[2 * i] - a0) >> 3));
	a1 = mullo(a1, 6521);

	/* invalid inputs might need reduction mod 11468 */
	a1 -= 11468;
	a1 += (int16_t)(11468 & sntrup_int16_negative_mask(a1));

	ws->R6[10] = a0;
	ws->R6[11] = a1;
	s -= 5;
	for (i = 4; i >= 0; --i) {
		a2 = a0 = ws->R7[i];
		a0 = mulhi(a0, -656) -
		     mulhi(mullo(a0, -10434), 1608); /* -968...804 */
		a0 += s[1 * i + 0]; /* -968...1059 */
		a0 += (int16_t)(1608 &
				sntrup_int16_negative_mask(a0)); /* 0...1607 */
		a1 = (int16_t)((a2 << 5) + ((s[i] - a0) >> 3));
		a1 = mullo(a1, 6521);

		/* invalid inputs might need reduction mod 1608 */
		a1 -= 1608;
		a1 += (int16_t)(1608 & sntrup_int16_negative_mask(a1));

		ws->R6[2 * i] = a0;
		ws->R6[2 * i + 1] = a1;
	}

	/* ws->R6 ------> ws->R5: reconstruct mod 23*[10265]+[286] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R6[11];
	a0 = mulhi(a0, 4206) -
	     mulhi(mullo(a0, -1634), 10265); /* -5133...6184 */
	a0 += s[1 * i + 0]; /* -5133...6439 */
	a0 += (int16_t)(10265 & sntrup_int16_negative_mask(a0)); /* 0...10264 */
	a1 = (int16_t)((a2 << 8) + s[i] - a0);
	a1 = mullo(a1, -19415);

	/* invalid inputs might need reduction mod 286 */
	a1 -= 286;
	a1 += (int16_t)(286 & sntrup_int16_negative_mask(a1));

	ws->R5[22] = a0;
	ws->R5[23] = a1;
	s -= 22;
	for (i = 10; i >= 0; --i) {
		a2 = a0 = ws->R6[i];
		a0 = mulhi(a0, 4206) -
		     mulhi(mullo(a0, -1634), 10265); /* -5133...6184 */
		a0 += s[2 * i + 1]; /* -5133...6439 */
		a0 = mulhi(a0, 4206) -
		     mulhi(mullo(a0, -1634), 10265); /* -5462...5545 */
		a0 += s[2 * i + 0]; /* -5462...5800 */
		a0 += (int16_t)(10265 &
				sntrup_int16_negative_mask(a0)); /* 0...10264 */
		a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
		a1 = mullo(a1, -19415);

		/* invalid inputs might need reduction mod 10265 */
		a1 -= 10265;
		a1 += (int16_t)(10265 & sntrup_int16_negative_mask(a1));

		ws->R5[2 * i] = a0;
		ws->R5[2 * i + 1] = a1;
	}

	/* ws->R5 ------> ws->R4: reconstruct mod 47*[1621]+[11550] */

	i = 0;
	s -= 2;
	a2 = a0 = ws->R5[23];
	a0 = mulhi(a0, -134) - mulhi(mullo(a0, -10350), 1621); /* -844...810 */
	a0 += s[2 * i + 1]; /* -844...1065 */
	a0 = mulhi(a0, -134) - mulhi(mullo(a0, -10350), 1621); /* -813...812 */
	a0 += s[2 * i + 0]; /* -813...1067 */
	a0 += (int16_t)(1621 & sntrup_int16_negative_mask(a0)); /* 0...1620 */
	a1 = (int16_t)((s[2 * i + 1] << 8) + s[2 * i] - a0);
	a1 = mullo(a1, -14595);

	/* invalid inputs might need reduction mod 11550 */
	a1 -= 11550;
	a1 += (int16_t)(11550 & sntrup_int16_negative_mask(a1));

	ws->R4[46] = a0;
	ws->R4[47] = a1;
	s -= 23;
	i = 7;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R5[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -134),
			     mulhiconst(mulloconst(ws->A0, -10350),
					1621)); /* -844...810 */
		ws->A0 = add(ws->A0, ws->S0); /* -844...1065 */
		ws->A0 = ifnegaddconst(ws->A0, 1621); /* 0...1620 */
		ws->A1 = add(shiftleftconst(ws->A2, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, -14595);

		/* invalid inputs might need reduction mod 1621 */
		ws->A1 = ifgesubconst(ws->A1, 1621);

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

	/* ws->R4 ------> ws->R3: reconstruct mod 95*[644]+[4591] */

	i = 0;
	s -= 1;
	a2 = a0 = ws->R4[47];
	a0 = mulhi(a0, -272) - mulhi(mullo(a0, -26052), 644); /* -390...322 */
	a0 += s[1 * i + 0]; /* -390...577 */
	a0 += (int16_t)(644 & sntrup_int16_negative_mask(a0)); /* 0...643 */
	a1 = (int16_t)((a2 << 6) + ((s[i] - a0) >> 2));
	a1 = mullo(a1, -7327);

	/* invalid inputs might need reduction mod 4591 */
	a1 -= 4591;
	a1 += (int16_t)(4591 & sntrup_int16_negative_mask(a1));

	ws->R3[94] = a0;
	ws->R3[95] = a1;
	s -= 47;
	i = 31;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R4[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, -272),
			     mulhiconst(mulloconst(ws->A0, -26052),
					644)); /* -390...322 */
		ws->A0 = add(ws->A0, ws->S0); /* -390...577 */
		ws->A0 = ifnegaddconst(ws->A0, 644); /* 0...643 */
		ws->A1 = add(shiftleftconst(ws->A2, 6),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 2));
		ws->A1 = mulloconst(ws->A1, -7327);

		/* invalid inputs might need reduction mod 644 */
		ws->A1 = ifgesubconst(ws->A1, 644);

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

	/* ws->R3 ------> ws->R2: reconstruct mod 190*[406]+[4591] */

	ws->R2[190] = ws->R3[95];
	s -= 95;
	i = 79;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R3[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 78),
			     mulhiconst(mulloconst(ws->A0, 24213),
					406)); /* -203...222 */
		ws->A0 = add(ws->A0, ws->S0); /* -203...477 */
		ws->A0 = subconst(ws->A0, 406); /* -609...71 */
		ws->A0 = ifnegaddconst(ws->A0, 406); /* -203...405 */
		ws->A0 = ifnegaddconst(ws->A0, 406); /* 0...405 */
		ws->A1 = add(shiftleftconst(ws->A2, 7),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, 25827);

		/* invalid inputs might need reduction mod 406 */
		ws->A1 = ifgesubconst(ws->A1, 406);

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

	/* ws->R2 ------> ws->R1: reconstruct mod 380*[322]+[4591] */

	ws->R1[380] = ws->R2[190];
	s -= 190;
	i = 174;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R2[i]);
		ws->S0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i *)(s + i)));
		ws->A0 = sub(mulhiconst(ws->A0, 50),
			     mulhiconst(mulloconst(ws->A0, 13433),
					322)); /* -161...173 */
		ws->A0 = add(ws->A0, ws->S0); /* -161...428 */
		ws->A0 = subconst(ws->A0, 322); /* -483...106 */
		ws->A0 = ifnegaddconst(ws->A0, 322); /* -161...321 */
		ws->A0 = ifnegaddconst(ws->A0, 322); /* 0...321 */
		ws->A1 = add(shiftleftconst(ws->A2, 7),
			     signedshiftrightconst(sub(ws->S0, ws->A0), 1));
		ws->A1 = mulloconst(ws->A1, -7327);

		/* invalid inputs might need reduction mod 322 */
		ws->A1 = ifgesubconst(ws->A1, 322);

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

	/* ws->R1 ------> R0: reconstruct mod 761*[4591] */

	R0[760] = ws->R1[380] - 2295;
	s -= 760;
	i = 364;
	for (;;) {
		ws->A2 = ws->A0 = _mm256_loadu_si256((__m256i *)&ws->R1[i]);
		ws->S0 = _mm256_loadu_si256((__m256i *)(s + 2 * i));
		ws->S1 = _mm256_srli_epi16(ws->S0, 8);
		ws->S0 &= _mm256_set1_epi16(255);
		ws->A0 = sub(mulhiconst(ws->A0, 1702),
			     mulhiconst(mulloconst(ws->A0, -3654),
					4591)); /* -2296...2721 */
		ws->A0 = add(ws->A0, ws->S1); /* -2296...2976 */
		ws->A0 = sub(mulhiconst(ws->A0, 1702),
			     mulhiconst(mulloconst(ws->A0, -3654),
					4591)); /* -2356...2372 */
		ws->A0 = add(ws->A0, ws->S0); /* -2356...2627 */
		ws->A0 = ifnegaddconst(ws->A0, 4591); /* 0...4590 */
		ws->A1 = add(shiftleftconst(ws->S1, 8), sub(ws->S0, ws->A0));
		ws->A1 = mulloconst(ws->A1, 15631);

		/* invalid inputs might need reduction mod 4591 */
		ws->A1 = ifgesubconst(ws->A1, 4591);

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
