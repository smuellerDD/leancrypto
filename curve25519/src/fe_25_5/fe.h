/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023 - 2025
 * Frank Denis <j at pureftpd dot org>
 */

#ifndef FE_H
#define FE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 Ignores top bit of s.
 */

void fe25519_frombytes(fe25519 h, const unsigned char *s)
{
	int64_t h0 = (int64_t)load_4(s);
	int64_t h1 = (int64_t)load_3(s + 4) << 6;
	int64_t h2 = (int64_t)load_3(s + 7) << 5;
	int64_t h3 = (int64_t)load_3(s + 10) << 3;
	int64_t h4 = (int64_t)load_3(s + 13) << 2;
	int64_t h5 = (int64_t)load_4(s + 16);
	int64_t h6 = (int64_t)load_3(s + 20) << 7;
	int64_t h7 = (int64_t)load_3(s + 23) << 5;
	int64_t h8 = (int64_t)load_3(s + 26) << 4;
	int64_t h9 = (int64_t)((load_3(s + 29) & 8388607) << 2);

	int64_t carry0;
	int64_t carry1;
	int64_t carry2;
	int64_t carry3;
	int64_t carry4;
	int64_t carry5;
	int64_t carry6;
	int64_t carry7;
	int64_t carry8;
	int64_t carry9;

	carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
	h0 += carry9 * 19;
	h9 -= carry9 * ((int64_t)1L << 25);
	carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
	h2 += carry1;
	h1 -= carry1 * ((int64_t)1L << 25);
	carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
	h4 += carry3;
	h3 -= carry3 * ((int64_t)1L << 25);
	carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
	h6 += carry5;
	h5 -= carry5 * ((int64_t)1L << 25);
	carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
	h8 += carry7;
	h7 -= carry7 * ((int64_t)1L << 25);

	carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 * ((int64_t)1L << 26);
	carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
	h3 += carry2;
	h2 -= carry2 * ((int64_t)1L << 26);
	carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 * ((int64_t)1L << 26);
	carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
	h7 += carry6;
	h6 -= carry6 * ((int64_t)1L << 26);
	carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
	h9 += carry8;
	h8 -= carry8 * ((int64_t)1L << 26);

	h[0] = (int32_t)h0;
	h[1] = (int32_t)h1;
	h[2] = (int32_t)h2;
	h[3] = (int32_t)h3;
	h[4] = (int32_t)h4;
	h[5] = (int32_t)h5;
	h[6] = (int32_t)h6;
	h[7] = (int32_t)h7;
	h[8] = (int32_t)h8;
	h[9] = (int32_t)h9;
}

/*
 Preconditions:
 |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

 Write p=2^255-19; q=floor(h/p).
 Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

 Proof:
 Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
 Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

 Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
 Then 0<y<1.

 Write r=h-pq.
 Have 0<=r<=p-1=2^255-20.
 Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

 Write x=r+19(2^-255)r+y.
 Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

 Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
 so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
*/

static void fe25519_reduce(fe25519 h, const fe25519 f)
{
	int32_t h0 = f[0];
	int32_t h1 = f[1];
	int32_t h2 = f[2];
	int32_t h3 = f[3];
	int32_t h4 = f[4];
	int32_t h5 = f[5];
	int32_t h6 = f[6];
	int32_t h7 = f[7];
	int32_t h8 = f[8];
	int32_t h9 = f[9];

	int32_t q;
	int32_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7,
		carry8, carry9;

	q = (19 * h9 + ((int32_t)1L << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;

	/* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
	h0 += 19 * q;
	/* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

	carry0 = h0 >> 26;
	h1 += carry0;
	h0 -= carry0 * ((int32_t)1L << 26);
	carry1 = h1 >> 25;
	h2 += carry1;
	h1 -= carry1 * ((int32_t)1L << 25);
	carry2 = h2 >> 26;
	h3 += carry2;
	h2 -= carry2 * ((int32_t)1L << 26);
	carry3 = h3 >> 25;
	h4 += carry3;
	h3 -= carry3 * ((int32_t)1L << 25);
	carry4 = h4 >> 26;
	h5 += carry4;
	h4 -= carry4 * ((int32_t)1L << 26);
	carry5 = h5 >> 25;
	h6 += carry5;
	h5 -= carry5 * ((int32_t)1L << 25);
	carry6 = h6 >> 26;
	h7 += carry6;
	h6 -= carry6 * ((int32_t)1L << 26);
	carry7 = h7 >> 25;
	h8 += carry7;
	h7 -= carry7 * ((int32_t)1L << 25);
	carry8 = h8 >> 26;
	h9 += carry8;
	h8 -= carry8 * ((int32_t)1L << 26);
	carry9 = h9 >> 25;
	h9 -= carry9 * ((int32_t)1L << 25);

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

/*
 Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
 Have h0+...+2^230 h9 between 0 and 2^255-1;
 evidently 2^255 h10-2^255 q = 0.

 Goal: Output h0+...+2^230 h9.
 */

void fe25519_tobytes(unsigned char *s, const fe25519 h)
{
	fe25519 t;

	fe25519_reduce(t, h);
	s[0] = (unsigned char)(t[0] >> 0);
	s[1] = (unsigned char)(t[0] >> 8);
	s[2] = (unsigned char)(t[0] >> 16);
	s[3] = (unsigned char)((t[0] >> 24) | (t[1] * ((int32_t)1 << 2)));
	s[4] = (unsigned char)(t[1] >> 6);
	s[5] = (unsigned char)(t[1] >> 14);
	s[6] = (unsigned char)((t[1] >> 22) | (t[2] * ((int32_t)1 << 3)));
	s[7] = (unsigned char)(t[2] >> 5);
	s[8] = (unsigned char)(t[2] >> 13);
	s[9] = (unsigned char)((t[2] >> 21) | (t[3] * ((int32_t)1 << 5)));
	s[10] = (unsigned char)(t[3] >> 3);
	s[11] = (unsigned char)(t[3] >> 11);
	s[12] = (unsigned char)((t[3] >> 19) | (t[4] * ((int32_t)1 << 6)));
	s[13] = (unsigned char)(t[4] >> 2);
	s[14] = (unsigned char)(t[4] >> 10);
	s[15] = (unsigned char)(t[4] >> 18);
	s[16] = (unsigned char)(t[5] >> 0);
	s[17] = (unsigned char)(t[5] >> 8);
	s[18] = (unsigned char)(t[5] >> 16);
	s[19] = (unsigned char)((t[5] >> 24) | (t[6] * ((int32_t)1 << 1)));
	s[20] = (unsigned char)(t[6] >> 7);
	s[21] = (unsigned char)(t[6] >> 15);
	s[22] = (unsigned char)((t[6] >> 23) | (t[7] * ((int32_t)1 << 3)));
	s[23] = (unsigned char)(t[7] >> 5);
	s[24] = (unsigned char)(t[7] >> 13);
	s[25] = (unsigned char)((t[7] >> 21) | (t[8] * ((int32_t)1 << 4)));
	s[26] = (unsigned char)(t[8] >> 4);
	s[27] = (unsigned char)(t[8] >> 12);
	s[28] = (unsigned char)((t[8] >> 20) | (t[9] * ((int32_t)1 << 6)));
	s[29] = (unsigned char)(t[9] >> 2);
	s[30] = (unsigned char)(t[9] >> 10);
	s[31] = (unsigned char)(t[9] >> 18);
}

#ifdef __cplusplus
}
#endif

#endif /* FE_H */
