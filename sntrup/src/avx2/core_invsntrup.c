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
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#include "ext_headers_x86.h"
#include "sntrup_int16.h"
#include "sntrup_int64.h"
#include "sntrup_uint64.h"
#include "params.h"

/* works for -7000000 < x < 7000000 if q in 4591, 4621, 5167, 6343, 7177, 7879 */
static Fq Fq_freeze(int32_t x)
{
	x -= q * ((q18 * x) >> 18);
	x -= q * ((q27 * x + 67108864) >> 27);
	return (Fq)x;
}

static Fq Fq_bigfreeze(int32_t x)
{
	x -= q * ((q14 * x) >> 14);
	x -= q * ((q18 * x) >> 18);
	x -= q * ((q27 * x + 67108864) >> 27);
	x -= q * ((q27 * x + 67108864) >> 27);
	return (Fq)x;
}

/* nonnegative e */
static Fq Fq_pow(Fq a, int e)
{
	if (e == 0)
		return 1;
	if (e == 1)
		return a;
	if (sntrup_int64_bottombit_01(e))
		return Fq_bigfreeze(a * (int32_t)Fq_pow(a, e - 1));
	a = Fq_bigfreeze(a * (int32_t)a);
	return Fq_pow(a, e >> 1);
}

static Fq Fq_recip(Fq a)
{
	return Fq_pow(a, q - 2);
}

/* ----- more */

#define qvec _mm256_set1_epi16(q)
#define qinvvec _mm256_set1_epi16(qinv)

static inline __m256i montproduct(__m256i x, __m256i y, __m256i yqinv)
{
	__m256i hi, d, e;

	d = _mm256_mullo_epi16(x, yqinv);
	hi = _mm256_mulhi_epi16(x, y);
	e = _mm256_mulhi_epi16(d, qvec);
	return _mm256_sub_epi16(hi, e);
}

static inline void vectormodq_swapeliminate(Fq *f, Fq *g, int len, const Fq f0,
					    const Fq g0, int mask)
{
	__m256i f0vec = _mm256_set1_epi16(f0);
	__m256i g0vec = _mm256_set1_epi16(g0);
	__m256i f0vecqinv = _mm256_mullo_epi16(f0vec, qinvvec);
	__m256i g0vecqinv = _mm256_mullo_epi16(g0vec, qinvvec);
	__m256i maskvec = _mm256_set1_epi32(mask);

	while (len > 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		__m256i fi = _mm256_loadu_si256((__m256i *)f);
		__m256i gi = _mm256_loadu_si256((__m256i *)g);
#pragma GCC diagnostic pop
		__m256i finew = _mm256_blendv_epi8(fi, gi, maskvec);
		__m256i ginew = _mm256_blendv_epi8(gi, fi, maskvec);
		ginew = _mm256_sub_epi16(montproduct(ginew, f0vec, f0vecqinv),
					 montproduct(finew, g0vec, g0vecqinv));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		_mm256_storeu_si256((__m256i *)f, finew);
		_mm256_storeu_si256((__m256i *)(g - 1), ginew);
#pragma GCC diagnostic pop
		f += 16;
		g += 16;
		len -= 16;
	}
}

static inline void vectormodq_xswapeliminate(Fq *f, Fq *g, int len, const Fq f0,
					     const Fq g0, int mask)
{
	__m256i f0vec = _mm256_set1_epi16(f0);
	__m256i g0vec = _mm256_set1_epi16(g0);
	__m256i f0vecqinv = _mm256_mullo_epi16(f0vec, qinvvec);
	__m256i g0vecqinv = _mm256_mullo_epi16(g0vec, qinvvec);
	__m256i maskvec = _mm256_set1_epi32(mask);

	f += len + (-len & 15);
	g += len + (-len & 15);
	while (len > 0) {
		f -= 16;
		g -= 16;
		len -= 16;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		__m256i fi = _mm256_loadu_si256((__m256i *)f);
		__m256i gi = _mm256_loadu_si256((__m256i *)g);
#pragma GCC diagnostic pop
		__m256i finew = _mm256_blendv_epi8(fi, gi, maskvec);
		__m256i ginew = _mm256_blendv_epi8(gi, fi, maskvec);
		ginew = _mm256_sub_epi16(montproduct(ginew, f0vec, f0vecqinv),
					 montproduct(finew, g0vec, g0vecqinv));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		_mm256_storeu_si256((__m256i *)(f + 1), finew);
		_mm256_storeu_si256((__m256i *)g, ginew);
#pragma GCC diagnostic pop
	}
}

void sntrup_core_inv_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			  const uint8_t *kbytes, const uint8_t *cbytes,
			  struct ws_core_inv *ws)
{
	small *in = (small *)inbytes;
	int loop;
	int i;
	int delta = 1;
	int minusdelta;
	int fgflip;
	int swap;

	(void)kbytes;
	(void)cbytes;

	LC_FPU_ENABLE;

	for (i = 0; i < ppad; ++i)
		ws->f[i] = 0;
	ws->f[0] = 1;
	ws->f[p - 1] = -1;
	ws->f[p] = -1;
	/* generalization: initialize f to reversal of any deg-p polynomial m */

	for (i = 0; i < p; ++i)
		ws->g[i] = in[p - 1 - i];
	for (i = p; i < ppad; ++i)
		ws->g[i] = 0;

	for (i = 0; i < ppad; ++i)
		ws->r[i] = 0;
	ws->r[0] = Fq_recip(3);

	for (i = 0; i < ppad; ++i)
		ws->v[i] = 0;

	for (loop = 0; loop < p; ++loop) {
		ws->g0 = Fq_freeze(ws->g[0]);
		ws->f0 = ws->f[0];
		if (q > 5167)
			ws->f0 = Fq_freeze(ws->f0);

		minusdelta = -delta;
		swap = sntrup_int16_negative_mask((int16_t)minusdelta) &
		       sntrup_int16_nonzero_mask(ws->g0);
		delta ^= swap & (delta ^ minusdelta);
		delta += 1;

		fgflip = swap & (ws->f0 ^ ws->g0);
		ws->f0 ^= (Fq)fgflip;
		ws->g0 ^= (Fq)fgflip;

		ws->f[0] = ws->f0;

		vectormodq_swapeliminate(ws->f + 1, ws->g + 1, p, ws->f0,
					 ws->g0, swap);
		vectormodq_xswapeliminate(ws->v, ws->r, loop + 1, ws->f0,
					  ws->g0, swap);
	}

	for (loop = p - 1; loop > 0; --loop) {
		ws->g0 = Fq_freeze(ws->g[0]);
		ws->f0 = ws->f[0];
		if (q > 5167)
			ws->f0 = Fq_freeze(ws->f0);

		minusdelta = -delta;
		swap = sntrup_int16_negative_mask((int16_t)minusdelta) &
		       sntrup_int16_nonzero_mask(ws->g0);
		delta ^= swap & (delta ^ minusdelta);
		delta += 1;

		fgflip = swap & (ws->f0 ^ ws->g0);
		ws->f0 ^= (Fq)fgflip;
		ws->g0 ^= (Fq)fgflip;

		ws->f[0] = ws->f0;

		vectormodq_swapeliminate(ws->f + 1, ws->g + 1, loop, ws->f0,
					 ws->g0, swap);
		vectormodq_xswapeliminate(ws->v, ws->r, p, ws->f0, ws->g0,
					  swap);
	}

	ws->scale = Fq_recip(Fq_freeze(ws->f[0]));
	for (i = 0; i < p; ++i)
		ws->out[i] = Fq_bigfreeze(ws->scale *
					  (int32_t)Fq_freeze(ws->v[p - i]));

	sntrup_encode_pxint16(outbytes, ws->out);
	outbytes[2 * p] = (uint8_t)sntrup_int16_nonzero_mask((int16_t)delta);

	LC_FPU_DISABLE;
}
