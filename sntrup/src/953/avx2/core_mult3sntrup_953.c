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
#include "ntt.h"
#include "sntrup_int8.h"
#include "sntrup_int32.h"
#include "sntrup_int64.h"
#include "sntrup_uint64.h"
#include "params.h"

#define int16x16 __m256i
#define load_x16(p) _mm256_loadu_si256((int16x16 *)(p))
#define store_x16(p, v) _mm256_storeu_si256((int16x16 *)(p), (v))
#define const_x16 _mm256_set1_epi16
#define add_x16 _mm256_add_epi16
#define sub_x16 _mm256_sub_epi16
#define mullo_x16 _mm256_mullo_epi16
#define mulhi_x16 _mm256_mulhi_epi16
#define mulhrs_x16 _mm256_mulhrs_epi16
#define signmask_x16(x) _mm256_srai_epi16((x), 15)

static int16x16 squeeze_3_x16(int16x16 x)
{
	return sub_x16(x, mullo_x16(mulhrs_x16(x, const_x16(10923)),
				    const_x16(3)));
}

static int16x16 squeeze_7681_x16(int16x16 x)
{
	return sub_x16(x,
		       mullo_x16(mulhrs_x16(x, const_x16(4)), const_x16(7681)));
}

static int16x16 mulmod_7681_x16(int16x16 x, int16x16 y)
{
	int16x16 yqinv = mullo_x16(y, const_x16(-7679)); /* XXX: precompute */
	int16x16 b = mulhi_x16(x, y);
	int16x16 d = mullo_x16(x, yqinv);
	int16x16 e = mulhi_x16(d, const_x16(7681));
	return sub_x16(b, e);
}

static void stride(int16_t fpad[4][512], const int16_t f[1024])
{
	int16x16 f0, f1, f2, f3, g0, g1, g2, g3;
	int i, j;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (j = 0; j < 256; j += 16) {
		f0 = load_x16(&f[0]);
		f1 = load_x16(&f[16]);
		f2 = load_x16(&f[32]);
		f3 = load_x16(&f[48]);
		f += 64;

		g0 = _mm256_permute2x128_si256(f0, f2, 0x20);
		g1 = _mm256_permute2x128_si256(f0, f2, 0x31);
		g2 = _mm256_permute2x128_si256(f1, f3, 0x20);
		g3 = _mm256_permute2x128_si256(f1, f3, 0x31);
		f0 = _mm256_unpacklo_epi16(g0, g1);
		f1 = _mm256_unpackhi_epi16(g0, g1);
		f2 = _mm256_unpacklo_epi16(g2, g3);
		f3 = _mm256_unpackhi_epi16(g2, g3);
		g0 = _mm256_unpacklo_epi16(f0, f1);
		g1 = _mm256_unpackhi_epi16(f0, f1);
		g2 = _mm256_unpacklo_epi16(f2, f3);
		g3 = _mm256_unpackhi_epi16(f2, f3);
		f0 = _mm256_unpacklo_epi64(g0, g2);
		f1 = _mm256_unpackhi_epi64(g0, g2);
		f2 = _mm256_unpacklo_epi64(g1, g3);
		f3 = _mm256_unpackhi_epi64(g1, g3);

		store_x16(&fpad[0][j], f0);
		store_x16(&fpad[1][j], f1);
		store_x16(&fpad[2][j], f2);
		store_x16(&fpad[3][j], f3);
	}
#pragma GCC diagnostic pop

	for (i = 0; i < 4; ++i)
		for (j = 256; j < 512; ++j)
			fpad[i][j] = 0;
}

static void unstride(int16_t f[2048], const int16_t fpad[4][512])
{
	int16x16 f0, f1, f2, f3, g0, g1, g2, g3, h0, h1, h2, h3;
	int j;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (j = 0; j < 512; j += 16) {
		f0 = load_x16(&fpad[0][j]);
		f1 = load_x16(&fpad[1][j]);
		f2 = load_x16(&fpad[2][j]);
		f3 = load_x16(&fpad[3][j]);

		g2 = _mm256_unpacklo_epi16(f2, f3);
		g3 = _mm256_unpackhi_epi16(f2, f3);
		g0 = _mm256_unpacklo_epi16(f0, f1);
		h0 = _mm256_unpacklo_epi32(g0, g2);
		h1 = _mm256_unpackhi_epi32(g0, g2);
		g1 = _mm256_unpackhi_epi16(f0, f1);
		h2 = _mm256_unpacklo_epi32(g1, g3);
		h3 = _mm256_unpackhi_epi32(g1, g3);
		f1 = _mm256_permute2x128_si256(h2, h3, 0x20);
		f3 = _mm256_permute2x128_si256(h2, h3, 0x31);
		f0 = _mm256_permute2x128_si256(h0, h1, 0x20);
		f2 = _mm256_permute2x128_si256(h0, h1, 0x31);

		store_x16(&f[0], f0);
		store_x16(&f[16], f1);
		store_x16(&f[32], f2);
		store_x16(&f[48], f3);
		f += 64;
	}
#pragma GCC diagnostic pop
}

#define ALIGNED __attribute((aligned(32)))

static const ALIGNED int16_t y_7681[512] = {
#include "precomp7681.inc"
};

static void mult1024(int16_t h[2048], const int16_t f[1024],
		     const int16_t g[1024], struct ws_core_mult3_avx2 *ws)
{
#define fpad ws->fgpad
#define gpad (ws->fgpad + 4)
#define hpad fpad
	int i;

	stride(fpad, f);
	stride(gpad, g);

	ntt512_7681(ws->fgpad[0], 8);

	/* XXX: try arbitrary-degree Karatsuba */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < 512; i += 16) {
		ws->f0 = squeeze_7681_x16(load_x16(&fpad[0][i]));
		ws->f1 = squeeze_7681_x16(load_x16(&fpad[1][i]));
		ws->f2 = squeeze_7681_x16(load_x16(&fpad[2][i]));
		ws->f3 = squeeze_7681_x16(load_x16(&fpad[3][i]));
		ws->g0 = squeeze_7681_x16(load_x16(&gpad[0][i]));
		ws->g1 = squeeze_7681_x16(load_x16(&gpad[1][i]));
		ws->g2 = squeeze_7681_x16(load_x16(&gpad[2][i]));
		ws->g3 = squeeze_7681_x16(load_x16(&gpad[3][i]));
		ws->d0 = mulmod_7681_x16(ws->f0, ws->g0);
		ws->d1 = mulmod_7681_x16(ws->f1, ws->g1);
		ws->d2 = mulmod_7681_x16(ws->f2, ws->g2);
		ws->d3 = mulmod_7681_x16(ws->f3, ws->g3);
		ws->d0d1 = add_x16(ws->d0, ws->d1);
		ws->d0d1d2 = add_x16(ws->d0d1, ws->d2);
		ws->d0d1d2d3 = squeeze_7681_x16(add_x16(ws->d0d1d2, ws->d3));
		ws->d2d3 = add_x16(ws->d2, ws->d3);
		ws->d1d2d3 = add_x16(ws->d1, ws->d2d3);
		ws->e01 = mulmod_7681_x16(sub_x16(ws->f0, ws->f1),
					  sub_x16(ws->g0, ws->g1));
		ws->e02 = mulmod_7681_x16(sub_x16(ws->f0, ws->f2),
					  sub_x16(ws->g0, ws->g2));
		ws->e03 = mulmod_7681_x16(sub_x16(ws->f0, ws->f3),
					  sub_x16(ws->g0, ws->g3));
		ws->e12 = mulmod_7681_x16(sub_x16(ws->f1, ws->f2),
					  sub_x16(ws->g1, ws->g2));
		ws->e13 = mulmod_7681_x16(sub_x16(ws->f1, ws->f3),
					  sub_x16(ws->g1, ws->g3));
		ws->e23 = mulmod_7681_x16(sub_x16(ws->f2, ws->f3),
					  sub_x16(ws->g2, ws->g3));
		ws->h0 = ws->d0;
		ws->h1 = sub_x16(ws->d0d1, ws->e01);
		ws->h2 = sub_x16(ws->d0d1d2, ws->e02);
		ws->h3 = sub_x16(ws->d0d1d2d3, add_x16(ws->e12, ws->e03));
		ws->h4 = sub_x16(ws->d1d2d3, ws->e13);
		ws->h5 = sub_x16(ws->d2d3, ws->e23);
		ws->h6 = ws->d3;
		ws->twist = load_x16(&y_7681[i]);
		ws->h4 = mulmod_7681_x16(ws->h4, ws->twist);
		ws->h5 = mulmod_7681_x16(ws->h5, ws->twist);
		ws->h6 = mulmod_7681_x16(ws->h6, ws->twist);
		ws->h0 = add_x16(ws->h0, ws->h4);
		ws->h1 = add_x16(ws->h1, ws->h5);
		ws->h2 = add_x16(ws->h2, ws->h6);
		store_x16(&hpad[0][i], squeeze_7681_x16(ws->h0));
		store_x16(&hpad[1][i], squeeze_7681_x16(ws->h1));
		store_x16(&hpad[2][i], squeeze_7681_x16(ws->h2));
		store_x16(&hpad[3][i], squeeze_7681_x16(ws->h3));
	}

	invntt512_7681(hpad[0], 4);
	unstride(ws->h_7681, hpad);

	for (i = 0; i < 2048; i += 16) {
		ws->h0 = load_x16(&ws->h_7681[i]);
		ws->h0 = mulmod_7681_x16(ws->h0, const_x16(956));
		store_x16(&h[i], ws->h0);
	}
#pragma GCC diagnostic pop
}

static inline int16x16 freeze_3_x16(int16x16 x)
{
	int16x16 mask, x3;
	x = add_x16(x, const_x16(3) & signmask_x16(x));
	mask = signmask_x16(sub_x16(x, const_x16(2)));
	x3 = sub_x16(x, const_x16(3));
	x = _mm256_blendv_epi8(x3, x, mask);
	return x;
}

void sntrup_core_mult3_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			    const uint8_t *kbytes, const uint8_t *cbytes,
			    struct ws_core_mult3 *ws_full)
{
	struct ws_core_mult3_avx2 *ws = &ws_full->u.avx2;
#define h ws->f
	int i;
	int16x16 x;

	(void)cbytes;

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	x = const_x16(0);
	for (i = p & ~15; i < 1024; i += 16)
		store_x16(&ws->f[i], x);
	for (i = p & ~15; i < 1024; i += 16)
		store_x16(&ws->g[i], x);

	for (i = 0; i < p; ++i) {
		int8_t fi = (int8_t)inbytes[i];
		int8_t fi0 = sntrup_int8_bottombit_01(fi);
		ws->f[i] = (int16_t)(fi0 - (fi & (fi0 << 1)));
	}
	for (i = 0; i < p; ++i) {
		int8_t gi = (int8_t)kbytes[i];
		int8_t gi0 = sntrup_int8_bottombit_01(gi);
		ws->g[i] = (int16_t)(gi0 - (gi & (gi0 << 1)));
	}

	mult1024(ws->fg, ws->f, ws->g, ws);

	ws->fg[0] -= ws->fg[p - 1];
	for (i = 0; i < 1024; i += 16) {
		int16x16 fgi = load_x16(&ws->fg[i]);
		int16x16 fgip = load_x16(&ws->fg[i + p]);
		int16x16 fgip1 = load_x16(&ws->fg[i + p - 1]);
		x = add_x16(fgi, add_x16(fgip, fgip1));
		x = freeze_3_x16(squeeze_3_x16(x));
		store_x16(&h[i], x);
	}
#pragma GCC diagnostic pop

	for (i = 0; i < p; ++i)
		outbytes[i] = (uint8_t)h[i];

	LC_FPU_DISABLE;
}
