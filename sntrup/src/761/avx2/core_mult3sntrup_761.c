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

#define mask0                                                                  \
	_mm256_set_epi16(-1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1)
#define mask1                                                                  \
	_mm256_set_epi16(0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0)
#define mask2                                                                  \
	_mm256_set_epi16(0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0)

static void good(int16_t fpad[3][512], const int16_t f[768])
{
	int j;
	int16x16 f0, f1;

	j = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (;;) {
		f0 = load_x16(f + j);
		f1 = load_x16(f + 512 + j);
		store_x16(&fpad[0][j], (f0 & mask0) | (f1 & mask1));
		store_x16(&fpad[1][j], (f0 & mask1) | (f1 & mask2));
		store_x16(&fpad[2][j], (f0 & mask2) | (f1 & mask0));
		j += 16;
		if (j == 256)
			break;

		f0 = load_x16(f + j);
		f1 = load_x16(f + 512 + j);
		store_x16(&fpad[0][j], (f0 & mask2) | (f1 & mask0));
		store_x16(&fpad[1][j], (f0 & mask0) | (f1 & mask1));
		store_x16(&fpad[2][j], (f0 & mask1) | (f1 & mask2));
		j += 16;

		f0 = load_x16(f + j);
		f1 = load_x16(f + 512 + j);
		store_x16(&fpad[0][j], (f0 & mask1) | (f1 & mask2));
		store_x16(&fpad[1][j], (f0 & mask2) | (f1 & mask0));
		store_x16(&fpad[2][j], (f0 & mask0) | (f1 & mask1));
		j += 16;
	}
	for (;;) {
		f0 = load_x16(f + j);
		store_x16(&fpad[0][j], f0 & mask2);
		store_x16(&fpad[1][j], f0 & mask0);
		store_x16(&fpad[2][j], f0 & mask1);
		j += 16;
		if (j == 512)
			break;

		f0 = load_x16(f + j);
		store_x16(&fpad[0][j], f0 & mask1);
		store_x16(&fpad[1][j], f0 & mask2);
		store_x16(&fpad[2][j], f0 & mask0);
		j += 16;

		f0 = load_x16(f + j);
		store_x16(&fpad[0][j], f0 & mask0);
		store_x16(&fpad[1][j], f0 & mask1);
		store_x16(&fpad[2][j], f0 & mask2);
		j += 16;
	}
#pragma GCC diagnostic pop
}

static void ungood(int16_t f[1536], const int16_t fpad[3][512])
{
	int j;
	int16x16 f0, f1, f2, g0, g1, g2;

	j = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (;;) {
		f0 = load_x16(&fpad[0][j]);
		f1 = load_x16(&fpad[1][j]);
		f2 = load_x16(&fpad[2][j]);
		g0 = (f0 & mask0) | (f1 & mask1) | (f2 & mask2);
		g1 = (f0 & mask1) | (f1 & mask2) | (f2 & mask0);
		g2 = f0 ^ f1 ^ f2 ^ g0 ^
		     g1; /* same as (f0&mask2)|(f1&mask0)|(f2&mask1) */
		store_x16(f + 0 + j, g0);
		store_x16(f + 512 + j, g1);
		store_x16(f + 1024 + j, g2);
		j += 16;

		f0 = load_x16(&fpad[0][j]);
		f1 = load_x16(&fpad[1][j]);
		f2 = load_x16(&fpad[2][j]);
		g0 = (f0 & mask2) | (f1 & mask0) | (f2 & mask1);
		g1 = (f0 & mask0) | (f1 & mask1) | (f2 & mask2);
		g2 = f0 ^ f1 ^ f2 ^ g0 ^
		     g1; /* same as (f0&mask1)|(f1&mask2)|(f2&mask0) */
		store_x16(f + 0 + j, g0);
		store_x16(f + 512 + j, g1);
		store_x16(f + 1024 + j, g2);
		j += 16;
		if (j == 512)
			break;

		f0 = load_x16(&fpad[0][j]);
		f1 = load_x16(&fpad[1][j]);
		f2 = load_x16(&fpad[2][j]);
		g0 = (f0 & mask1) | (f1 & mask2) | (f2 & mask0);
		g1 = (f0 & mask2) | (f1 & mask0) | (f2 & mask1);
		g2 = f0 ^ f1 ^ f2 ^ g0 ^
		     g1; /* same as (f0&mask0)|(f1&mask1)|(f2&mask2) */
		store_x16(f + 0 + j, g0);
		store_x16(f + 512 + j, g1);
		store_x16(f + 1024 + j, g2);
		j += 16;
	}
#pragma GCC diagnostic pop
}

#define ALIGNED __attribute((aligned(32)))

static void mult768(int16_t h[1536], const int16_t f[768], const int16_t g[768],
		    struct ws_core_mult3_avx2 *ws)
{
#define fpad ws->fgpad
#define gpad (ws->fgpad + 3)
#define hpad fpad
	int i;

	good(fpad, f);
	good(gpad, g);

	ntt512_7681(ws->fgpad[0], 6);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < 512; i += 16) {
		ws->f0 = squeeze_7681_x16(load_x16(&fpad[0][i]));
		ws->f1 = squeeze_7681_x16(load_x16(&fpad[1][i]));
		ws->f2 = squeeze_7681_x16(load_x16(&fpad[2][i]));
		ws->g0 = squeeze_7681_x16(load_x16(&gpad[0][i]));
		ws->g1 = squeeze_7681_x16(load_x16(&gpad[1][i]));
		ws->g2 = squeeze_7681_x16(load_x16(&gpad[2][i]));
		ws->d0 = mulmod_7681_x16(ws->f0, ws->g0);
		ws->d1 = mulmod_7681_x16(ws->f1, ws->g1);
		ws->d2 = mulmod_7681_x16(ws->f2, ws->g2);
		ws->d3 = add_x16(add_x16(ws->d0, ws->d1), ws->d2);
		ws->h0 = add_x16(ws->d3,
				 mulmod_7681_x16(sub_x16(ws->f2, ws->f1),
						 sub_x16(ws->g1, ws->g2)));
		ws->h1 = add_x16(ws->d3,
				 mulmod_7681_x16(sub_x16(ws->f1, ws->f0),
						 sub_x16(ws->g0, ws->g1)));
		ws->h2 = add_x16(ws->d3,
				 mulmod_7681_x16(sub_x16(ws->f0, ws->f2),
						 sub_x16(ws->g2, ws->g0)));
		store_x16(&hpad[0][i], squeeze_7681_x16(ws->h0));
		store_x16(&hpad[1][i], squeeze_7681_x16(ws->h1));
		store_x16(&hpad[2][i], squeeze_7681_x16(ws->h2));
	}

	invntt512_7681(hpad[0], 3);
	ungood(ws->h_7681, hpad);

	for (i = 0; i < 1536; i += 16) {
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
	for (i = p & ~15; i < 768; i += 16)
		store_x16(&ws->f[i], x);
	for (i = p & ~15; i < 768; i += 16)
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

	mult768(ws->fg, ws->f, ws->g, ws);

	ws->fg[0] -= ws->fg[p - 1];
	for (i = 0; i < 768; i += 16) {
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
