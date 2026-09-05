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

#include "lc_memset_secure.h"
#include "params.h"

#include "sntrup_int8.h"
#include "sntrup_int16.h"
#include "sntrup_int64.h"
#include "sntrup_uint64.h"

static inline int8_t bitvec_bot(bitvec v)
{
	return (int8_t)sntrup_uint64_bottombit_01(v[0]);
}

static inline int8_t bitvec_get(bitvec v, int pos)
{
	return (int8_t)sntrup_uint64_bitmod_01(v[pos >> 6], (uint64_t)pos);
}

static inline void bitvec_set(bitvec v, int pos, int8_t bit)
{
	bit ^= bitvec_get(v, pos);
	v[pos >> 6] ^= sntrup_uint64_shlmod((uint64_t)bit, (uint64_t)pos);
}

static void bitvec_shiftup(bitvec v)
{
	int i;
	for (i = bitvec_len - 1; i > 0; --i)
		v[i] = (v[i] << 1) |
		       (uint64_t)sntrup_int64_negative_01((int64_t)v[i - 1]);
	v[0] <<= 1;
}

static void bitvec_shiftdown(bitvec v)
{
	int i;
	for (i = 0; i < bitvec_len - 1; ++i)
		v[i] = (v[i] >> 1) |
		       (uint64_t)sntrup_int64_shlmod((int64_t)v[i + 1], 63);
	v[bitvec_len - 1] >>= 1;
}

static void bitvec_condswap(bitvec v, bitvec x, int64_t swap)
{
	int i;
	for (i = 0; i < bitvec_len; ++i) {
		uint64_t t = (uint64_t)swap & (v[i] ^ x[i]);
		v[i] ^= t;
		x[i] ^= t;
	}
}

static void bitvec_eliminate(bitvec f0, bitvec f1, bitvec g0, bitvec g1,
			     uint64_t c0, uint64_t c1)
{
	int i;
	c0 = -c0;
	c1 = -c1;

	for (i = 0; i < bitvec_len; ++i) {
		uint64_t f0i = f0[i];
		uint64_t f1i = f1[i];
		uint64_t g0i = g0[i];
		uint64_t g1i = g1[i];
		uint64_t t;

		f0i &= c0;
		f1i ^= c1;
		f1i &= f0i;

		t = g0i ^ f0i;
		g0[i] = t | (g1i ^ f1i);
		g1[i] = (g1i ^ f0i) & (f1i ^ t);
	}
}

/* byte p of output is 0 if recip succeeded; else -1 */
void sntrup_core_inv3(uint8_t *outbytes, const uint8_t *inbytes,
		      const uint8_t *kbytes, const uint8_t *cbytes,
		      struct ws_core_inv3 *ws_full)
{
	struct ws_core_inv3_ref *ws = &ws_full->u.ref;
	int8_t *out = (int8_t *)outbytes;
	int8_t *in = (int8_t *)inbytes;
	unsigned int i, loop;
	int delta, swap;
	int8_t sign0, sign1;

	(void)kbytes;
	(void)cbytes;

	lc_memset_secure(ws, 0, sizeof(struct ws_core_inv3));

	bitvec_set(ws->r0, 0, 1);
	bitvec_set(ws->f0, 0, 1);
	bitvec_set(ws->f0, p - 1, 1);
	bitvec_set(ws->f1, p - 1, 1);
	bitvec_set(ws->f0, p, 1);
	bitvec_set(ws->f1, p, 1);
	for (i = 0; i < p; ++i) {
		int8_t x0 = sntrup_int8_bottombit_01(in[i]);
		int8_t x1 = x0 & (in[i] >> 1);
		bitvec_set(ws->g0, (int)(p - 1 - i), x0);
		bitvec_set(ws->g1, (int)(p - 1 - i), x1);
	}
	bitvec_set(ws->g0, p, 0);
	bitvec_set(ws->g1, p, 0);

	delta = 1;

	for (loop = 0; loop < 2 * p - 1; ++loop) {
		bitvec_shiftup(ws->v0);
		bitvec_shiftup(ws->v1);

		/* note: this sign is f0g0 _without_ negation */
		sign0 = bitvec_bot(ws->g0) & bitvec_bot(ws->f0);
		sign1 = (bitvec_bot(ws->g1) ^ bitvec_bot(ws->f1)) & sign0;

		swap = sntrup_int16_positive_mask((int16_t)delta) &
		       sntrup_int16_nonzero_mask(bitvec_bot(ws->g0));
		delta ^= swap & (delta ^ -delta);
		delta += 1;

		bitvec_condswap(ws->f0, ws->g0, swap);
		bitvec_condswap(ws->f1, ws->g1, swap);
		bitvec_condswap(ws->v0, ws->r0, swap);
		bitvec_condswap(ws->v1, ws->r1, swap);

		bitvec_eliminate(ws->f0, ws->f1, ws->g0, ws->g1,
				 (uint64_t)sign0, (uint64_t)sign1);
		bitvec_eliminate(ws->v0, ws->v1, ws->r0, ws->r1,
				 (uint64_t)sign0, (uint64_t)sign1);

		bitvec_shiftdown(ws->g0);
		bitvec_shiftdown(ws->g1);
	}

	sign0 = bitvec_bot(ws->f0);
	sign1 = bitvec_bot(ws->f1);
	for (i = 0; i < p; ++i) {
		int8_t m0 = bitvec_get(ws->v0, (int)(p - 1 - i));
		int8_t m1 = bitvec_get(ws->v1, (int)(p - 1 - i));
		m0 &= sign0;
		m1 ^= sign1;
		m1 &= m0;
		out[i] = (int8_t)(m0 - 2 * m1);
	}

	out[p] = (int8_t)sntrup_int16_nonzero_mask((int16_t)delta);
}
