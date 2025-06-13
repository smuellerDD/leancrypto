/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 * Modifications Copyright 2020 David Schatz
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#include "field.h"
#include "point_448.h"
#include "lc_ed448.h"
#include "lc_memset_secure.h"
#include "small_stack_support.h"
#include "word.h"

#define C448_WNAF_FIXED_TABLE_BITS 5
#define C448_WNAF_VAR_TABLE_BITS 3
#define TWISTED_D (EDWARDS_D - 1)
#define WBITS C448_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

static const curve448_scalar_t precomputed_scalarmul_adjustment = {
	{ { SC_LIMB(0xc873d6d54a7bb0cfULL), SC_LIMB(0xe933d8d723a70aadULL),
	    SC_LIMB(0xbb124b65129c96fdULL), SC_LIMB(0x00000008335dc163ULL) } }
};

/** identity = (0,1) */
static const curve448_point_t curve448_point_identity = {
	{ { { { 0 } } }, { { { 1 } } }, { { { 1 } } }, { { { 0 } } } }
};

static void point_double_internal(curve448_point_t p, const curve448_point_t q,
				  int before_double)
{
	gf a, b, c, d;

	gf_sqr(c, q->x);
	gf_sqr(a, q->y);
	gf_add_nr(d, c, a); /* 2+e */
	gf_add_nr(p->t, q->y, q->x); /* 2+e */
	gf_sqr(b, p->t);
	gf_subx_nr(b, b, d, 3); /* 4+e */
	gf_sub_nr(p->t, a, c); /* 3+e */
	gf_sqr(p->x, q->z);
	gf_add_nr(p->z, p->x, p->x); /* 2+e */
	gf_subx_nr(a, p->z, p->t, 4); /* 6+e */
	if (GF_HEADROOM == 5)
		gf_weak_reduce(a); /* or 1+e */
	gf_mul(p->x, a, b);
	gf_mul(p->z, p->t, a);
	gf_mul(p->y, p->t, d);
	if (!before_double)
		gf_mul(p->t, b, d);
}

void curve448_point_double(curve448_point_t p, const curve448_point_t q)
{
	point_double_internal(p, q, 0);
}

/* Operations on [p]niels */
static inline void cond_neg_niels(niels_t n, mask_t neg)
{
	gf_cond_swap(n->a, n->b, neg);
	gf_cond_neg(n->c, neg);
}

static void pt_to_pniels(pniels_t b, const curve448_point_t a)
{
	gf_sub(b->n->a, a->y, a->x);
	gf_add(b->n->b, a->x, a->y);
	gf_mulw(b->n->c, a->t, 2 * TWISTED_D);
	gf_add(b->z, a->z, a->z);
}

static void pniels_to_pt(curve448_point_t e, const pniels_t d)
{
	gf eu;

	gf_add(eu, d->n->b, d->n->a);
	gf_sub(e->y, d->n->b, d->n->a);
	gf_mul(e->t, e->y, eu);
	gf_mul(e->x, d->z, e->y);
	gf_mul(e->y, d->z, eu);
	gf_sqr(e->z, d->z);
}

static void niels_to_pt(curve448_point_t e, const niels_t n)
{
	gf_add(e->y, n->b, n->a);
	gf_sub(e->x, n->b, n->a);
	gf_mul(e->t, e->y, e->x);
	gf_copy(e->z, ONE);
}

static void add_niels_to_pt(curve448_point_t d, const niels_t e,
			    int before_double)
{
	gf a, b, c;

	gf_sub_nr(b, d->y, d->x); /* 3+e */
	gf_mul(a, e->a, b);
	gf_add_nr(b, d->x, d->y); /* 2+e */
	gf_mul(d->y, e->b, b);
	gf_mul(d->x, e->c, d->t);
	gf_add_nr(c, a, d->y); /* 2+e */
	gf_sub_nr(b, d->y, a); /* 3+e */
	gf_sub_nr(d->y, d->z, d->x); /* 3+e */
	gf_add_nr(a, d->x, d->z); /* 2+e */
	gf_mul(d->z, a, d->y);
	gf_mul(d->x, d->y, b);
	gf_mul(d->y, a, c);
	if (!before_double)
		gf_mul(d->t, b, c);
}

static void sub_niels_from_pt(curve448_point_t d, const niels_t e,
			      int before_double)
{
	gf a, b, c;

	gf_sub_nr(b, d->y, d->x); /* 3+e */
	gf_mul(a, e->b, b);
	gf_add_nr(b, d->x, d->y); /* 2+e */
	gf_mul(d->y, e->a, b);
	gf_mul(d->x, e->c, d->t);
	gf_add_nr(c, a, d->y); /* 2+e */
	gf_sub_nr(b, d->y, a); /* 3+e */
	gf_add_nr(d->y, d->z, d->x); /* 2+e */
	gf_sub_nr(a, d->z, d->x); /* 3+e */
	gf_mul(d->z, a, d->y);
	gf_mul(d->x, d->y, b);
	gf_mul(d->y, a, c);
	if (!before_double)
		gf_mul(d->t, b, c);
}

static void add_pniels_to_pt(curve448_point_t p, const pniels_t pn,
			     int before_double)
{
	gf L0;

	gf_mul(L0, p->z, pn->z);
	gf_copy(p->z, L0);
	add_niels_to_pt(p, pn->n, before_double);
}

static void sub_pniels_from_pt(curve448_point_t p, const pniels_t pn,
			       int before_double)
{
	gf L0;

	gf_mul(L0, p->z, pn->z);
	gf_copy(p->z, L0);
	sub_niels_from_pt(p, pn->n, before_double);
}

c448_bool_t curve448_point_eq(const curve448_point_t p,
			      const curve448_point_t q)
{
	mask_t succ;
	gf a, b;

	/* equality mod 2-torsion compares x/y */
	gf_mul(a, p->y, q->x);
	gf_mul(b, q->y, p->x);
	succ = gf_eq(a, b);

	return mask_to_bool(succ);
}

c448_bool_t curve448_point_valid(const curve448_point_t p)
{
	mask_t out;
	gf a, b, c;

	gf_mul(a, p->x, p->y);
	gf_mul(b, p->z, p->t);
	out = gf_eq(a, b);
	gf_sqr(a, p->x);
	gf_sqr(b, p->y);
	gf_sub(a, b, a);
	gf_sqr(b, p->t);
	gf_mulw(c, b, TWISTED_D);
	gf_sqr(b, p->z);
	gf_add(b, b, c);
	out &= gf_eq(a, b);
	out &= ~gf_eq(p->z, ZERO);
	return mask_to_bool(out);
}

static inline void constant_time_lookup_niels(niels_s *RESTRICT ni,
					      const niels_t *table,
					      size_t nelts, size_t idx)
{
	constant_time_lookup(ni, table, sizeof(niels_s), nelts, idx);
}

void curve448_precomputed_scalarmul(curve448_point_t out,
				    const curve448_precomputed_s *table,
				    const curve448_scalar_t scalar)
{
	unsigned int i, j, k;
	const unsigned int n = COMBS_N, t = COMBS_T, s = COMBS_S;
	niels_t ni;
	curve448_scalar_t scalar1x;

	curve448_scalar_add(scalar1x, scalar, precomputed_scalarmul_adjustment);
	curve448_scalar_halve(scalar1x, scalar1x);

	for (i = s; i > 0; i--) {
		if (i != s)
			point_double_internal(out, out, 0);

		for (j = 0; j < n; j++) {
			size_t tab = 0;
			mask_t invert;

			for (k = 0; k < t; k++) {
				unsigned int bit = (i - 1) + s * (k + j * t);

				if (bit < C448_SCALAR_BITS)
					tab |= (scalar1x->limb[bit / WBITS] >>
							(bit % WBITS) &
						1)
					       << k;
			}

			invert = (mask_t)((tab >> (t - 1)) - 1);
			tab ^= invert;
			tab &= (size_t)((1 << (t - 1)) - 1);

			constant_time_lookup_niels(ni,
						   &table->table[j << (t - 1)],
						   1 << (t - 1), tab);

			cond_neg_niels(ni, invert);
			if ((i != s) || j != 0)
				add_niels_to_pt(out, ni, j == n - 1 && i != 1);
			else
				niels_to_pt(out, ni);
		}
	}

	lc_memset_secure(ni, 0, sizeof(ni));
	lc_memset_secure(scalar1x, 0, sizeof(scalar1x));
}

void curve448_point_mul_by_ratio_and_encode_like_eddsa(
	uint8_t enc[LC_ED448_PUBLICKEYBYTES], const curve448_point_t p)
{
	/* The point is now on the twisted curve.  Move it to untwisted. */
	gf x, y, z, t, u;
	curve448_point_t q;

	curve448_point_copy(q, p);

	/* 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) */
	gf_sqr(x, q->x);
	gf_sqr(t, q->y);
	gf_add(u, x, t);
	gf_add(z, q->y, q->x);
	gf_sqr(y, z);
	gf_sub(y, y, u);
	gf_sub(z, t, x);
	gf_sqr(x, q->z);
	gf_add(t, x, x);
	gf_sub(t, t, z);
	gf_mul(x, t, y);
	gf_mul(y, z, u);
	gf_mul(z, u, t);

	/* Affinize */
	gf_invert(z, z);
	gf_mul(t, x, z);
	gf_mul(x, y, z);

	/* Encode */
	enc[LC_ED448_SECRETKEYBYTES - 1] = 0;
	gf_serialize(enc, x, 1);
	enc[LC_ED448_SECRETKEYBYTES - 1] |= 0x80 & gf_lobit(t);

	lc_memset_secure(x, 0, sizeof(x));
	lc_memset_secure(y, 0, sizeof(y));
	lc_memset_secure(z, 0, sizeof(z));
	lc_memset_secure(t, 0, sizeof(t));
	lc_memset_secure(u, 0, sizeof(u));
	curve448_point_destroy(q);
}

int curve448_point_decode_like_eddsa_and_mul_by_ratio(
	curve448_point_t p, const uint8_t enc[LC_ED448_PUBLICKEYBYTES])
{
	uint8_t enc2[LC_ED448_PUBLICKEYBYTES];
	memcpy(enc2, enc, sizeof(enc2));

	mask_t low = ~word_is_zero(enc2[LC_ED448_SECRETKEYBYTES - 1] & 0x80);
	enc2[LC_ED448_SECRETKEYBYTES - 1] &= (uint8_t)~0x80;

	mask_t succ = gf_deserialize(p->y, enc2, 0, 0);

	gf_sqr(p->x, p->y);
	gf_sub(p->z, ONE, p->x); /* num = 1-y^2 */
	gf_mulw(p->t, p->x, EDWARDS_D); /* dy^2 */
	gf_sub(p->t, ONE, p->t); /* denom = 1-dy^2 or 1-d + dy^2 */

	gf_mul(p->x, p->z, p->t);
	succ &= gf_isr(p->t, p->x); /* 1/sqrt(num * denom) */

	gf_mul(p->x, p->t, p->z); /* sqrt(num / denom) */
	gf_cond_neg(p->x, gf_lobit(p->x) ^ low);
	gf_copy(p->z, ONE);

	/* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
	gf a, b, c, d;
	gf_sqr(c, p->x);
	gf_sqr(a, p->y);
	gf_add(d, c, a);
	gf_add(p->t, p->y, p->x);
	gf_sqr(b, p->t);
	gf_sub(b, b, d);
	gf_sub(p->t, a, c);
	gf_sqr(p->x, p->z);
	gf_add(p->z, p->x, p->x);
	gf_sub(a, p->z, d);
	gf_mul(p->x, a, b);
	gf_mul(p->z, p->t, a);
	gf_mul(p->y, p->t, d);
	gf_mul(p->t, b, d);
	lc_memset_secure(a, 0, sizeof(a));
	lc_memset_secure(b, 0, sizeof(b));
	lc_memset_secure(c, 0, sizeof(c));
	lc_memset_secure(d, 0, sizeof(d));

	lc_memset_secure(enc2, 0, sizeof(enc2));

	return -(int)mask_to_bool(succ);
}

void curve448_point_mul_by_ratio_and_encode_like_x448(
	uint8_t out[LC_X448_PUBLICKEYBYTES], const curve448_point_t p)
{
	curve448_point_t q;

	curve448_point_copy(q, p);
	gf_invert(q->t, q->x); /* 1/x */
	gf_mul(q->z, q->t, q->y); /* y/x */
	gf_sqr(q->y, q->z); /* (y/x)^2 */
	gf_serialize(out, q->y, 1);
	curve448_point_destroy(q);
}

/* Control for variable-time scalar multiply algorithms. */
struct smvt_control {
	int power, addend;
};

#if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 3))
#define NUMTRAILINGZEROS __builtin_ctz
#else
#define NUMTRAILINGZEROS numtrailingzeros
static uint32_t numtrailingzeros(uint32_t i)
{
	uint32_t tmp;
	uint32_t num = 31;

	if (i == 0)
		return 32;

	tmp = i << 16;
	if (tmp != 0) {
		i = tmp;
		num -= 16;
	}
	tmp = i << 8;
	if (tmp != 0) {
		i = tmp;
		num -= 8;
	}
	tmp = i << 4;
	if (tmp != 0) {
		i = tmp;
		num -= 4;
	}
	tmp = i << 2;
	if (tmp != 0) {
		i = tmp;
		num -= 2;
	}
	tmp = i << 1;
	if (tmp != 0)
		num--;

	return num;
}
#endif

static int recode_wnaf(struct smvt_control *control,
		       /* [nbits/(table_bits + 1) + 3] */
		       const curve448_scalar_t scalar, unsigned int table_bits)
{
	unsigned int table_size = C448_SCALAR_BITS / (table_bits + 1) + 3;
	unsigned int position = table_size - 1; /* at the end */
	uint64_t curr_val = scalar->limb[0] & 0xFFFF;
	uint32_t mask = (uint32_t)((1 << (table_bits + 1)) - 1);
	unsigned int w;
	const unsigned int B_OVER_16 = sizeof(scalar->limb[0]) / 2;
	unsigned int n, i;

	/* place the end marker */
	control[position].power = -1;
	control[position].addend = 0;
	position--;

	/*
     * PERF: Could negate scalar if it's large.  But then would need more cases
     * in the actual code that uses it, all for an expected reduction of like
     * 1/5 op. Probably not worth it.
     */

	for (w = 1; w < (C448_SCALAR_BITS - 1) / 16 + 3; w++) {
		if (w < (C448_SCALAR_BITS - 1) / 16 + 1) {
			/* Refill the 16 high bits of current */
			curr_val += (uint32_t)((scalar->limb[w / B_OVER_16] >>
						(16 * (w % B_OVER_16)))
					       << 16);
		}

		while (curr_val & 0xFFFF) {
			uint32_t pos =
				(uint32_t)NUMTRAILINGZEROS((uint32_t)curr_val);
			uint32_t odd = (uint32_t)curr_val >> pos;
			int32_t delta = (int32_t)(odd & mask);

			if (odd & (1 << (table_bits + 1)))
				delta -= (1 << (table_bits + 1));
			curr_val -= (uint64_t)(delta * (1 << pos));
			control[position].power = (int)(pos + 16 * (w - 1));
			control[position].addend = (int)delta;
			position--;
		}
		curr_val >>= 16;
	}
	//assert(current == 0);

	position++;
	n = table_size - position;
	for (i = 0; i < n; i++)
		control[i] = control[i + position];

	return (int)(n - 1);
}

static void prepare_wnaf_table(pniels_t *output, const curve448_point_t working,
			       unsigned int tbits)
{
	curve448_point_t tmp;
	int i;
	pniels_t twop;

	pt_to_pniels(output[0], working);

	if (tbits == 0)
		return;

	curve448_point_double(tmp, working);
	pt_to_pniels(twop, tmp);

	add_pniels_to_pt(tmp, output[0], 0);
	pt_to_pniels(output[1], tmp);

	for (i = 2; i < 1 << tbits; i++) {
		add_pniels_to_pt(tmp, twop, 0);
		pt_to_pniels(output[i], tmp);
	}

	curve448_point_destroy(tmp);
	lc_memset_secure(twop, 0, sizeof(twop));
}

int curve448_base_double_scalarmul_non_secret(curve448_point_t combo,
					      const curve448_scalar_t scalar1,
					      const curve448_point_t base2,
					      const curve448_scalar_t scalar2)
{
	static const int table_bits_var = C448_WNAF_VAR_TABLE_BITS;
	static const int table_bits_pre = C448_WNAF_FIXED_TABLE_BITS;
	struct workspace {
		struct smvt_control control_var
			[C448_SCALAR_BITS / (C448_WNAF_VAR_TABLE_BITS + 1) + 3];
		struct smvt_control
			control_pre[C448_SCALAR_BITS /
					    (C448_WNAF_FIXED_TABLE_BITS + 1) +
				    3];
		pniels_t precmp_var[1 << C448_WNAF_VAR_TABLE_BITS];
	};
	int ncb_pre, ncb_var;
	int contp = 0, contv = 0, i;
	LC_DECLARE_MEM(ws, struct workspace, 8);

	ncb_pre = recode_wnaf(ws->control_pre, scalar1, table_bits_pre);
	ncb_var = recode_wnaf(ws->control_var, scalar2, table_bits_var);

	prepare_wnaf_table(ws->precmp_var, base2, table_bits_var);
	i = ws->control_var[0].power;

	if (i < 0) {
		curve448_point_copy(combo, curve448_point_identity);
		return 0;
	}
	if (i > ws->control_pre[0].power) {
		pniels_to_pt(combo,
			     ws->precmp_var[ws->control_var[0].addend >> 1]);
		contv++;
	} else if (i == ws->control_pre[0].power && i >= 0) {
		pniels_to_pt(combo,
			     ws->precmp_var[ws->control_var[0].addend >> 1]);
		add_niels_to_pt(
			combo,
			curve448_wnaf_base[ws->control_pre[0].addend >> 1], i);
		contv++;
		contp++;
	} else {
		i = ws->control_pre[0].power;
		niels_to_pt(combo,
			    curve448_wnaf_base[ws->control_pre[0].addend >> 1]);
		contp++;
	}

	for (i--; i >= 0; i--) {
		int cv = (i == ws->control_var[contv].power);
		int cp = (i == ws->control_pre[contp].power);

		point_double_internal(combo, combo, i && !(cv || cp));

		if (cv) {
			//assert(control_var[contv].addend);

			if (ws->control_var[contv].addend > 0)
				add_pniels_to_pt(
					combo,
					ws->precmp_var[ws->control_var[contv]
							       .addend >>
						       1],
					i && !cp);
			else
				sub_pniels_from_pt(
					combo,
					ws->precmp_var[(-ws->control_var[contv]
								 .addend) >>
						       1],
					i && !cp);
			contv++;
		}

		if (cp) {
			//assert(control_pre[contp].addend);

			if (ws->control_pre[contp].addend > 0)
				add_niels_to_pt(
					combo,
					curve448_wnaf_base[ws->control_pre[contp]
								   .addend >>
							   1],
					i);
			else
				sub_niels_from_pt(
					combo,
					curve448_wnaf_base[(-ws->control_pre[contp]
								     .addend) >>
							   1],
					i);
			contp++;
		}
	}

	//assert(contv == ncb_var);
	(void)ncb_var;
	//assert(contp == ncb_pre);
	(void)ncb_pre;

	LC_RELEASE_MEM(ws);
	return 0;
}

void curve448_point_destroy(curve448_point_t point)
{
	lc_memset_secure(point, 0, sizeof(curve448_point_t));
}
