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
 * This file is derived from
 * https://github.com/floodyberry/poly1305-donna marked as "PUBLIC DOMAIN"
 */

/*
 * poly1305 implementation using 64 bit * 64 bit = 128 bit multiplication and
 * 128 bit addition
 */

#ifndef POLY1305_64_H
#define POLY1305_64_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
#include <intrin.h>

typedef struct uint128_t {
	unsigned long long lo;
	unsigned long long hi;
} uint128_t;

#define MUL(out, x, y) out.lo = _umul128((x), (y), &out.hi)
#define ADD(out, in)                                                           \
	{                                                                      \
		unsigned long long t = out.lo;                                 \
		out.lo += in.lo;                                               \
		out.hi += (out.lo < t) + in.hi;                                \
	}
#define ADDLO(out, in)                                                         \
	{                                                                      \
		unsigned long long t = out.lo;                                 \
		out.lo += in;                                                  \
		out.hi += (out.lo < t);                                        \
	}
#define SHR(in, shift) (__shiftright128(in.lo, in.hi, (shift)))
#define LO(in) (in.lo)

#elif defined(__GNUC__)
#if defined(__SIZEOF_INT128__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef unsigned __int128 uint128_t;
#pragma GCC diagnostic pop
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif

#define MUL(out, x, y) out = ((uint128_t)x * y)
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (unsigned long long)(in >> (shift))
#define LO(in) (unsigned long long)(in)

#endif

#define poly1305_block_size (16UL)

/* 17 + sizeof(size_t) + 8*sizeof(unsigned long long) */
typedef struct poly1305_state_internal_t {
	unsigned long long r[3];
	unsigned long long h[3];
	unsigned long long pad[2];
	size_t leftover;
	uint8_t buffer[poly1305_block_size];
	uint8_t final;
} poly1305_state_internal_t;

/*
 * interpret eight 8 bit unsigned integers as a 64 bit unsigned integer in
 * little endian
 */
static unsigned long long U8TO64(const uint8_t *p)
{
	return (((unsigned long long)(p[0] & 0xff)) |
		((unsigned long long)(p[1] & 0xff) << 8) |
		((unsigned long long)(p[2] & 0xff) << 16) |
		((unsigned long long)(p[3] & 0xff) << 24) |
		((unsigned long long)(p[4] & 0xff) << 32) |
		((unsigned long long)(p[5] & 0xff) << 40) |
		((unsigned long long)(p[6] & 0xff) << 48) |
		((unsigned long long)(p[7] & 0xff) << 56));
}

/*
 * store a 64 bit unsigned integer as eight 8 bit unsigned integers in little
 * endian
 */
static void U64TO8(uint8_t *p, unsigned long long v)
{
	p[0] = (uint8_t)((v) & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
	p[4] = (uint8_t)((v >> 32) & 0xff);
	p[5] = (uint8_t)((v >> 40) & 0xff);
	p[6] = (uint8_t)((v >> 48) & 0xff);
	p[7] = (uint8_t)((v >> 56) & 0xff);
}

void lc_poly1305_init(struct lc_poly1305_context *ctx, const uint8_t key[32])
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long long t0, t1;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	t0 = U8TO64(&key[0]);
	t1 = U8TO64(&key[8]);

	st->r[0] = (t0) & 0xffc0fffffff;
	st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	st->r[2] = ((t1 >> 24)) & 0x00ffffffc0f;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;

	/* save pad for later */
	st->pad[0] = U8TO64(&key[16]);
	st->pad[1] = U8TO64(&key[24]);

	st->leftover = 0;
	st->final = 0;
}

static void lc_poly1305_blocks(poly1305_state_internal_t *st, const uint8_t *m,
			       size_t bytes)
{
	const unsigned long long hibit =
		(st->final) ? 0 : ((unsigned long long)1 << 40); /* 1 << 128 */
	unsigned long long r0, r1, r2;
	unsigned long long s1, s2;
	unsigned long long h0, h1, h2;
	unsigned long long c;
	uint128_t d0, d1, d2, d;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	s1 = r1 * (5 << 2);
	s2 = r2 * (5 << 2);

	while (bytes >= poly1305_block_size) {
		unsigned long long t0, t1;

		/* h += m[i] */
		t0 = U8TO64(&m[0]);
		t1 = U8TO64(&m[8]);

		h0 += ((t0) & 0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

		/* h *= r */
		MUL(d0, h0, r0);
		MUL(d, h1, s2);
		ADD(d0, d);
		MUL(d, h2, s1);
		ADD(d0, d);
		MUL(d1, h0, r1);
		MUL(d, h1, r0);
		ADD(d1, d);
		MUL(d, h2, s2);
		ADD(d1, d);
		MUL(d2, h0, r2);
		MUL(d, h1, r1);
		ADD(d2, d);
		MUL(d, h2, r0);
		ADD(d2, d);

		/* (partial) h %= p */
		c = SHR(d0, 44);
		h0 = LO(d0) & 0xfffffffffff;
		ADDLO(d1, c);
		c = SHR(d1, 44);
		h1 = LO(d1) & 0xfffffffffff;
		ADDLO(d2, c);
		c = SHR(d2, 42);
		h2 = LO(d2) & 0x3ffffffffff;
		h0 += c * 5;
		c = (h0 >> 44);
		h0 = h0 & 0xfffffffffff;
		h1 += c;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
}

noinline void lc_poly1305_final(struct lc_poly1305_context *ctx,
				uint8_t mac[LC_POLY1305_TAGSIZE])
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long long h0, h1, h2, c;
	unsigned long long g0, g1, g2;
	unsigned long long t0, t1;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i] = 1;
		for (i = i + 1; i < poly1305_block_size; i++)
			st->buffer[i] = 0;
		st->final = 1;
		lc_poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += c;
	c = (h2 >> 42);
	h2 &= 0x3ffffffffff;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += c;
	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += c;
	c = (h2 >> 42);
	h2 &= 0x3ffffffffff;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5;
	c = (g0 >> 44);
	g0 &= 0xfffffffffff;
	g1 = h1 + c;
	c = (g1 >> 44);
	g1 &= 0xfffffffffff;
	g2 = h2 + c - ((unsigned long long)1 << 42);

	/* select h if h < p, or h + -p if h >= p */
	c = (g2 >> ((sizeof(unsigned long long) * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;

	/* h = (h + pad) */
	t0 = st->pad[0];
	t1 = st->pad[1];

	h0 += ((t0) & 0xfffffffffff);
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)) & 0x3ffffffffff) + c;
	h2 &= 0x3ffffffffff;

	/* mac = h % (2^128) */
	h0 = ((h0) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	U64TO8(&mac[0], h0);
	U64TO8(&mac[8], h1);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
}

#ifdef __cplusplus
}
#endif

#endif /* POLY1305_64_H */
