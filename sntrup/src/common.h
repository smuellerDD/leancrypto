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

#ifndef common_H
#define common_H

#include "alignment.h"
#include "ext_headers_internal.h"

#ifdef LC_HOST_X86_64
#include "ext_headers_x86.h"
typedef __m256i vec256;
#endif

/* ----- arithmetic mod 3 */
typedef int8_t lc_small;

/* F3 is always represented as -1,0,1 */
typedef int16_t Fq;

int sntrup_verify_clen(const uint8_t *, const uint8_t *);
int sntrup_verify_clen_avx2(const uint8_t *x, const uint8_t *y);

#ifdef LC_HOST_X86_64
struct ws_small_encode_avx2 {
	__m256i f0, f1, f2, f3, a0, a1, a2, a3, b0, b2;
};
#endif
struct ws_small_encode_ref {
	uint8_t x;
};
struct ws_small_encode {
	union {
#ifdef LC_HOST_X86_64
		struct ws_small_encode_avx2 avx2;
#endif
		struct ws_small_encode_ref ref;
	} u;
};
void Small_encode(uint8_t *s, const void *v, struct ws_small_encode *ws);
void Small_encode_avx2(uint8_t *s, const void *v, struct ws_small_encode *ws);

#ifdef LC_HOST_X86_64
struct ws_small_decode_avx2 {
	__m256i s0, s1, a0, a1, a2, a3, b0, b1, b2, b3, f0, f1, f2, f3;
};
#endif
struct ws_small_decode_ref {
	uint8_t x;
};
struct ws_small_decode {
	union {
#ifdef LC_HOST_X86_64
		struct ws_small_decode_avx2 avx2;
#endif
		struct ws_small_decode_ref ref;
	} u;
};
void Small_decode(void *v, const uint8_t *s, struct ws_small_decode *ws);
void Small_decode_avx2(void *v, const uint8_t *s, struct ws_small_decode *ws);

#ifdef LC_HOST_X86_64
struct ws_encode_pxfreeze3_avx2 {
	__m256i x, y;
	__m128i x0, x1;
};
#endif
struct ws_encode_pxfreeze3_ref {
	uint8_t x;
};
struct ws_encode_pxfreeze3 {
	union {
#ifdef LC_HOST_X86_64
		struct ws_encode_pxfreeze3_avx2 avx2;
#endif
		struct ws_encode_pxfreeze3_ref ref;
	} u;
};
void sntrup_encode_pxfreeze3(uint8_t *s, const void *v,
			     struct ws_encode_pxfreeze3 *ws);
void sntrup_encode_pxfreeze3_avx2(uint8_t *s, const void *v,
				  struct ws_encode_pxfreeze3 *ws);
void sntrup_decode_pxint32(void *v, const uint8_t *s);
void sntrup_decode_pxint16(void *v, const uint8_t *s);
void sntrup_encode_pxint16(uint8_t *s, const void *v);
void sntrup_core_wforce(uint8_t *out, const uint8_t *in, const uint8_t *kbytes,
			const uint8_t *cbytes);
void sntrup_core_wforce_avx2(uint8_t *out, const uint8_t *in,
			     const uint8_t *kbytes, const uint8_t *cbytes);

#ifdef LC_HOST_X86_64
struct ws_core_scale3_avx2 {
	vec256 save;
	vec256 x;
	vec256 xneg;
};
#endif
struct ws_core_scale3_ref {
	Fq f[p];
};
struct ws_core_scale3 {
	union {
#ifdef LC_HOST_X86_64
		struct ws_core_scale3_avx2 avx2;
#endif
		struct ws_core_scale3_ref ref;
	} u;
};
void sntrup_core_scale3(uint8_t *outbytes, const uint8_t *inbytes,
			const uint8_t *kbytes, const uint8_t *cbytes,
			struct ws_core_scale3 *ws);
void sntrup_core_scale3_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			     const uint8_t *kbytes, const uint8_t *cbytes,
			     struct ws_core_scale3 *ws);

struct ws_core_inv {
	Fq out[p], f[ppad], g[ppad], v[ppad], r[ppad];
	Fq f0, g0;
	Fq scale;
};
void sntrup_core_inv(uint8_t *, const uint8_t *, const uint8_t *,
		     const uint8_t *, struct ws_core_inv *ws);
void sntrup_core_inv_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			  const uint8_t *kbytes, const uint8_t *cbytes,
			  struct ws_core_inv *ws);

#ifdef LC_HOST_X86_64
struct ws_core_inv3_avx2 {
	vec256 F0[numvec];
	vec256 F1[numvec];
	vec256 G0[numvec];
	vec256 G1[numvec];
	vec256 V0[numvec];
	vec256 V1[numvec];
	vec256 R0[numvec];
	vec256 R1[numvec];
	vec256 c0vec, c1vec;
	vec256 swapvec;
	vec256 b0, b1, b2, b3, b4, b5, b6, b7;
	vec256 c0, c1, c2, c3, c4, c5, c6, c7;
	vec256 d0, d2, d4, d6;
	vec256 e0, e2, e4, e6;
	vec256 f0, f4;
	vec256 g0, g4;
	vec256 h;
	lc_small srev[ppadavx2 + (ppadavx2 - p)];
	lc_small si;
	lc_small s0[ppadavx2];
	lc_small s1[ppadavx2];
	lc_small v[ppadavx2];
};
#endif

struct ws_core_inv3_ref {
	bitvec f0, f1, g0, g1, v0, v1, r0, r1;
};

struct ws_core_inv3 {
	union {
#ifdef LC_HOST_X86_64
		struct ws_core_inv3_avx2 avx2;
#endif
		struct ws_core_inv3_ref ref;
	} u;
};
void sntrup_core_inv3(uint8_t *, const uint8_t *, const uint8_t *,
		      const uint8_t *, struct ws_core_inv3 *ws);
void sntrup_core_inv3_avx2(uint8_t *, const uint8_t *, const uint8_t *,
			   const uint8_t *, struct ws_core_inv3 *ws);

#ifdef LC_HOST_X86_64
struct ws_core_mult3_avx2 {
	vec256 f0, f1, f2, f3, f4;
	vec256 g0, g1, g2, g3, g4;
	vec256 d0, d1, d2, d3, d4;
	vec256 d0d1, d0d1d2, d0d1d2d3, d2d3, d1d2d3;
	vec256 e01, e02, e03, e12, e13, e23;
	vec256 h0, h1, h2, h3, h4, h5, h6;
	vec256 twist;
	int16_t fgpad[mult3_numvec / 8][512] __align(32);
	int16_t h_7681[32 * mult3_numvec] __align(32);
	int16_t f[16 * mult3_numvec] __align(32);
	int16_t g[16 * mult3_numvec] __align(32);
	int16_t fg[32 * mult3_numvec] __align(32);
};
#endif

struct ws_core_mult3_ref {
	lc_small f[p];
	lc_small g[p];
	int16_t fg[p + p - 1];
};

struct ws_core_mult3 {
	union {
#ifdef LC_HOST_X86_64
		struct ws_core_mult3_avx2 avx2;
#endif
		struct ws_core_mult3_ref ref;
	} u;
};
void sntrup_core_mult3(uint8_t *outbytes, const uint8_t *inbytes,
		       const uint8_t *kbytes, const uint8_t *cbytes,
		       struct ws_core_mult3 *ws);
void sntrup_core_mult3_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			    const uint8_t *kbytes, const uint8_t *cbytes,
			    struct ws_core_mult3 *ws);

#ifdef LC_HOST_X86_64
struct ws_core_mult_avx2 {
	vec256 f0, f1, f2, f3, f4;
	vec256 g0, g1, g2, g3, g4;
	vec256 d0, d1, d2, d3, d4;
	vec256 d0d1, d0d1d2, d0d1d2d3, d2d3, d1d2d3;
	vec256 e01, e02, e03, e12, e13, e23;
	vec256 h0, h1, h2, h3, h4, h5, h6;
	vec256 twist;
	int16_t fgpad[mult3_numvec / 8][512] __align(32);
	int16_t h_7681[32 * mult3_numvec] __align(32);
	int16_t h_10753[32 * mult3_numvec] __align(32);
	int16_t f[16 * mult3_numvec] __align(32);
	int16_t g[16 * mult3_numvec] __align(32);
	int16_t fg[32 * mult3_numvec] __align(32);
};
#endif

struct ws_core_mult_ref {
	Fq f[p];
	int32_t f32[p];
	int32_t fg[p + p - 1];
	Fq h[p];
};

struct ws_core_mult {
	union {
#ifdef LC_HOST_X86_64
		struct ws_core_mult_avx2 avx2;
#endif
		struct ws_core_mult_ref ref;
	} u;
};
void sntrup_core_mult(uint8_t *outbytes, const uint8_t *inbytes,
		      const uint8_t *kbytes, const uint8_t *cbytes,
		      struct ws_core_mult *ws);
void sntrup_core_mult_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			   const uint8_t *kbytes, const uint8_t *cbytes,
			   struct ws_core_mult *ws);
void sntrup_core_weight(uint8_t *outbytes, const uint8_t *inbytes,
			const uint8_t *kbytes, const uint8_t *cbytes);
void sntrup_core_weight_avx2(uint8_t *outbytes, const uint8_t *inbytes,
			     const uint8_t *kbytes, const uint8_t *cbytes);
int sntrup_verify_clen(const uint8_t *, const uint8_t *);

#endif
