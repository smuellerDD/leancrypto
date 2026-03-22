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
 * This code is derived from OpenSSL crypto/aes/aes_core.c with the following
 * license:
 */
/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "aes_internal.h"
#include "alignment.h"
#include "build_bug_on.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "small_stack_support.h"

typedef union {
	unsigned char b[8];
	uint32_t w[2];
	uint64_t d;
} uni;

struct workspace_subword {
	uint32_t x, y, a1, a2, a3, a4, a5, a6;
};

struct workspace_key_expansion {
	uni prev;
	uint32_t rcon, temp;
	struct workspace_subword subword;
};

struct workspace_mixcolumns {
	uni s1, s;
};

struct workspace_shiftrows {
	uint8_t s[4];
};

struct workspace_sublong {
	uint64_t x, y, a1, a2, a3, a4, a5, a6;
};

struct workspace_cipher {
	union {
		struct workspace_sublong sublong;
		struct workspace_shiftrows shiftrows;
		struct workspace_mixcolumns mixcolumns;
	} u;
};

/*
 * Compute w := (w * x) mod (x^8 + x^4 + x^3 + x^1 + 1)
 * Therefore the name "xtime".
 */
static void XtimeWord(uint32_t *w)
{
	uint32_t a, b;

	a = *w;
	b = a & 0x80808080u;
	a ^= b;
	b -= b >> 7;
	b &= 0x1B1B1B1Bu;
	b ^= a << 1;
	*w = b;
}

static void XtimeLong(uint64_t *w)
{
	uint64_t a, b;

	a = *w;
	b = a & UINT64_C(0x8080808080808080);
	a ^= b;
	b -= b >> 7;
	b &= UINT64_C(0x1B1B1B1B1B1B1B1B);
	b ^= a << 1;
	*w = b;
}

/*
 * This computes w := S * w ^ -1 + c, where c = {01100011}.
 * Instead of using GF(2^8) mod (x^8+x^4+x^3+x+1} we do the inversion
 * in GF(GF(GF(2^2)^2)^2) mod (X^2+X+8)
 * and GF(GF(2^2)^2) mod (X^2+X+2)
 * and GF(2^2) mod (X^2+X+1)
 * The first part of the algorithm below transfers the coordinates
 * {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80} =>
 * {1,Y,Y^2,Y^3,Y^4,Y^5,Y^6,Y^7} with Y=0x41:
 * {0x01,0x41,0x66,0x6c,0x56,0x9a,0x58,0xc4}
 * The last part undoes the coordinate transfer and the final affine
 * transformation S:
 * b[i] = b[i] + b[(i+4)%8] + b[(i+5)%8] + b[(i+6)%8] + b[(i+7)%8] + c[i]
 * in one step.
 * The multiplication in GF(2^2^2^2) is done in ordinary coords:
 * A = (a0*1 + a1*x^4)
 * B = (b0*1 + b1*x^4)
 * AB = ((a0*b0 + 8*a1*b1)*1 + (a1*b0 + (a0+a1)*b1)*x^4)
 * When A = (a0,a1) is given we want to solve AB = 1:
 * (a) 1 = a0*b0 + 8*a1*b1
 * (b) 0 = a1*b0 + (a0+a1)*b1
 * => multiply (a) by a1 and (b) by a0
 * (c) a1 = a1*a0*b0 + (8*a1*a1)*b1
 * (d) 0 = a1*a0*b0 + (a0*a0+a1*a0)*b1
 * => add (c) + (d)
 * (e) a1 = (a0*a0 + a1*a0 + 8*a1*a1)*b1
 * => therefore
 * b1 = (a0*a0 + a1*a0 + 8*a1*a1)^-1 * a1
 * => and adding (a1*b0) to (b) we get
 * (f) a1*b0 = (a0+a1)*b1
 * => therefore
 * b0 = (a0*a0 + a1*a0 + 8*a1*a1)^-1 * (a0+a1)
 * Note this formula also works for the case
 * (a0+a1)*a0 + 8*a1*a1 = 0
 * if the inverse element for 0^-1 is mapped to 0.
 * Repeat the same for GF(2^2^2) and GF(2^2).
 * We get the following algorithm:
 * inv8(a0,a1):
 *   x0 = a0^a1
 *   [y0,y1] = mul4([x0,a1],[a0,a1]); (*)
 *   y1 = mul4(8,y1);
 *   t = inv4(y0^y1);
 *   [b0,b1] = mul4([x0,a1],[t,t]); (*)
 *   return [b0,b1];
 * The non-linear multiplies (*) can be done in parallel at no extra cost.
 */
static void SubWord(uint32_t *w, struct workspace_subword *ws)
{
	ws->x = *w;
	ws->y = ((ws->x & 0xFEFEFEFEu) >> 1) | ((ws->x & 0x01010101u) << 7);
	ws->x &= 0xDDDDDDDDu;
	ws->x ^= ws->y & 0x57575757u;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x1C1C1C1Cu;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x4A4A4A4Au;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x42424242u;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x64646464u;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0xE0E0E0E0u;
	ws->a1 = ws->x;
	ws->a1 ^= (ws->x & 0xF0F0F0F0u) >> 4;
	ws->a2 = ((ws->x & 0xCCCCCCCCu) >> 2) | ((ws->x & 0x33333333u) << 2);
	ws->a3 = ws->x & ws->a1;
	ws->a3 ^= (ws->a3 & 0xAAAAAAAAu) >> 1;
	ws->a3 ^= (((ws->x << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->x)) &
		  0xAAAAAAAAu;
	ws->a4 = ws->a2 & ws->a1;
	ws->a4 ^= (ws->a4 & 0xAAAAAAAAu) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->a2)) &
		  0xAAAAAAAAu;
	ws->a5 = (ws->a3 & 0xCCCCCCCCu) >> 2;
	ws->a3 ^= ((ws->a4 << 2) ^ ws->a4) & 0xCCCCCCCCu;
	ws->a4 = ws->a5 & 0x22222222u;
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & 0x22222222u;
	ws->a3 ^= ws->a4;
	ws->a5 = ws->a3 & 0xA0A0A0A0u;
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a3 << 1) & 0xA0A0A0A0u;
	ws->a4 = ws->a5 & 0xC0C0C0C0u;
	ws->a6 = ws->a4 >> 2;
	ws->a4 ^= (ws->a5 << 2) & 0xC0C0C0C0u;
	ws->a5 = ws->a6 & 0x20202020u;
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a6 << 1) & 0x20202020u;
	ws->a4 |= ws->a5;
	ws->a3 ^= ws->a4 >> 4;
	ws->a3 &= 0x0F0F0F0Fu;
	ws->a2 = ws->a3;
	ws->a2 ^= (ws->a3 & 0x0C0C0C0Cu) >> 2;
	ws->a4 = ws->a3 & ws->a2;
	ws->a4 ^= (ws->a4 & 0x0A0A0A0Au) >> 1;
	ws->a4 ^= (((ws->a3 << 1) & ws->a2) ^ ((ws->a2 << 1) & ws->a3)) &
		  0x0A0A0A0Au;
	ws->a5 = ws->a4 & 0x08080808u;
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a4 << 1) & 0x08080808u;
	ws->a4 ^= ws->a5 >> 2;
	ws->a4 &= 0x03030303u;
	ws->a4 ^= (ws->a4 & 0x02020202u) >> 1;
	ws->a4 |= ws->a4 << 2;
	ws->a3 = ws->a2 & ws->a4;
	ws->a3 ^= (ws->a3 & 0x0A0A0A0Au) >> 1;
	ws->a3 ^= (((ws->a2 << 1) & ws->a4) ^ ((ws->a4 << 1) & ws->a2)) &
		  0x0A0A0A0Au;
	ws->a3 |= ws->a3 << 4;
	ws->a2 = ((ws->a1 & 0xCCCCCCCCu) >> 2) | ((ws->a1 & 0x33333333u) << 2);
	ws->x = ws->a1 & ws->a3;
	ws->x ^= (ws->x & 0xAAAAAAAAu) >> 1;
	ws->x ^= (((ws->a1 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a1)) &
		 0xAAAAAAAAu;
	ws->a4 = ws->a2 & ws->a3;
	ws->a4 ^= (ws->a4 & 0xAAAAAAAAu) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a2)) &
		  0xAAAAAAAAu;
	ws->a5 = (ws->x & 0xCCCCCCCCu) >> 2;
	ws->x ^= ((ws->a4 << 2) ^ ws->a4) & 0xCCCCCCCCu;
	ws->a4 = ws->a5 & 0x22222222u;
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & 0x22222222u;
	ws->x ^= ws->a4;
	ws->y = ((ws->x & 0xFEFEFEFEu) >> 1) | ((ws->x & 0x01010101u) << 7);
	ws->x &= 0x39393939u;
	ws->x ^= ws->y & 0x3F3F3F3Fu;
	ws->y = ((ws->y & 0xFCFCFCFCu) >> 2) | ((ws->y & 0x03030303u) << 6);
	ws->x ^= ws->y & 0x97979797u;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x9B9B9B9Bu;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x3C3C3C3Cu;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0xDDDDDDDDu;
	ws->y = ((ws->y & 0xFEFEFEFEu) >> 1) | ((ws->y & 0x01010101u) << 7);
	ws->x ^= ws->y & 0x72727272u;
	ws->x ^= 0x63636363u;
	*w = ws->x;
}

static void SubLong(uint64_t *w, struct workspace_sublong *ws)
{
	ws->x = *w;
	ws->y = ((ws->x & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->x & UINT64_C(0x0101010101010101)) << 7);
	ws->x &= UINT64_C(0xDDDDDDDDDDDDDDDD);
	ws->x ^= ws->y & UINT64_C(0x5757575757575757);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x1C1C1C1C1C1C1C1C);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x4A4A4A4A4A4A4A4A);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x4242424242424242);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x6464646464646464);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xE0E0E0E0E0E0E0E0);
	ws->a1 = ws->x;
	ws->a1 ^= (ws->x & UINT64_C(0xF0F0F0F0F0F0F0F0)) >> 4;
	ws->a2 = ((ws->x & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2) |
		 ((ws->x & UINT64_C(0x3333333333333333)) << 2);
	ws->a3 = ws->x & ws->a1;
	ws->a3 ^= (ws->a3 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a3 ^= (((ws->x << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->x)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a4 = ws->a2 & ws->a1;
	ws->a4 ^= (ws->a4 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->a2)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a5 = (ws->a3 & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2;
	ws->a3 ^= ((ws->a4 << 2) ^ ws->a4) & UINT64_C(0xCCCCCCCCCCCCCCCC);
	ws->a4 = ws->a5 & UINT64_C(0x2222222222222222);
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & UINT64_C(0x2222222222222222);
	ws->a3 ^= ws->a4;
	ws->a5 = ws->a3 & UINT64_C(0xA0A0A0A0A0A0A0A0);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a3 << 1) & UINT64_C(0xA0A0A0A0A0A0A0A0);
	ws->a4 = ws->a5 & UINT64_C(0xC0C0C0C0C0C0C0C0);
	ws->a6 = ws->a4 >> 2;
	ws->a4 ^= (ws->a5 << 2) & UINT64_C(0xC0C0C0C0C0C0C0C0);
	ws->a5 = ws->a6 & UINT64_C(0x2020202020202020);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a6 << 1) & UINT64_C(0x2020202020202020);
	ws->a4 |= ws->a5;
	ws->a3 ^= ws->a4 >> 4;
	ws->a3 &= UINT64_C(0x0F0F0F0F0F0F0F0F);
	ws->a2 = ws->a3;
	ws->a2 ^= (ws->a3 & UINT64_C(0x0C0C0C0C0C0C0C0C)) >> 2;
	ws->a4 = ws->a3 & ws->a2;
	ws->a4 ^= (ws->a4 & UINT64_C(0x0A0A0A0A0A0A0A0A)) >> 1;
	ws->a4 ^= (((ws->a3 << 1) & ws->a2) ^ ((ws->a2 << 1) & ws->a3)) &
		  UINT64_C(0x0A0A0A0A0A0A0A0A);
	ws->a5 = ws->a4 & UINT64_C(0x0808080808080808);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a4 << 1) & UINT64_C(0x0808080808080808);
	ws->a4 ^= ws->a5 >> 2;
	ws->a4 &= UINT64_C(0x0303030303030303);
	ws->a4 ^= (ws->a4 & UINT64_C(0x0202020202020202)) >> 1;
	ws->a4 |= ws->a4 << 2;
	ws->a3 = ws->a2 & ws->a4;
	ws->a3 ^= (ws->a3 & UINT64_C(0x0A0A0A0A0A0A0A0A)) >> 1;
	ws->a3 ^= (((ws->a2 << 1) & ws->a4) ^ ((ws->a4 << 1) & ws->a2)) &
		  UINT64_C(0x0A0A0A0A0A0A0A0A);
	ws->a3 |= ws->a3 << 4;
	ws->a2 = ((ws->a1 & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2) |
		 ((ws->a1 & UINT64_C(0x3333333333333333)) << 2);
	ws->x = ws->a1 & ws->a3;
	ws->x ^= (ws->x & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->x ^= (((ws->a1 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a1)) &
		 UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a4 = ws->a2 & ws->a3;
	ws->a4 ^= (ws->a4 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a2)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a5 = (ws->x & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2;
	ws->x ^= ((ws->a4 << 2) ^ ws->a4) & UINT64_C(0xCCCCCCCCCCCCCCCC);
	ws->a4 = ws->a5 & UINT64_C(0x2222222222222222);
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & UINT64_C(0x2222222222222222);
	ws->x ^= ws->a4;
	ws->y = ((ws->x & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->x & UINT64_C(0x0101010101010101)) << 7);
	ws->x &= UINT64_C(0x3939393939393939);
	ws->x ^= ws->y & UINT64_C(0x3F3F3F3F3F3F3F3F);
	ws->y = ((ws->y & UINT64_C(0xFCFCFCFCFCFCFCFC)) >> 2) |
		((ws->y & UINT64_C(0x0303030303030303)) << 6);
	ws->x ^= ws->y & UINT64_C(0x9797979797979797);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x9B9B9B9B9B9B9B9B);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x3C3C3C3C3C3C3C3C);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xDDDDDDDDDDDDDDDD);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x7272727272727272);
	ws->x ^= UINT64_C(0x6363636363636363);
	*w = ws->x;
}

/*
 * This computes w := (S^-1 * (w + c))^-1
 */
static void InvSubLong(uint64_t *w, struct workspace_sublong *ws)
{
	ws->x = *w;
	ws->x ^= UINT64_C(0x6363636363636363);
	ws->y = ((ws->x & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->x & UINT64_C(0x0101010101010101)) << 7);
	ws->x &= UINT64_C(0xFDFDFDFDFDFDFDFD);
	ws->x ^= ws->y & UINT64_C(0x5E5E5E5E5E5E5E5E);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xF3F3F3F3F3F3F3F3);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xF5F5F5F5F5F5F5F5);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x7878787878787878);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x7777777777777777);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x1515151515151515);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xA5A5A5A5A5A5A5A5);
	ws->a1 = ws->x;
	ws->a1 ^= (ws->x & UINT64_C(0xF0F0F0F0F0F0F0F0)) >> 4;
	ws->a2 = ((ws->x & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2) |
		 ((ws->x & UINT64_C(0x3333333333333333)) << 2);
	ws->a3 = ws->x & ws->a1;
	ws->a3 ^= (ws->a3 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a3 ^= (((ws->x << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->x)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a4 = ws->a2 & ws->a1;
	ws->a4 ^= (ws->a4 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a1) ^ ((ws->a1 << 1) & ws->a2)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a5 = (ws->a3 & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2;
	ws->a3 ^= ((ws->a4 << 2) ^ ws->a4) & UINT64_C(0xCCCCCCCCCCCCCCCC);
	ws->a4 = ws->a5 & UINT64_C(0x2222222222222222);
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & UINT64_C(0x2222222222222222);
	ws->a3 ^= ws->a4;
	ws->a5 = ws->a3 & UINT64_C(0xA0A0A0A0A0A0A0A0);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a3 << 1) & UINT64_C(0xA0A0A0A0A0A0A0A0);
	ws->a4 = ws->a5 & UINT64_C(0xC0C0C0C0C0C0C0C0);
	ws->a6 = ws->a4 >> 2;
	ws->a4 ^= (ws->a5 << 2) & UINT64_C(0xC0C0C0C0C0C0C0C0);
	ws->a5 = ws->a6 & UINT64_C(0x2020202020202020);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a6 << 1) & UINT64_C(0x2020202020202020);
	ws->a4 |= ws->a5;
	ws->a3 ^= ws->a4 >> 4;
	ws->a3 &= UINT64_C(0x0F0F0F0F0F0F0F0F);
	ws->a2 = ws->a3;
	ws->a2 ^= (ws->a3 & UINT64_C(0x0C0C0C0C0C0C0C0C)) >> 2;
	ws->a4 = ws->a3 & ws->a2;
	ws->a4 ^= (ws->a4 & UINT64_C(0x0A0A0A0A0A0A0A0A)) >> 1;
	ws->a4 ^= (((ws->a3 << 1) & ws->a2) ^ ((ws->a2 << 1) & ws->a3)) &
		  UINT64_C(0x0A0A0A0A0A0A0A0A);
	ws->a5 = ws->a4 & UINT64_C(0x0808080808080808);
	ws->a5 |= ws->a5 >> 1;
	ws->a5 ^= (ws->a4 << 1) & UINT64_C(0x0808080808080808);
	ws->a4 ^= ws->a5 >> 2;
	ws->a4 &= UINT64_C(0x0303030303030303);
	ws->a4 ^= (ws->a4 & UINT64_C(0x0202020202020202)) >> 1;
	ws->a4 |= ws->a4 << 2;
	ws->a3 = ws->a2 & ws->a4;
	ws->a3 ^= (ws->a3 & UINT64_C(0x0A0A0A0A0A0A0A0A)) >> 1;
	ws->a3 ^= (((ws->a2 << 1) & ws->a4) ^ ((ws->a4 << 1) & ws->a2)) &
		  UINT64_C(0x0A0A0A0A0A0A0A0A);
	ws->a3 |= ws->a3 << 4;
	ws->a2 = ((ws->a1 & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2) |
		 ((ws->a1 & UINT64_C(0x3333333333333333)) << 2);
	ws->x = ws->a1 & ws->a3;
	ws->x ^= (ws->x & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->x ^= (((ws->a1 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a1)) &
		 UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a4 = ws->a2 & ws->a3;
	ws->a4 ^= (ws->a4 & UINT64_C(0xAAAAAAAAAAAAAAAA)) >> 1;
	ws->a4 ^= (((ws->a2 << 1) & ws->a3) ^ ((ws->a3 << 1) & ws->a2)) &
		  UINT64_C(0xAAAAAAAAAAAAAAAA);
	ws->a5 = (ws->x & UINT64_C(0xCCCCCCCCCCCCCCCC)) >> 2;
	ws->x ^= ((ws->a4 << 2) ^ ws->a4) & UINT64_C(0xCCCCCCCCCCCCCCCC);
	ws->a4 = ws->a5 & UINT64_C(0x2222222222222222);
	ws->a4 |= ws->a4 >> 1;
	ws->a4 ^= (ws->a5 << 1) & UINT64_C(0x2222222222222222);
	ws->x ^= ws->a4;
	ws->y = ((ws->x & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->x & UINT64_C(0x0101010101010101)) << 7);
	ws->x &= UINT64_C(0xB5B5B5B5B5B5B5B5);
	ws->x ^= ws->y & UINT64_C(0x4040404040404040);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x8080808080808080);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x1616161616161616);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xEBEBEBEBEBEBEBEB);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x9797979797979797);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0xFBFBFBFBFBFBFBFB);
	ws->y = ((ws->y & UINT64_C(0xFEFEFEFEFEFEFEFE)) >> 1) |
		((ws->y & UINT64_C(0x0101010101010101)) << 7);
	ws->x ^= ws->y & UINT64_C(0x7D7D7D7D7D7D7D7D);
	*w = ws->x;
}

static void ShiftRows(uint64_t *state, struct workspace_shiftrows *ws)
{
	uint8_t *s0;
	int r;

	s0 = (uint8_t *)state;
	for (r = 0; r < 4; r++) {
		ws->s[0] = s0[0 * 4 + r];
		ws->s[1] = s0[1 * 4 + r];
		ws->s[2] = s0[2 * 4 + r];
		ws->s[3] = s0[3 * 4 + r];
		s0[0 * 4 + r] = ws->s[(r + 0) % 4];
		s0[1 * 4 + r] = ws->s[(r + 1) % 4];
		s0[2 * 4 + r] = ws->s[(r + 2) % 4];
		s0[3 * 4 + r] = ws->s[(r + 3) % 4];
	}
}

static void InvShiftRows(uint64_t *state, struct workspace_shiftrows *ws)
{
	uint8_t *s0;
	int r;

	s0 = (uint8_t *)state;
	for (r = 0; r < 4; r++) {
		ws->s[0] = s0[0 * 4 + r];
		ws->s[1] = s0[1 * 4 + r];
		ws->s[2] = s0[2 * 4 + r];
		ws->s[3] = s0[3 * 4 + r];
		s0[0 * 4 + r] = ws->s[(4 - r) % 4];
		s0[1 * 4 + r] = ws->s[(5 - r) % 4];
		s0[2 * 4 + r] = ws->s[(6 - r) % 4];
		s0[3 * 4 + r] = ws->s[(7 - r) % 4];
	}
}

static void MixColumns(uint64_t *state, struct workspace_mixcolumns *ws)
{
	int c;

	for (c = 0; c < 2; c++) {
		ws->s1.d = state[c];
		ws->s.d = ws->s1.d;
		ws->s.d ^= ((ws->s.d & UINT64_C(0xFFFF0000FFFF0000)) >> 16) |
			   ((ws->s.d & UINT64_C(0x0000FFFF0000FFFF)) << 16);
		ws->s.d ^= ((ws->s.d & UINT64_C(0xFF00FF00FF00FF00)) >> 8) |
			   ((ws->s.d & UINT64_C(0x00FF00FF00FF00FF)) << 8);
		ws->s.d ^= ws->s1.d;
		XtimeLong(&ws->s1.d);
		ws->s.d ^= ws->s1.d;
		ws->s.b[0] ^= ws->s1.b[1];
		ws->s.b[1] ^= ws->s1.b[2];
		ws->s.b[2] ^= ws->s1.b[3];
		ws->s.b[3] ^= ws->s1.b[0];
		ws->s.b[4] ^= ws->s1.b[5];
		ws->s.b[5] ^= ws->s1.b[6];
		ws->s.b[6] ^= ws->s1.b[7];
		ws->s.b[7] ^= ws->s1.b[4];
		state[c] = ws->s.d;
	}
}

static void InvMixColumns(uint64_t *state, struct workspace_mixcolumns *ws)
{
	int c;

	for (c = 0; c < 2; c++) {
		ws->s1.d = state[c];
		ws->s.d = ws->s1.d;
		ws->s.d ^= ((ws->s.d & UINT64_C(0xFFFF0000FFFF0000)) >> 16) |
			   ((ws->s.d & UINT64_C(0x0000FFFF0000FFFF)) << 16);
		ws->s.d ^= ((ws->s.d & UINT64_C(0xFF00FF00FF00FF00)) >> 8) |
			   ((ws->s.d & UINT64_C(0x00FF00FF00FF00FF)) << 8);
		ws->s.d ^= ws->s1.d;
		XtimeLong(&ws->s1.d);
		ws->s.d ^= ws->s1.d;
		ws->s.b[0] ^= ws->s1.b[1];
		ws->s.b[1] ^= ws->s1.b[2];
		ws->s.b[2] ^= ws->s1.b[3];
		ws->s.b[3] ^= ws->s1.b[0];
		ws->s.b[4] ^= ws->s1.b[5];
		ws->s.b[5] ^= ws->s1.b[6];
		ws->s.b[6] ^= ws->s1.b[7];
		ws->s.b[7] ^= ws->s1.b[4];
		XtimeLong(&ws->s1.d);
		ws->s1.d ^= ((ws->s1.d & UINT64_C(0xFFFF0000FFFF0000)) >> 16) |
			    ((ws->s1.d & UINT64_C(0x0000FFFF0000FFFF)) << 16);
		ws->s.d ^= ws->s1.d;
		XtimeLong(&ws->s1.d);
		ws->s1.d ^= ((ws->s1.d & UINT64_C(0xFF00FF00FF00FF00)) >> 8) |
			    ((ws->s1.d & UINT64_C(0x00FF00FF00FF00FF)) << 8);
		ws->s.d ^= ws->s1.d;
		state[c] = ws->s.d;
	}
}

static void AddRoundKey(uint64_t *state, const uint64_t *w)
{
	state[0] ^= w[0];
	state[1] ^= w[1];
}

static void aes_cipher(uint64_t *state, const uint64_t *w, unsigned int nr,
		       struct workspace_cipher *ws)
{
	unsigned int i;

	AddRoundKey(state, w);

	for (i = 1; i < nr; i++) {
		SubLong(&state[0], &ws->u.sublong);
		SubLong(&state[1], &ws->u.sublong);
		ShiftRows(state, &ws->u.shiftrows);
		MixColumns(state, &ws->u.mixcolumns);
		AddRoundKey(state, w + i * 2);
	}

	SubLong(&state[0], &ws->u.sublong);
	SubLong(&state[1], &ws->u.sublong);
	ShiftRows(state, &ws->u.shiftrows);
	AddRoundKey(state, w + nr * 2);
}

static void aes_inv_cipher(uint64_t *state, const uint64_t *w, unsigned int nr,
			   struct workspace_cipher *ws)

{
	unsigned int i;

	AddRoundKey(state, w + nr * 2);

	for (i = nr - 1; i > 0; i--) {
		InvShiftRows(state, &ws->u.shiftrows);
		InvSubLong(&state[0], &ws->u.sublong);
		InvSubLong(&state[1], &ws->u.sublong);
		AddRoundKey(state, w + i * 2);
		InvMixColumns(state, &ws->u.mixcolumns);
	}

	InvShiftRows(state, &ws->u.shiftrows);
	InvSubLong(&state[0], &ws->u.sublong);
	InvSubLong(&state[1], &ws->u.sublong);
	AddRoundKey(state, w);
}

static void RotWord(uint32_t *x)
{
	unsigned char *w0;
	unsigned char tmp;

	w0 = (unsigned char *)x;
	tmp = w0[0];
	w0[0] = w0[1];
	w0[1] = w0[2];
	w0[2] = w0[3];
	w0[3] = tmp;
}

static void aes_key_expansion(uint64_t *w, const uint8_t *key, const uint8_t nr,
			      const uint8_t nk,
			      struct workspace_key_expansion *ws)
{
	uint8_t i, n;

	memcpy(w, key, nk * 4);
	memcpy(&ws->rcon, "\1\0\0\0", 4);
	n = nk >> 1;
	ws->prev.d = w[n - 1];
	for (i = n; i < (nr + 1) * 2; i++) {
		ws->temp = ws->prev.w[1];
		if (i % n == 0) {
			RotWord(&ws->temp);
			SubWord(&ws->temp, &ws->subword);
			ws->temp ^= ws->rcon;
			XtimeWord(&ws->rcon);
		} else if (nk > 6 && i % n == 2) {
			SubWord(&ws->temp, &ws->subword);
		}
		ws->prev.d = w[i - n];
		ws->prev.w[0] ^= ws->temp;
		ws->prev.w[1] ^= ws->prev.w[0];
		w[i] = ws->prev.d;
	}
}

/* Expand the cipher key into the encryption key schedule. */
void aes_setkey_ct(struct aes_block_ctx *block_ctx, const uint8_t *key)
{
	//LC_DECLARE_MEM(ws, struct workspace_key_expansion, 8);
	struct workspace_key_expansion ws;

	aes_key_expansion(block_ctx->round_key, key, block_ctx->nr,
			  block_ctx->nk, &ws);

	//LC_RELEASE_MEM(ws);
	lc_memset_secure(&ws, 0, sizeof(ws));
}

/* Encrypt a single block */
void aes_encrypt_ct(state_t *state, const struct aes_block_ctx *block_ctx)
{
	//LC_DECLARE_MEM(ws, struct workspace_cipher, 8);
	struct workspace_cipher ws;

	if (aligned((uint8_t *)state, sizeof(uint64_t) - 1)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		aes_cipher((uint64_t *)state, block_ctx->round_key,
			   block_ctx->nr, &ws);
#pragma GCC diagnostic pop
	} else {
		uint64_t tmp[2];

		BUILD_BUG_ON(sizeof(tmp) != sizeof(*state));
		memcpy(tmp, state, sizeof(tmp));
		aes_cipher(tmp, block_ctx->round_key, block_ctx->nr, &ws);
		lc_memset_secure(tmp, 0, sizeof(tmp));
	}

	//LC_RELEASE_MEM(ws);
	lc_memset_secure(&ws, 0, sizeof(ws));
}

/* Decrypt a single block */
void aes_decrypt_ct(state_t *state, const struct aes_block_ctx *block_ctx)
{
	//LC_DECLARE_MEM(ws, struct workspace_cipher, 8);
	struct workspace_cipher ws;

	if (aligned((uint8_t *)state, sizeof(uint64_t) - 1)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		aes_inv_cipher((uint64_t *)state, block_ctx->round_key,
			       block_ctx->nr, &ws);
#pragma GCC diagnostic pop
	} else {
		uint64_t tmp[2];

		BUILD_BUG_ON(sizeof(tmp) != sizeof(*state));
		memcpy(tmp, state, sizeof(tmp));
		aes_inv_cipher(tmp, block_ctx->round_key, block_ctx->nr, &ws);
		lc_memset_secure(tmp, 0, sizeof(tmp));
	}

	//LC_RELEASE_MEM(ws);
	lc_memset_secure(&ws, 0, sizeof(ws));
}
