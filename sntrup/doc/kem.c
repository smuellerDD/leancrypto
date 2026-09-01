#include "params.h"

#include "crypto_hash_sha512.h"
#include "crypto_sort_uint32.h"
#include "crypto_declassify.h"

#include "crypto_int8.h"
#include "crypto_int16.h"
#include "crypto_int32.h"
#include "crypto_uint16.h"
#include "crypto_uint32.h"
#define int8 crypto_int8
#define int16 crypto_int16
#define int32 crypto_int32
#define uint16 crypto_uint16
#define uint32 crypto_uint32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/******************************************************************************/
#define Nb 4 // number of words in each block
struct aes_block_ctx {
	/*
	 * AES-256: 240 bytes
	 * AES-192: 208 bytes
	 * AES-128: 176 bytes
	 */
	uint64_t round_key[Nb / 2 * (14 + 1)];
	//uint32_t round_key[Nb * (14 + 1)];

	uint8_t nk;
	uint8_t nr;
};

typedef union {
	unsigned char b[8];
	uint32_t x[2];
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
static void XtimeWord(uint32_t *x)
{
	uint32_t a, b;

	a = *x;
	b = a & 0x80808080u;
	a ^= b;
	b -= b >> 7;
	b &= 0x1B1B1B1Bu;
	b ^= a << 1;
	*x = b;
}

static void XtimeLong(uint64_t *x)
{
	uint64_t a, b;

	a = *x;
	b = a & UINT64_C(0x8080808080808080);
	a ^= b;
	b -= b >> 7;
	b &= UINT64_C(0x1B1B1B1B1B1B1B1B);
	b ^= a << 1;
	*x = b;
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
static void SubWord(uint32_t *x, struct workspace_subword *ws)
{
	ws->x = *x;
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
	*x = ws->x;
}

static void SubLong(uint64_t *x, struct workspace_sublong *ws)
{
	ws->x = *x;
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
	*x = ws->x;
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

static void AddRoundKey(uint64_t *state, const uint64_t *x)
{
	state[0] ^= x[0];
	state[1] ^= x[1];
}

static void aes_cipher(uint64_t *state, const uint64_t *x, unsigned int nr,
		       struct workspace_cipher *ws)
{
	unsigned int i;

	AddRoundKey(state, x);

	for (i = 1; i < nr; i++) {
		SubLong(&state[0], &ws->u.sublong);
		SubLong(&state[1], &ws->u.sublong);
		ShiftRows(state, &ws->u.shiftrows);
		MixColumns(state, &ws->u.mixcolumns);
		AddRoundKey(state, x + i * 2);
	}

	SubLong(&state[0], &ws->u.sublong);
	SubLong(&state[1], &ws->u.sublong);
	ShiftRows(state, &ws->u.shiftrows);
	AddRoundKey(state, x + nr * 2);
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

static void aes_key_expansion(uint64_t *x, const uint8_t *key, const uint8_t nr,
			      const uint8_t nk,
			      struct workspace_key_expansion *ws)
{
	uint8_t i, n;

	memcpy(x, key, nk * 4);
	memcpy(&ws->rcon, "\1\0\0\0", 4);
	n = nk >> 1;
	ws->prev.d = x[n - 1];
	for (i = n; i < (nr + 1) * 2; i++) {
		ws->temp = ws->prev.x[1];
		if (i % n == 0) {
			RotWord(&ws->temp);
			SubWord(&ws->temp, &ws->subword);
			ws->temp ^= ws->rcon;
			XtimeWord(&ws->rcon);
		} else if (nk > 6 && i % n == 2) {
			SubWord(&ws->temp, &ws->subword);
		}
		ws->prev.d = x[i - n];
		ws->prev.x[0] ^= ws->temp;
		ws->prev.x[1] ^= ws->prev.x[0];
		x[i] = ws->prev.d;
	}
}

/* Expand the cipher key into the encryption key schedule. */
static void aes_setkey_ct(struct aes_block_ctx *block_ctx, const uint8_t *key)
{
	//LC_DECLARE_MEM(ws, struct workspace_key_expansion, 8);
	struct workspace_key_expansion ws;

	aes_key_expansion(block_ctx->round_key, key, block_ctx->nr,
			  block_ctx->nk, &ws);

	//LC_RELEASE_MEM(ws);
}

/* Encrypt a single block */
static void aes_encrypt_ct(void *state, const struct aes_block_ctx *block_ctx)
{
	//LC_DECLARE_MEM(ws, struct workspace_cipher, 8);
	struct workspace_cipher ws;

	uint64_t tmp[2];

	memcpy(tmp, state, sizeof(tmp));
	aes_cipher(tmp, block_ctx->round_key, block_ctx->nr, &ws);
	memcpy(state, tmp, sizeof(tmp));

	//LC_RELEASE_MEM(ws);
}

#define AES_BLOCK_SIZE 16
static void aes256_encrypt(const uint8_t *Key, uint8_t *tmp, const uint8_t *V)
{
	struct aes_block_ctx block = {
		.nk = 8,
		.nr = 14,
	};

	aes_setkey_ct(&block, Key);

	memcpy(tmp, V, AES_BLOCK_SIZE);
	aes_encrypt_ct(tmp, &block);
}

#include <string.h>

#define AES256_KEY_SIZE (32)
#define DRBG_CTR_AES256_SEED_SIZE (48)

struct drbg_ctr_aes256_ctx {
	uint8_t K[AES256_KEY_SIZE];
	uint8_t V[AES_BLOCK_SIZE];
};

static void memxor(uint8_t *dst, const uint8_t *src, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		dst[i] ^= src[i];
}

static void increment(uint8_t *V)
{
	size_t i;

	for (i = AES_BLOCK_SIZE - 1; i > 0; i--) {
		if (V[i] == 0xFF)
			V[i] = 0;
		else {
			V[i]++;
			break;
		}
	}
}

static void drbg_ctr_aes256_update(uint8_t *Key, uint8_t *V,
				   const uint8_t *provided_data)
{
	uint8_t tmp[DRBG_CTR_AES256_SEED_SIZE];

	increment(V);
	aes256_encrypt(Key, tmp, V);

	increment(V);
	aes256_encrypt(Key, tmp + AES_BLOCK_SIZE, V);

	increment(V);
	aes256_encrypt(Key, tmp + 2 * AES_BLOCK_SIZE, V);

	if (provided_data)
		memxor(tmp, provided_data, 48);

	memcpy(Key, tmp, AES256_KEY_SIZE);
	memcpy(V, tmp + AES256_KEY_SIZE, AES_BLOCK_SIZE);
}

static const uint8_t seed[] = {
	0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE,
	0x04, 0xEF, 0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79,
	0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC, 0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26,
	0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1
};
static struct drbg_ctr_aes256_ctx mystate;
static int drbg_seeded = 0;

/* Initialize using DRBG_CTR_AES256_SEED_SIZE bytes of
   SEED_MATERIAL.  */
static void drbg_ctr_aes256_init(const uint8_t *seed_material)
{
	struct drbg_ctr_aes256_ctx *ctx = &mystate;
	memset(ctx->K, 0, AES256_KEY_SIZE);
	memset(ctx->V, 0, AES_BLOCK_SIZE);

	drbg_ctr_aes256_update(ctx->K, ctx->V, seed_material);
}

/* Output N bytes of random data into DST.  */
static void drbg_ctr_aes256_random(uint8_t *dst, size_t n)
{
	struct drbg_ctr_aes256_ctx *ctx = &mystate;

	if (!drbg_seeded) {
		drbg_seeded = 1;
		drbg_ctr_aes256_init(seed);
	}

	while (n >= AES_BLOCK_SIZE) {
		increment(ctx->V);
		aes256_encrypt(ctx->K, dst, ctx->V);
		dst += AES_BLOCK_SIZE;
		n -= AES_BLOCK_SIZE;
	}

	if (n > 0) {
		uint8_t block[AES_BLOCK_SIZE];

		increment(ctx->V);
		aes256_encrypt(ctx->K, block, ctx->V);
		memcpy(dst, block, n);
	}

	drbg_ctr_aes256_update(ctx->K, ctx->V, NULL);
}

/******************************************************************************/
/* ----- arithmetic mod 3 */

typedef int8 small;
/* F3 is always represented as -1,0,1 */

/* ----- arithmetic mod q */

typedef int16 Fq;
/* always represented as -(q-1)/2...(q-1)/2 */

/* ----- small polynomials */

/* R3_fromR(R_fromRq(r)) */
static void R3_fromRq(small *out, const Fq *r)
{
	crypto_encode_pxfreeze3((unsigned char *)out, (unsigned char *)r);
}

/* h = f*g in the ring R3 */
static void R3_mult(small *h, const small *f, const small *g)
{
	crypto_core_mult3((unsigned char *)h, (const unsigned char *)f,
			  (const unsigned char *)g, 0);
}

/* ----- polynomials mod q */

/* h = h*g in the ring Rq */
static void Rq_mult_small(Fq *h, const small *g)
{
	crypto_encode_pxint16((unsigned char *)h, h);
	crypto_core_mult((unsigned char *)h, (const unsigned char *)h,
			 (const unsigned char *)g, 0);
	crypto_decode_pxint16(h, (const unsigned char *)h);
}

/* h = 3f in Rq */
static void Rq_mult3(Fq *h, const Fq *f)
{
	crypto_encode_pxint16((unsigned char *)h, f);
	crypto_core_scale3((unsigned char *)h, (const unsigned char *)h, 0, 0);
	crypto_decode_pxint16(h, (const unsigned char *)h);
}

/* out = 1/(3*in) in Rq */
/* caller must have 2p+1 bytes free in out, not just 2p */
static void Rq_recip3(Fq *out, const small *in)
{
	crypto_core_inv((unsigned char *)out, (const unsigned char *)in, 0, 0);
	/* could check byte 2*p for failure; but, in context, inv always works */
	crypto_decode_pxint16(out, (unsigned char *)out);
}

/* ----- underlying hash function */

#define Hash_bytes 32

static void Hash(unsigned char *out, const unsigned char *in, int inlen)
{
	unsigned char h[64];
	int i;
	crypto_hash_sha512(h, in, inlen);
	for (i = 0; i < 32; ++i)
		out[i] = h[i];
}

/* ----- higher-level randomness */

static void Short_random(small *out)
{
	uint32 L[ppadsort];
	int i;

	drbg_ctr_aes256_random((unsigned char *)L, 4 * p);
	crypto_decode_pxint32(L, (unsigned char *)L);
	for (i = 0; i < w; ++i)
		L[i] = L[i] & (uint32)-2;
	for (i = w; i < p; ++i)
		L[i] = (L[i] & (uint32)-3) | 1;
	for (i = p; i < ppadsort; ++i)
		L[i] = 0xffffffff;
	crypto_sort_uint32(L, ppadsort);
	for (i = 0; i < p; ++i)
		out[i] = (L[i] & 3) - 1;
}

static void Small_random(small *out)
{
	uint32 L[p];
	int i;

	drbg_ctr_aes256_random((unsigned char *)L, sizeof L);
	crypto_decode_pxint32(L, (unsigned char *)L);
	for (i = 0; i < p; ++i)
		out[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
}

/* ----- Streamlined NTRU Prime */

typedef small Inputs[p]; /* passed by reference */
#define Ciphertexts_bytes Rounded_bytes
#define SecretKeys_bytes (2 * Small_bytes)
#define PublicKeys_bytes Rq_bytes
#define Confirm_bytes 32

/* c,r_enc[1:] = Hide(r,pk,cache); cache is Hash4(pk) */
/* also set r_enc[0]=3 */
/* also set x[0]=2, and x[1:1+Hash_bytes] = Hash3(r_enc) */
/* also overwrite x[1+Hash_bytes:1+2*Hash_bytes] */
static void Hide(unsigned char *x, unsigned char *c, unsigned char *r_enc,
		 const Inputs r, const unsigned char *pk,
		 const unsigned char *cache)
{
	Fq h[p];
	int i;

	Small_encode(r_enc + 1, r);
	Rq_decode(h, pk);
	Rq_mult_small(h, r);
	Round_and_encode(c, h);
	r_enc[0] = 3;
	Hash(x + 1, r_enc, 1 + Small_bytes);
	for (i = 0; i < Hash_bytes; ++i)
		x[1 + Hash_bytes + i] = cache[i];
	x[0] = 2;
	Hash(c + Ciphertexts_bytes, x, 1 + Hash_bytes * 2);
}

#include "crypto_kem.h"
void crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned int i;
	small g[p];
	for (;;) {
		Small_random(g);
		{
			small v[p + 1];
			small vp;
			crypto_core_inv3((unsigned char *)v,
					 (const unsigned char *)g, 0, 0);
			vp = v[p];
			crypto_declassify(&vp, sizeof vp);
			if (vp == 0) {
				Small_encode(sk + Small_bytes, v);
				break;
			}
		}
	}

	{
		small f[p];
		Short_random(f);
		Small_encode(sk, f);
		{
			Fq h[p + 1];
			Rq_recip3(h, f); /* always works */
			Rq_mult_small(h, g);
			Rq_encode(pk, h);
		}
	}
	{
		int i;
		unsigned char sksave = sk[SecretKeys_bytes - 1];
		for (i = 0; i < PublicKeys_bytes; ++i)
			sk[SecretKeys_bytes + i] = pk[i];
		sk[SecretKeys_bytes - 1] = 4;
		Hash(sk + SecretKeys_bytes + PublicKeys_bytes + Small_bytes,
		     sk + SecretKeys_bytes - 1, 1 + PublicKeys_bytes);
		sk[SecretKeys_bytes - 1] = sksave;
		drbg_ctr_aes256_random(sk + SecretKeys_bytes + PublicKeys_bytes,
				       Small_bytes);
	}
	printf("sec \n");
	for (i = 0; i < crypto_kem_SECRETKEYBYTES; i++) {
		printf("0x%.2x ", ((uint8_t *)(sk))[i]);
		if (!((i + 1) & 0x7))
			printf("\n");
	}
	printf("\n");
	printf("pub \n");
	for (i = 0; i < crypto_kem_PUBLICKEYBYTES; i++) {
		printf("0x%.2x ", ((uint8_t *)(pk))[i]);
		if (!((i + 1) & 0x7))
			printf("\n");
	}
	printf("\n");

	unsigned char ct[crypto_kem_CIPHERTEXTBYTES];
	unsigned char ss[crypto_kem_BYTES];
	crypto_kem_enc(ct, ss, pk);
	printf("ct \n");
	for (i = 0; i < crypto_kem_CIPHERTEXTBYTES; i++) {
		printf("0x%.2x ", ((uint8_t *)(ct))[i]);
		if (!((i + 1) & 0x7))
			printf("\n");
	}
	printf("\n");
	printf("ss \n");
	for (i = 0; i < crypto_kem_BYTES; i++) {
		printf("0x%.2x ", ((uint8_t *)(ss))[i]);
		if (!((i + 1) & 0x7))
			printf("\n");
	}
	printf("\n");
}

void crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk)
{
	unsigned char cache[Hash_bytes];
	int i;
	{
		unsigned char
			y[1 +
			  PublicKeys_bytes]; /* XXX: can eliminate with incremental hashing */
		for (i = 0; i < PublicKeys_bytes; ++i)
			y[1 + i] = pk[i];
		y[0] = 4;
		Hash(cache, y, sizeof y);
	}
	{
		Inputs r;
		Short_random(r);
		{
			unsigned char r_enc[Small_bytes + 1];
			unsigned char x[1 + Hash_bytes + Ciphertexts_bytes +
					Confirm_bytes];
			Hide(x, c, r_enc, r, pk, cache);
			for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; ++i)
				x[1 + Hash_bytes + i] = c[i];
			x[0] = 1;
			Hash(k, x, sizeof x);
		}
	}
}

void crypto_kem_dec(unsigned char *k, const unsigned char *c,
		    const unsigned char *sk)
{
	const unsigned char *pk = sk + SecretKeys_bytes;
	const unsigned char *rho = pk + PublicKeys_bytes;
	const unsigned char *cache = rho + Small_bytes;
	int mask, i;
	Inputs r;
	{
		Fq d[p];
		Rounded_decode(d, c);
		{
			small f[p];
			Small_decode(f, sk);
			Rq_mult_small(d, f);
			Rq_mult3(d, d);
		}
		{
			small e[p];
			small v[p];
			R3_fromRq(e, d);
			Small_decode(v, sk + Small_bytes);
			R3_mult(r, e, v);
		}
		crypto_core_wforce((unsigned char *)r, (unsigned char *)r, 0,
				   0);
	}
	{
		unsigned char r_enc[1 + Small_bytes];
		unsigned char cnew[Ciphertexts_bytes + Confirm_bytes];
		unsigned char
			x[1 + Hash_bytes + Ciphertexts_bytes + Confirm_bytes];
		/* XXX: can use incremental hashing to reduce x size */

		Hide(x, cnew, r_enc, r, pk, cache);
		mask = crypto_verify_clen(c, cnew);
		for (i = 0; i < Small_bytes; ++i)
			r_enc[i + 1] ^= mask & (r_enc[i + 1] ^ rho[i]);
		Hash(x + 1, r_enc,
		     1 + Small_bytes); /* XXX: can instead do cmov on cached hash of rho */
		for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; ++i)
			x[1 + Hash_bytes + i] = c[i];
		x[0] = 1 + mask;
		Hash(k, x, sizeof x);
	}
}
