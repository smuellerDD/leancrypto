#include <string.h>
#include <stdio.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef union {
	unsigned char b[8];
	u32 w[2];
	u64 d;
} uni;

static void XtimeWord(u32 *w)
{
	u32 a, b;
	a = *w;
	b = a & 0x80808080u;
	a ^= b;
	b -= b >> 7;
	b &= 0x1B1B1B1Bu;
	b ^= a << 1;
	*w = b;
}

static void XtimeLong(u64 *w)
{
	u64 a, b;
	a = *w;
	b = a & 0x8080808080808080uLL;
	a ^= b;
	b -= b >> 7;
	b &= 0x1B1B1B1B1B1B1B1BuLL;
	b ^= a << 1;
	*w = b;
}

static void SubWord(u32 *w)
{
	u32 x, y, a1, a2, a3, a4, a5, a6;
	x = *w;
	y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
	x &= 0xDDDDDDDDu;
	x ^= y & 0x57575757u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x1C1C1C1Cu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x4A4A4A4Au;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x42424242u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x64646464u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0xE0E0E0E0u;
	a1 = x;
	a1 ^= (x & 0xF0F0F0F0u) >> 4;
	// a3=mul4(x,a1)
	a2 = ((x & 0xCCCCCCCCu) >> 2) | ((x & 0x33333333u) << 2);
	// a3=mul2(x,a1)
	a3 = x & a1;
	a3 ^= (a3 & 0xAAAAAAAAu) >> 1;
	a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAu;
	// a4=mul2(a2,a1)
	a4 = a2 & a1;
	a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
	a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAu;
	a5 = (a3 & 0xCCCCCCCCu) >> 2;
	a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
	// a4=mul2(a5,2)
	a4 = a5 & 0x22222222u;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x22222222u;
	a3 ^= a4;
	// a4=mul4(8,a3)
	// a5=mul2(2,a3)
	a5 = a3 & 0xA0A0A0A0u;
	a5 |= a5 >> 1;
	a5 ^= (a3 << 1) & 0xA0A0A0A0u;
	a4 = a5 & 0xC0C0C0C0u;
	a6 = a4 >> 2;
	a4 ^= (a5 << 2) & 0xC0C0C0C0u;
	// a5=mul2(2,a6)
	a5 = a6 & 0x20202020u;
	a5 |= a5 >> 1;
	a5 ^= (a6 << 1) & 0x20202020u;
	a4 |= a5;
	a3 ^= a4 >> 4;
	a3 &= 0x0F0F0F0Fu;
	// a3=inv4(a3)
	a2 = a3;
	a2 ^= (a3 & 0x0C0C0C0Cu) >> 2;
	// a4=mul2(a3,a2)
	a4 = a3 & a2;
	a4 ^= (a4 & 0x0A0A0A0A0Au) >> 1;
	a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0Au;
	// a5=mul2(2,a4)
	a5 = a4 & 0x08080808u;
	a5 |= a5 >> 1;
	a5 ^= (a4 << 1) & 0x08080808u;
	a4 ^= a5 >> 2;
	a4 &= 0x03030303u;
	// a4=inv2(a4)
	a4 ^= (a4 & 0x02020202u) >> 1;
	a4 |= a4 << 2;
	// a3=mul2(a2,a4)
	a3 = a2 & a4;
	a3 ^= (a3 & 0x0A0A0A0Au) >> 1;
	a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0Au;
	a3 |= a3 << 4;
	// x=mul4(a1,a3)
	a2 = ((a1 & 0xCCCCCCCCu) >> 2) | ((a1 & 0x33333333u) << 2);
	x = a1 & a3;
	x ^= (x & 0xAAAAAAAAu) >> 1;
	x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAu;
	// a4=mul2(a2,a3)
	a4 = a2 & a3;
	a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
	a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAu;
	a5 = (x & 0xCCCCCCCCu) >> 2;
	x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
	// a4=mul2(a5,2)
	a4 = a5 & 0x22222222u;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x22222222u;
	x ^= a4;
	// S*X^-1
	y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
	x &= 0x39393939u;
	x ^= y & 0x3F3F3F3Fu;
	y = ((y & 0xFCFCFCFCu) >> 2) | ((y & 0x03030303u) << 6);
	x ^= y & 0x97979797u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x9B9B9B9Bu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x3C3C3C3Cu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0xDDDDDDDDu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x72727272u;
	x ^= 0x63636363u;
	*w = x;
}

static void SubLong(u64 *w)
{
	u64 x, y, a1, a2, a3, a4, a5, a6;
	x = *w;
	y = ((x & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((x & 0x0101010101010101uLL) << 7);
	x &= 0xDDDDDDDDDDDDDDDDuLL;
	x ^= y & 0x5757575757575757uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x1C1C1C1C1C1C1C1CuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x4A4A4A4A4A4A4A4AuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x4242424242424242uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x6464646464646464uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xE0E0E0E0E0E0E0E0uLL;
	a1 = x;
	a1 ^= (x & 0xF0F0F0F0F0F0F0F0uLL) >> 4;
	// a3=mul4(x,a1)
	a2 = ((x & 0xCCCCCCCCCCCCCCCCuLL) >> 2) |
	     ((x & 0x3333333333333333uLL) << 2);
	// a3=mul2(x,a1)
	a3 = x & a1;
	a3 ^= (a3 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAAAAAAAAAuLL;
	// a4=mul2(a2,a1)
	a4 = a2 & a1;
	a4 ^= (a4 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAAAAAAAAAuLL;
	a5 = (a3 & 0xCCCCCCCCCCCCCCCCuLL) >> 2;
	a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCCCCCCCCCuLL;
	// a4=mul2(a5,2)
	a4 = a5 & 0x2222222222222222uLL;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x2222222222222222uLL;
	a3 ^= a4;
	// a4=mul4(8,a3)
	// a5=mul2(2,a3)
	a5 = a3 & 0xA0A0A0A0A0A0A0A0uLL;
	a5 |= a5 >> 1;
	a5 ^= (a3 << 1) & 0xA0A0A0A0A0A0A0A0uLL;
	a4 = a5 & 0xC0C0C0C0C0C0C0C0uLL;
	a6 = a4 >> 2;
	a4 ^= (a5 << 2) & 0xC0C0C0C0C0C0C0C0uLL;
	// a5=mul2(2,a6)
	a5 = a6 & 0x2020202020202020uLL;
	a5 |= a5 >> 1;
	a5 ^= (a6 << 1) & 0x2020202020202020uLL;
	a4 |= a5;
	a3 ^= a4 >> 4;
	a3 &= 0x0F0F0F0F0F0F0F0FuLL;
	// a3=inv4(a3)
	a2 = a3;
	a2 ^= (a3 & 0x0C0C0C0C0C0C0C0CuLL) >> 2;
	// a4=mul2(a3,a2)
	a4 = a3 & a2;
	a4 ^= (a4 & 0x0A0A0A0A0A0A0A0AuLL) >> 1;
	a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0A0A0A0A0AuLL;
	// a5=mul2(2,a4)
	a5 = a4 & 0x0808080808080808uLL;
	a5 |= a5 >> 1;
	a5 ^= (a4 << 1) & 0x0808080808080808uLL;
	a4 ^= a5 >> 2;
	a4 &= 0x0303030303030303uLL;
	// a4=inv2(a4)
	a4 ^= (a4 & 0x0202020202020202uLL) >> 1;
	a4 |= a4 << 2;
	// a3=mul2(a2,a4)
	a3 = a2 & a4;
	a3 ^= (a3 & 0x0A0A0A0A0A0A0A0AuLL) >> 1;
	a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0A0A0A0A0AuLL;
	a3 |= a3 << 4;
	// x=mul4(a1,a3)
	a2 = ((a1 & 0xCCCCCCCCCCCCCCCCuLL) >> 2) |
	     ((a1 & 0x3333333333333333uLL) << 2);
	x = a1 & a3;
	x ^= (x & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAAAAAAAAAuLL;
	// a4=mul2(a2,a3)
	a4 = a2 & a3;
	a4 ^= (a4 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAAAAAAAAAuLL;
	a5 = (x & 0xCCCCCCCCCCCCCCCCuLL) >> 2;
	x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCCCCCCCCCuLL;
	// a4=mul2(a5,2)
	a4 = a5 & 0x2222222222222222uLL;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x2222222222222222uLL;
	x ^= a4;
	// S*X^-1
	y = ((x & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((x & 0x0101010101010101uLL) << 7);
	x &= 0x3939393939393939uLL;
	x ^= y & 0x3F3F3F3F3F3F3F3FuLL;
	y = ((y & 0xFCFCFCFCFCFCFCFCuLL) >> 2) |
	    ((y & 0x0303030303030303uLL) << 6);
	x ^= y & 0x9797979797979797uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x9B9B9B9B9B9B9B9BuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x3C3C3C3C3C3C3C3CuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xDDDDDDDDDDDDDDDDuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x7272727272727272uLL;
	x ^= 0x6363636363636363uLL;
	*w = x;
}

static void InvSubLong(u64 *w)
{
	u64 x, y, a1, a2, a3, a4, a5, a6;
	x = *w;
	x ^= 0x6363636363636363uLL;
	// X*S^-1
	y = ((x & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((x & 0x0101010101010101uLL) << 7);
	x &= 0xFDFDFDFDFDFDFDFDuLL;
	x ^= y & 0x5E5E5E5E5E5E5E5EuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xF3F3F3F3F3F3F3F3uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xF5F5F5F5F5F5F5F5uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x7878787878787878uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x7777777777777777uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x1515151515151515uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xA5A5A5A5A5A5A5A5uLL;
	a1 = x;
	a1 ^= (x & 0xF0F0F0F0F0F0F0F0uLL) >> 4;
	// a3=mul4(x,a1)
	a2 = ((x & 0xCCCCCCCCCCCCCCCCuLL) >> 2) |
	     ((x & 0x3333333333333333uLL) << 2);
	// a3=mul2(x,a1)
	a3 = x & a1;
	a3 ^= (a3 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAAAAAAAAAuLL;
	// a4=mul2(a2,a1)
	a4 = a2 & a1;
	a4 ^= (a4 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAAAAAAAAAuLL;
	a5 = (a3 & 0xCCCCCCCCCCCCCCCCuLL) >> 2;
	a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCCCCCCCCCuLL;
	// a4=mul2(a5,2)
	a4 = a5 & 0x2222222222222222uLL;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x2222222222222222uLL;
	a3 ^= a4;
	// a4=mul4(8,a3)
	// a5=mul2(2,a3)
	a5 = a3 & 0xA0A0A0A0A0A0A0A0uLL;
	a5 |= a5 >> 1;
	a5 ^= (a3 << 1) & 0xA0A0A0A0A0A0A0A0uLL;
	a4 = a5 & 0xC0C0C0C0C0C0C0C0uLL;
	a6 = a4 >> 2;
	a4 ^= (a5 << 2) & 0xC0C0C0C0C0C0C0C0uLL;
	// a5=mul2(2,a6)
	a5 = a6 & 0x2020202020202020uLL;
	a5 |= a5 >> 1;
	a5 ^= (a6 << 1) & 0x2020202020202020uLL;
	a4 |= a5;
	a3 ^= a4 >> 4;
	a3 &= 0x0F0F0F0F0F0F0F0FuLL;
	// a3=inv4(a3)
	a2 = a3;
	a2 ^= (a3 & 0x0C0C0C0C0C0C0C0CuLL) >> 2;
	// a4=mul2(a3,a2)
	a4 = a3 & a2;
	a4 ^= (a4 & 0x0A0A0A0A0A0A0A0AuLL) >> 1;
	a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0A0A0A0A0AuLL;
	// a5=mul2(2,a4)
	a5 = a4 & 0x0808080808080808uLL;
	a5 |= a5 >> 1;
	a5 ^= (a4 << 1) & 0x0808080808080808uLL;
	a4 ^= a5 >> 2;
	a4 &= 0x0303030303030303uLL;
	// a4=inv2(a4)
	a4 ^= (a4 & 0x0202020202020202uLL) >> 1;
	a4 |= a4 << 2;
	// a3=mul2(a2,a4)
	a3 = a2 & a4;
	a3 ^= (a3 & 0x0A0A0A0A0A0A0A0AuLL) >> 1;
	a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0A0A0A0A0AuLL;
	a3 |= a3 << 4;
	// x=mul4(a1,a3)
	a2 = ((a1 & 0xCCCCCCCCCCCCCCCCuLL) >> 2) |
	     ((a1 & 0x3333333333333333uLL) << 2);
	x = a1 & a3;
	x ^= (x & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAAAAAAAAAuLL;
	// a4=mul2(a2,a3)
	a4 = a2 & a3;
	a4 ^= (a4 & 0xAAAAAAAAAAAAAAAAuLL) >> 1;
	a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAAAAAAAAAuLL;
	a5 = (x & 0xCCCCCCCCCCCCCCCCuLL) >> 2;
	x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCCCCCCCCCuLL;
	// a4=mul2(a5,2)
	a4 = a5 & 0x2222222222222222uLL;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x2222222222222222uLL;
	x ^= a4;
	// X^-1
	y = ((x & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((x & 0x0101010101010101uLL) << 7);
	x &= 0xB5B5B5B5B5B5B5B5uLL;
	x ^= y & 0x4040404040404040uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x8080808080808080uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x1616161616161616uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xEBEBEBEBEBEBEBEBuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x9797979797979797uLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0xFBFBFBFBFBFBFBFBuLL;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y & 0x7D7D7D7D7D7D7D7DuLL;
	*w = x;
}

static void ShiftRows(u64 *state)
{
	unsigned char s[4];
	unsigned char *s0;
	int r;

	s0 = (unsigned char *)state;
	for (r = 0; r < 4; r++) {
		s[0] = s0[0 * 4 + r];
		s[1] = s0[1 * 4 + r];
		s[2] = s0[2 * 4 + r];
		s[3] = s0[3 * 4 + r];
		s0[0 * 4 + r] = s[(r + 0) % 4];
		s0[1 * 4 + r] = s[(r + 1) % 4];
		s0[2 * 4 + r] = s[(r + 2) % 4];
		s0[3 * 4 + r] = s[(r + 3) % 4];
	}
}

static void InvShiftRows(u64 *state)
{
	unsigned char s[4];
	unsigned char *s0;
	int r;

	s0 = (unsigned char *)state;
	for (r = 0; r < 4; r++) {
		s[0] = s0[0 * 4 + r];
		s[1] = s0[1 * 4 + r];
		s[2] = s0[2 * 4 + r];
		s[3] = s0[3 * 4 + r];
		s0[0 * 4 + r] = s[(4 - r) % 4];
		s0[1 * 4 + r] = s[(5 - r) % 4];
		s0[2 * 4 + r] = s[(6 - r) % 4];
		s0[3 * 4 + r] = s[(7 - r) % 4];
	}
}

static void MixColumns(u64 *state)
{
	uni s1;
	uni s;
	int c;

	for (c = 0; c < 2; c++) {
		s1.d = state[c];
		s.d = s1.d;
		s.d ^= (s.d & 0xFFFF0000FFFF0000uLL) >> 16 |
		       (s.d & 0x0000FFFF0000FFFFuLL) << 16;
		s.d ^= (s.d & 0xFF00FF00FF00FF00uLL) >> 8 |
		       (s.d & 0x00FF00FF00FF00FFuLL) << 8;
		s.d ^= s1.d;
		XtimeLong(&s1.d);
		s.d ^= s1.d;
		s.b[0] ^= s1.b[1];
		s.b[1] ^= s1.b[2];
		s.b[2] ^= s1.b[3];
		s.b[3] ^= s1.b[0];
		s.b[4] ^= s1.b[5];
		s.b[5] ^= s1.b[6];
		s.b[6] ^= s1.b[7];
		s.b[7] ^= s1.b[4];
		state[c] = s.d;
	}
}

static void InvMixColumns(u64 *state)
{
	uni s1;
	uni s;
	int c;

	for (c = 0; c < 2; c++) {
		s1.d = state[c];
		s.d = s1.d;
		s.d ^= (s.d & 0xFFFF0000FFFF0000uLL) >> 16 |
		       (s.d & 0x0000FFFF0000FFFFuLL) << 16;
		s.d ^= (s.d & 0xFF00FF00FF00FF00uLL) >> 8 |
		       (s.d & 0x00FF00FF00FF00FFuLL) << 8;
		s.d ^= s1.d;
		XtimeLong(&s1.d);
		s.d ^= s1.d;
		s.b[0] ^= s1.b[1];
		s.b[1] ^= s1.b[2];
		s.b[2] ^= s1.b[3];
		s.b[3] ^= s1.b[0];
		s.b[4] ^= s1.b[5];
		s.b[5] ^= s1.b[6];
		s.b[6] ^= s1.b[7];
		s.b[7] ^= s1.b[4];
		XtimeLong(&s1.d);
		s1.d ^= (s1.d & 0xFFFF0000FFFF0000uLL) >> 16 |
			(s1.d & 0x0000FFFF0000FFFFuLL) << 16;
		s.d ^= s1.d;
		XtimeLong(&s1.d);
		s1.d ^= (s1.d & 0xFF00FF00FF00FF00uLL) >> 8 |
			(s1.d & 0x00FF00FF00FF00FFuLL) << 8;
		s.d ^= s1.d;
		state[c] = s.d;
	}
}

static void AddRoundKey(u64 *state, u64 *w)
{
	state[0] ^= w[0];
	state[1] ^= w[1];
}

void Cipher(unsigned char *in, unsigned char *out, u64 *w, int nr)
{
	u64 state[2];
	int i;

	memcpy(state, in, 16);

	AddRoundKey(state, w);

	for (i = 1; i < nr; i++) {
		SubLong(&state[0]);
		SubLong(&state[1]);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, w + i * 2);
	}

	SubLong(&state[0]);
	SubLong(&state[1]);
	ShiftRows(state);
	AddRoundKey(state, w + nr * 2);

	memcpy(out, state, 16);
}

void InvCipher(unsigned char *in, unsigned char *out, u64 *w, int nr)
{
	u64 state[2];
	int i;

	memcpy(state, in, 16);

	AddRoundKey(state, w + nr * 2);

	for (i = nr - 1; i > 0; i--) {
		InvShiftRows(state);
		InvSubLong(&state[0]);
		InvSubLong(&state[1]);
		AddRoundKey(state, w + i * 2);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubLong(&state[0]);
	InvSubLong(&state[1]);
	AddRoundKey(state, w);

	memcpy(out, state, 16);
}

void RotWord(u32 *x)
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

void KeyExpansion(unsigned char *key, u64 *w, int nr, int nk)
{
	u32 rcon;
	uni prev;
	u32 temp;
	int i, n;

	memcpy(w, key, nk * 4);
	memcpy(&rcon, "\1\0\0\0", 4);
	n = nk / 2;
	prev.d = w[n - 1];
	for (i = n; i < (nr + 1) * 2; i++) {
		temp = prev.w[1];
		if (i % n == 0) {
			RotWord(&temp);
			SubWord(&temp);
			temp ^= rcon;
			XtimeWord(&rcon);
		} else if (nk > 6 && i % n == 2) {
			SubWord(&temp);
		}
		prev.d = w[i - n];
		prev.w[0] ^= temp;
		prev.w[1] ^= prev.w[0];
		w[i] = prev.d;
	}
}

int main()
{
	int x;
	unsigned char plain[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
				    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
				    0xcc, 0xdd, 0xee, 0xff };
	unsigned char key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				  0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				  0x1c, 0x1d, 0x1e, 0x1f };
	unsigned char input[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a,
				    0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
				    0xe0, 0x37, 0x07, 0x34 };
	unsigned char key1[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
				   0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
				   0x09, 0xcf, 0x4f, 0x3c };
	u64 w[15 * 2];
	unsigned char cipher[16];
	unsigned char output[16];
	KeyExpansion(key1, w, 10, 4);
	Cipher(input, cipher, w, 10);
	for (x = 0; x < 16; x++) {
		if (x % 4 == 0)
			printf("%2d: ", x / 4);
		printf("%02x ", cipher[x]);
		if (x % 4 == 3)
			printf("\n");
	}
	InvCipher(cipher, output, w, 10);
	for (x = 0; x < 16; x++) {
		if (x % 4 == 0)
			printf("%2d: ", x / 4);
		printf("%02x ", output[x]);
		if (x % 4 == 3)
			printf("\n");
	}
	KeyExpansion(key, w, 14, 8);
	Cipher(plain, cipher, w, 14);
	for (x = 0; x < 16; x++) {
		if (x % 4 == 0)
			printf("%2d: ", x / 4);
		printf("%02x ", cipher[x]);
		if (x % 4 == 3)
			printf("\n");
	}
	InvCipher(cipher, output, w, 14);
	for (x = 0; x < 16; x++) {
		if (x % 4 == 0)
			printf("%2d: ", x / 4);
		printf("%02x ", output[x]);
		if (x % 4 == 3)
			printf("\n");
	}
	return 0;
}
