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

static void MulWord(u32 *r, u32 *s)
{
	int i;
	u32 a, m, x, y;
	a = *r;
	y = *s;
	m = a & 0x01010101u;
	a >>= 1;
	m = (m << 8) - m;
	x = m & y;
	for (i = 1; i < 8; i++) {
		m = y & 0x80808080u;
		y ^= m;
		m = m - (m >> 7);
		y = (y << 1) ^ (m & 0x1B1B1B1Bu);
		m = a & 0x01010101u;
		a >>= 1;
		m = (m << 8) - m;
		x ^= (y & m);
	}
	*r = x;
}

static void MulWord2(u32 *r, u32 *s)
{
	int i;
	u32 a, b, m, x, y, z;
	a = *r;
	y = *s;
	b = y;
	m = a & 0x01010101u;
	a >>= 1;
	m = (m << 8) - m;
	x = m & y;
	m = b & 0x01010101u;
	b >>= 1;
	m = (m << 8) - m;
	z = m & y;
	for (i = 1; i < 8; i++) {
		m = y & 0x80808080u;
		y ^= m;
		m = m - (m >> 7);
		y = (y << 1) ^ (m & 0x1B1B1B1Bu);
		m = a & 0x01010101u;
		a >>= 1;
		m = (m << 8) - m;
		x ^= (y & m);
		m = b & 0x01010101u;
		b >>= 1;
		m = (m << 8) - m;
		z ^= (y & m);
	}
	*r = x;
	*s = z;
}

static void MulLong(u64 *r, u64 *s)
{
	int i;
	u64 a, m, x, y;
	a = *r;
	y = *s;
	m = a & 0x0101010101010101uLL;
	a >>= 1;
	m = (m << 8) - m;
	x = m & y;
	for (i = 1; i < 8; i++) {
		m = y & 0x8080808080808080uLL;
		y ^= m;
		m = m - (m >> 7);
		y = (y << 1) ^ (m & 0x1B1B1B1B1B1B1B1BuLL);
		m = a & 0x0101010101010101uLL;
		a >>= 1;
		m = (m << 8) - m;
		x ^= (y & m);
	}
	*r = x;
}

static void MulLong2(u64 *r, u64 *s)
{
	int i;
	u64 a, b, m, x, y, z;
	a = *r;
	y = *s;
	b = y;
	m = a & 0x0101010101010101uLL;
	a >>= 1;
	m = (m << 8) - m;
	x = m & y;
	m = b & 0x0101010101010101uLL;
	b >>= 1;
	m = (m << 8) - m;
	z = m & y;
	for (i = 1; i < 8; i++) {
		m = y & 0x8080808080808080uLL;
		y ^= m;
		m = m - (m >> 7);
		y = (y << 1) ^ (m & 0x1B1B1B1B1B1B1B1BuLL);
		m = a & 0x0101010101010101uLL;
		a >>= 1;
		m = (m << 8) - m;
		x ^= (y & m);
		m = b & 0x0101010101010101uLL;
		b >>= 1;
		m = (m << 8) - m;
		z ^= (y & m);
	}
	*r = x;
	*s = z;
}

static void SubWord(u32 *w)
{
	u32 x, y;
	y = *w;
	MulWord(&y, &y);
	x = y;
	MulWord(&y, &y);
	MulWord2(&x, &y);
	MulWord2(&x, &y);
	MulWord2(&x, &y);
	MulWord2(&x, &y);
	MulWord2(&x, &y);
	MulWord(&x, &y);
	y = ((x & 0xF0F0F0F0u) >> 4) | ((x & 0x0F0F0F0Fu) << 4);
	x ^= y;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y;
	x ^= 0x63636363u;
	*w = x;
}

static void SubLong(u64 *w)
{
	u64 x, y;
	y = *w;
	MulLong(&y, &y);
	x = y;
	MulLong(&y, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong(&x, &y);
	y = ((x & 0xF0F0F0F0F0F0F0F0uLL) >> 4) |
	    ((x & 0x0F0F0F0F0F0F0F0FuLL) << 4);
	x ^= y;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y;
	y = ((y & 0xFEFEFEFEFEFEFEFEuLL) >> 1) |
	    ((y & 0x0101010101010101uLL) << 7);
	x ^= y;
	x ^= 0x6363636363636363uLL;
	*w = x;
}

static void InvSubLong(u64 *w)
{
	u64 x, y;
	y = *w;
	y ^= 0x6363636363636363uLL;
	y = ((y & 0xFCFCFCFCFCFCFCFCuLL) >> 2) |
	    ((y & 0x0303030303030303uLL) << 6);
	x = ((y & 0xF8F8F8F8F8F8F8F8uLL) >> 3) |
	    ((y & 0x0707070707070707uLL) << 5);
	y ^= x;
	x = ((x & 0xFCFCFCFCFCFCFCFCuLL) >> 2) |
	    ((x & 0x0303030303030303uLL) << 6);
	y ^= x;
	MulLong(&y, &y);
	x = y;
	MulLong(&y, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong2(&x, &y);
	MulLong(&x, &y);
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
