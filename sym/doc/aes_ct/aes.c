#include <stdio.h>

int mul(int a, int b)
{
	int i, x, y;
	y = b;
	x = -(a & 1) & y;
	for (i = 1; i < 8; i++) {
		y = (y << 1) ^ (-(y >> 7) & 0x11b);
		x ^= -((a >> i) & 1) & y;
	}
	return x;
}

int inv(int a)
{
	int i, x, y;
	y = mul(a, a);
	x = y;
	for (i = 1; i < 7; i++) {
		y = mul(y, y);
		x = mul(x, y);
	}
	return x;
}

int sub(int a)
{
	int b, bb;
	b = inv(a);
	bb = (b << 8) | b;
	b ^= 0x63;
	b ^= ((bb >> 4) ^ (bb >> 5) ^ (bb >> 6) ^ (bb >> 7)) & 0xFF;
	return b;
}

int invsub(int a)
{
	int b, bb;
	b = a ^ 0x63;
	bb = (b << 8) | b;
	b = ((bb >> 2) ^ (bb >> 5) ^ (bb >> 7)) & 0xFF;
	b = inv(b);
	return b;
}

void SubBytes(unsigned char *state)
{
	int i;
	for (i = 0; i < 16; i++)
		state[i] = sub(state[i]);
}

void InvSubBytes(unsigned char *state)
{
	int i;
	for (i = 0; i < 16; i++)
		state[i] = invsub(state[i]);
}

void ShiftRows(unsigned char *state)
{
	int r, s[4];
	for (r = 0; r < 4; r++) {
		s[0] = state[0 * 4 + r];
		s[1] = state[1 * 4 + r];
		s[2] = state[2 * 4 + r];
		s[3] = state[3 * 4 + r];
		state[0 * 4 + r] = s[(r + 0) % 4];
		state[1 * 4 + r] = s[(r + 1) % 4];
		state[2 * 4 + r] = s[(r + 2) % 4];
		state[3 * 4 + r] = s[(r + 3) % 4];
	}
}

void InvShiftRows(unsigned char *state)
{
	int r, s[4];
	for (r = 0; r < 4; r++) {
		s[0] = state[0 * 4 + r];
		s[1] = state[1 * 4 + r];
		s[2] = state[2 * 4 + r];
		s[3] = state[3 * 4 + r];
		state[0 * 4 + r] = s[(4 - r) % 4];
		state[1 * 4 + r] = s[(5 - r) % 4];
		state[2 * 4 + r] = s[(6 - r) % 4];
		state[3 * 4 + r] = s[(7 - r) % 4];
	}
}

void MixColumns(unsigned char *state)
{
	int c, s[4];
	for (c = 0; c < 4; c++) {
		s[0] = state[c * 4 + 0];
		s[1] = state[c * 4 + 1];
		s[2] = state[c * 4 + 2];
		s[3] = state[c * 4 + 3];
		state[c * 4 + 0] = mul(2, s[0]) ^ mul(3, s[1]) ^ s[2] ^ s[3];
		state[c * 4 + 1] = mul(2, s[1]) ^ mul(3, s[2]) ^ s[3] ^ s[0];
		state[c * 4 + 2] = mul(2, s[2]) ^ mul(3, s[3]) ^ s[0] ^ s[1];
		state[c * 4 + 3] = mul(2, s[3]) ^ mul(3, s[0]) ^ s[1] ^ s[2];
	}
}

void InvMixColumns(unsigned char *state)
{
	int c, s[4];
	for (c = 0; c < 4; c++) {
		s[0] = state[c * 4 + 0];
		s[1] = state[c * 4 + 1];
		s[2] = state[c * 4 + 2];
		s[3] = state[c * 4 + 3];
		state[c * 4 + 0] = mul(0xe, s[0]) ^ mul(0xb, s[1]) ^
				   mul(0xd, s[2]) ^ mul(0x9, s[3]);
		state[c * 4 + 1] = mul(0xe, s[1]) ^ mul(0xb, s[2]) ^
				   mul(0xd, s[3]) ^ mul(0x9, s[0]);
		state[c * 4 + 2] = mul(0xe, s[2]) ^ mul(0xb, s[3]) ^
				   mul(0xd, s[0]) ^ mul(0x9, s[1]);
		state[c * 4 + 3] = mul(0xe, s[3]) ^ mul(0xb, s[0]) ^
				   mul(0xd, s[1]) ^ mul(0x9, s[2]);
	}
}

void AddRoundKey(unsigned char *state, unsigned char *w)
{
	int c;
	for (c = 0; c < 4; c++) {
		state[c * 4 + 0] ^= w[c * 4 + 0];
		state[c * 4 + 1] ^= w[c * 4 + 1];
		state[c * 4 + 2] ^= w[c * 4 + 2];
		state[c * 4 + 3] ^= w[c * 4 + 3];
	}
}

void Cipher(unsigned char *in, unsigned char *out, unsigned char *w, int nr)
{
	unsigned char *state;
	int i;

	state = out;
	for (i = 0; i < 16; i++)
		state[i] = in[i];

	AddRoundKey(state, w);

	for (i = 1; i < nr; i++) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, w + 16 * i);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, w + 16 * nr);
}

void InvCipher(unsigned char *in, unsigned char *out, unsigned char *w, int nr)
{
	unsigned char *state;
	int i;

	state = out;
	for (i = 0; i < 16; i++)
		state[i] = in[i];

	AddRoundKey(state, w + 16 * nr);

	for (i = nr - 1; i > 0; i--) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, w + 16 * i);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, w);
}

void EqInvCipher(unsigned char *in, unsigned char *out, unsigned char *w,
		 int nr)
{
	unsigned char *state;
	int i;

	state = out;
	for (i = 0; i < 16; i++)
		state[i] = in[i];

	AddRoundKey(state, w + 16 * nr);

	for (i = nr - 1; i > 0; i--) {
		InvSubBytes(state);
		InvShiftRows(state);
		InvMixColumns(state);
		AddRoundKey(state, w + 16 * i);
	}

	InvSubBytes(state);
	InvShiftRows(state);
	AddRoundKey(state, w);
}

void SubWord(unsigned char *w)
{
	int i;
	for (i = 0; i < 4; i++)
		w[i] = sub(w[i]);
}

void RotWord(unsigned char *w)
{
	int w0;
	w0 = w[0];
	w[0] = w[1];
	w[1] = w[2];
	w[2] = w[3];
	w[3] = w0;
}

void KeyExpansion(unsigned char *key, unsigned char *w, int nr, int nk)
{
	unsigned char temp[4];
	int rcon = 1;
	int i;

	for (i = 0; i < nk; i++) {
		w[i * 4 + 0] = key[i * 4 + 0];
		w[i * 4 + 1] = key[i * 4 + 1];
		w[i * 4 + 2] = key[i * 4 + 2];
		w[i * 4 + 3] = key[i * 4 + 3];
	}

	for (; i < 4 * (nr + 1); i++) {
		temp[0] = w[(i - 1) * 4 + 0];
		temp[1] = w[(i - 1) * 4 + 1];
		temp[2] = w[(i - 1) * 4 + 2];
		temp[3] = w[(i - 1) * 4 + 3];
		if (i % nk == 0) {
			RotWord(temp);
			SubWord(temp);
			temp[0] ^= rcon;
			rcon = mul(2, rcon);
		} else if (nk > 6 && i % nk == 4) {
			SubWord(temp);
		}
		w[i * 4 + 0] = w[(i - nk) * 4 + 0] ^ temp[0];
		w[i * 4 + 1] = w[(i - nk) * 4 + 1] ^ temp[1];
		w[i * 4 + 2] = w[(i - nk) * 4 + 2] ^ temp[2];
		w[i * 4 + 3] = w[(i - nk) * 4 + 3] ^ temp[3];
	}
}

void InvKeyExpansion(unsigned char *w, int nr)
{
	int i;
	for (i = 1; i < nr; i++)
		InvMixColumns(w + i * 16);
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
	unsigned char w[15 * 16];
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
	InvKeyExpansion(w, 14);
	EqInvCipher(cipher, output, w, 14);
	for (x = 0; x < 16; x++) {
		if (x % 4 == 0)
			printf("%2d: ", x / 4);
		printf("%02x ", output[x]);
		if (x % 4 == 3)
			printf("\n");
	}
	return 0;
}
