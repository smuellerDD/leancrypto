/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023 - 2025
 * Frank Denis <j at pureftpd dot org>
 */

#include "alignment.h"
#include "build_bug_on.h"
#include "ed25519_ref10.h"
#include "lc_memset_secure.h"
#include "x25519_scalarmult.h"
#include "x25519_scalarmult_c.h"

/*
 * Reject small order points early to mitigate the implications of
 * unexpected optimizations that would affect the ref10 code.
 * See https://eprint.iacr.org/2017/806.pdf for reference.
 */
static int has_small_order(const unsigned char s[32])
{
	static const unsigned char blocklist[][32] __align(16) = {
		/* 0 (order 4) */
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		/* 1 (order 1) */
		{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		/* 325606250916557431795983626356110631294008115727848805560023387167927233504
           (order 8) */
		{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
		  0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		  0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
		  0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
		/* 39382357235489614581723060781553021112529911719440698176882885853963445705823
           (order 8) */
		{ 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
		  0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		  0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
		  0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
		/* p-1 (order 2) */
		{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
		/* p (=0, order 4) */
		{ 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
		/* p+1 (=1, order 1) */
		{ 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
	};
	unsigned char c[7] = { 0 };
	unsigned int k;
	size_t i, j;

	BUILD_BUG_ON(7 != sizeof blocklist / sizeof blocklist[0]);
	for (j = 0; j < 31; j++) {
		for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
			c[i] |= s[j] ^ blocklist[i][j];
		}
	}
	for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
		c[i] |= (unsigned char)((s[j] & 0x7f) ^ blocklist[i][j]);
	}
	k = 0;
	for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
		k |= (c[i] - 1);
	}
	return (int)((k >> 8) & 1);
}

int crypto_scalarmult_curve25519_c(uint8_t *q, const uint8_t *n,
				   const uint8_t *p)
{
	unsigned char t[32];
	unsigned int i;
	fe25519 x1, x2, x3, z2, z3;
	fe25519 a, b, aa, bb, e, da, cb;
	int pos;
	unsigned int swap;
	unsigned int bit;

	if (has_small_order(p)) {
		return -1;
	}
	for (i = 0; i < 32; i++) {
		t[i] = n[i];
	}
	t[0] &= 248;
	t[31] &= 127;
	t[31] |= 64;
	fe25519_frombytes(x1, p);
	fe25519_1(x2);
	fe25519_0(z2);
	fe25519_copy(x3, x1);
	fe25519_1(z3);

	swap = 0;
	for (pos = 254; pos >= 0; --pos) {
		bit = t[pos / 8] >> (pos & 7);
		bit &= 1;
		swap ^= bit;
		fe25519_cswap(x2, x3, swap);
		fe25519_cswap(z2, z3, swap);
		swap = bit;
		fe25519_add(a, x2, z2);
		fe25519_sub(b, x2, z2);
		fe25519_sq(aa, a);
		fe25519_sq(bb, b);
		fe25519_mul(x2, aa, bb);
		fe25519_sub(e, aa, bb);
		fe25519_sub(da, x3, z3);
		fe25519_mul(da, da, a);
		fe25519_add(cb, x3, z3);
		fe25519_mul(cb, cb, b);
		fe25519_add(x3, da, cb);
		fe25519_sq(x3, x3);
		fe25519_sub(z3, da, cb);
		fe25519_sq(z3, z3);
		fe25519_mul(z3, z3, x1);
		fe25519_mul32(z2, e, 121666);
		fe25519_add(z2, z2, bb);
		fe25519_mul(z2, z2, e);
	}
	fe25519_cswap(x2, x3, swap);
	fe25519_cswap(z2, z3, swap);

	fe25519_invert(z2, z2);
	fe25519_mul(x2, x2, z2);
	fe25519_tobytes(q, x2);

	lc_memset_secure(t, 0, sizeof t);

	return 0;
}

static void edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY,
				  const fe25519 edwardsZ)
{
	fe25519 tempX;
	fe25519 tempZ;

	fe25519_add(tempX, edwardsZ, edwardsY);
	fe25519_sub(tempZ, edwardsZ, edwardsY);
	fe25519_invert(tempZ, tempZ);
	fe25519_mul(montgomeryX, tempX, tempZ);
}

int crypto_scalarmult_curve25519_base(uint8_t *q, const uint8_t *n)
{
	unsigned char *t = q;
	ge25519_p3 A;
	fe25519 pk;
	unsigned int i;

	for (i = 0; i < 32; i++) {
		t[i] = n[i];
	}
	t[0] &= 248;
	t[31] &= 127;
	t[31] |= 64;
	ge25519_scalarmult_base(&A, t);
	edwards_to_montgomery(pk, A.Y, A.Z);
	fe25519_tobytes(q, pk);

	return 0;
}
