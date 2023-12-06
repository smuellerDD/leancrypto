/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
 * Copyright (c) 2013-2023
 * Frank Denis <j at pureftpd dot org>
 */

#ifndef FE_H
#define FE_H

#include "bitshift_le.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 Ignores top bit of s.
 */

void fe25519_frombytes(fe25519 h, const unsigned char *s)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint64_t h0, h1, h2, h3, h4;

	h0 = (ptr_to_le64(s)) & mask;
	h1 = (ptr_to_le64(s + 6) >> 3) & mask;
	h2 = (ptr_to_le64(s + 12) >> 6) & mask;
	h3 = (ptr_to_le64(s + 19) >> 1) & mask;
	h4 = (ptr_to_le64(s + 24) >> 12) & mask;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
}

static void fe25519_reduce(fe25519 h, const fe25519 f)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t t[5];

	t[0] = f[0];
	t[1] = f[1];
	t[2] = f[2];
	t[3] = f[3];
	t[4] = f[4];

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19ULL;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19ULL * (t[4] >> 51);
	t[4] &= mask;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000 - 19ULL;
	t[1] += 0x8000000000000 - 1ULL;
	t[2] += 0x8000000000000 - 1ULL;
	t[3] += 0x8000000000000 - 1ULL;
	t[4] += 0x8000000000000 - 1ULL;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[4] &= mask;

	h[0] = (uint64_t)t[0];
	h[1] = (uint64_t)t[1];
	h[2] = (uint64_t)t[2];
	h[3] = (uint64_t)t[3];
	h[4] = (uint64_t)t[4];
}

void fe25519_tobytes(unsigned char *s, const fe25519 h)
{
	fe25519 t;
	uint64_t t0, t1, t2, t3;

	fe25519_reduce(t, h);
	t0 = t[0] | (t[1] << 51);
	t1 = (t[1] >> 13) | (t[2] << 38);
	t2 = (t[2] >> 26) | (t[3] << 25);
	t3 = (t[3] >> 39) | (t[4] << 12);
	le64_to_ptr(s + 0, t0);
	le64_to_ptr(s + 8, t1);
	le64_to_ptr(s + 16, t2);
	le64_to_ptr(s + 24, t3);
}

#ifdef __cplusplus
}
#endif

#endif /* FE_H */
