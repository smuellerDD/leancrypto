/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * Copyright (c) 2013-2023 - 2024
 * Frank Denis <j at pureftpd dot org>
 */

/*
   This file is adapted from amd64-51/fe25519_invert.c:
   Loops of squares are replaced by nsquares for better performance.
*/

#include "fe51.h"

#define fe51_square(x, y) curve25519_fe51_nsquare_avx(x, y, 1)

void curve25519_fe51_invert_avx(fe51 *r, const fe51 *x)
{
	fe51 z2;
	fe51 z9;
	fe51 z11;
	fe51 z2_5_0;
	fe51 z2_10_0;
	fe51 z2_20_0;
	fe51 z2_50_0;
	fe51 z2_100_0;
	fe51 t;

	/* 2 */ fe51_square(&z2, x);
	/* 4 */ fe51_square(&t, &z2);
	/* 8 */ fe51_square(&t, &t);
	/* 9 */ curve25519_fe51_mul_avx(&z9, &t, x);
	/* 11 */ curve25519_fe51_mul_avx(&z11, &z9, &z2);
	/* 22 */ fe51_square(&t, &z11);
	/* 2^5 - 2^0 = 31 */ curve25519_fe51_mul_avx(&z2_5_0, &t, &z9);

	/* 2^10 - 2^5 */ curve25519_fe51_nsquare_avx(&t, &z2_5_0, 5);
	/* 2^10 - 2^0 */ curve25519_fe51_mul_avx(&z2_10_0, &t, &z2_5_0);

	/* 2^20 - 2^10 */ curve25519_fe51_nsquare_avx(&t, &z2_10_0, 10);
	/* 2^20 - 2^0 */ curve25519_fe51_mul_avx(&z2_20_0, &t, &z2_10_0);

	/* 2^40 - 2^20 */ curve25519_fe51_nsquare_avx(&t, &z2_20_0, 20);
	/* 2^40 - 2^0 */ curve25519_fe51_mul_avx(&t, &t, &z2_20_0);

	/* 2^50 - 2^10 */ curve25519_fe51_nsquare_avx(&t, &t, 10);
	/* 2^50 - 2^0 */ curve25519_fe51_mul_avx(&z2_50_0, &t, &z2_10_0);

	/* 2^100 - 2^50 */ curve25519_fe51_nsquare_avx(&t, &z2_50_0, 50);
	/* 2^100 - 2^0 */ curve25519_fe51_mul_avx(&z2_100_0, &t, &z2_50_0);

	/* 2^200 - 2^100 */ curve25519_fe51_nsquare_avx(&t, &z2_100_0, 100);
	/* 2^200 - 2^0 */ curve25519_fe51_mul_avx(&t, &t, &z2_100_0);

	/* 2^250 - 2^50 */ curve25519_fe51_nsquare_avx(&t, &t, 50);
	/* 2^250 - 2^0 */ curve25519_fe51_mul_avx(&t, &t, &z2_50_0);

	/* 2^255 - 2^5 */ curve25519_fe51_nsquare_avx(&t, &t, 5);
	/* 2^255 - 21 */ curve25519_fe51_mul_avx(r, &t, &z11);
}
