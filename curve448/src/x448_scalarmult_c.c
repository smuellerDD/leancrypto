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
 * This code is derived in parts from
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 * Modifications Copyright 2020 David Schatz
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#include "lc_memset_secure.h"
#include "lc_memcpy_secure.h"
#include "point_448.h"
#include "sidechannel_resistance.h"
#include "timecop.h"
#include "x448_scalarmult_c.h"

#define LC_X448_SECRETKEYBITS (LC_X448_SECRETKEYBYTES << 3)

/*
 * RFC 7748 Diffie-Hellman base point scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * out (out): The scaled point base*scalar
 * scalar (in): The scalar to multiply by.
 */
void x448_derive_public_key_c(uint8_t out[LC_X448_PUBLICKEYBYTES],
			      const uint8_t scalar[LC_X448_SECRETKEYBYTES])
{
	/* Scalar conditioning */
	uint8_t scalar2[LC_X448_SECRETKEYBYTES];
	curve448_scalar_t the_scalar;
	curve448_point_t p;
	unsigned int i;

	memcpy(scalar2, scalar, sizeof(scalar2));
	scalar2[0] &= 252;
	scalar2[LC_X448_SECRETKEYBYTES - 1] |= 128;

	scalar2[0] &= (uint8_t)-COFACTOR;

	scalar2[LC_X448_SECRETKEYBYTES - 1] &=
		~((0u - 1u) << ((LC_X448_SECRETKEYBITS + 7) % 8));
	scalar2[LC_X448_SECRETKEYBYTES - 1] |=
		1 << ((LC_X448_SECRETKEYBITS + 7) % 8);

	curve448_scalar_decode_long(the_scalar, scalar2, sizeof(scalar2));

	/* Compensate for the encoding ratio */
	for (i = 1; i < X448_ENCODE_RATIO; i <<= 1)
		curve448_scalar_halve(the_scalar, the_scalar);

	curve448_precomputed_scalarmul(p, curve448_precomputed_base,
				       the_scalar);
	curve448_point_mul_by_ratio_and_encode_like_x448(out, p);
	curve448_point_destroy(p);

	lc_memset_secure(scalar2, 0, sizeof(scalar2));
	lc_memset_secure(the_scalar, 0, sizeof(the_scalar));
}

/*
 * RFC 7748 Diffie-Hellman scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * out (out): The scaled point base*scalar
 * base (in): The point to be scaled.
 * scalar (in): The scalar to multiply by.
 *
 * Returns:
 * 0: The scalarmul succeeded.
 * < 0: The scalarmul didn't succeed, because the base point is in a
 * small subgroup.
 */
int x448_scalarmult_c(uint8_t out[LC_X448_PUBLICKEYBYTES],
		      const uint8_t base[LC_X448_PUBLICKEYBYTES],
		      const uint8_t scalar[LC_X448_SECRETKEYBYTES])
{
	uint8_t scalar_tmp[LC_X448_SECRETKEYBYTES];
	gf x1, x2, z2, x3, z3, t1, t2;
	int t, ret = 0;
	mask_t swap = 0;

	memcpy(scalar_tmp, scalar, sizeof(scalar_tmp));
	scalar_tmp[0] &= 252;
	scalar_tmp[LC_X448_SECRETKEYBYTES - 1] |= 128;

	(void)gf_deserialize(x1, base, 1, 0);
	gf_copy(x2, ONE);
	gf_copy(z2, ZERO);
	gf_copy(x3, x1);
	gf_copy(z3, ONE);

	for (t = LC_X448_SECRETKEYBITS - 1; t >= 0; t--) {
		uint8_t sb = scalar_tmp[t / 8];
		mask_t k_t;

		/* Scalar conditioning */
		if (t / 8 == 0)
			sb &= (uint8_t)-COFACTOR;
		else if (t == LC_X448_SECRETKEYBITS - 1)
			sb = (uint8_t)-1;

		k_t = (sb >> (t % 8)) & 1;
		k_t = 0 - k_t; /* set to all 0s or all 1s */

		swap ^= k_t;
		gf_cond_swap(x2, x3, swap);
		gf_cond_swap(z2, z3, swap);
		swap = k_t;

		/*
		 * The "_nr" below skips coefficient reduction. In the following
		 * comments, "2+e" is saying that the coefficients are at most
		 * 2+epsilon times the reduction limit.
		 */
		gf_add_nr(t1, x2, z2); /* A = x2 + z2 */ /* 2+e */
		gf_sub_nr(t2, x2, z2); /* B = x2 - z2 */ /* 3+e */
		gf_sub_nr(z2, x3, z3); /* D = x3 - z3 */ /* 3+e */
		gf_mul(x2, t1, z2); /* DA */
		gf_add_nr(z2, z3, x3); /* C = x3 + z3 */ /* 2+e */
		gf_mul(x3, t2, z2); /* CB */
		gf_sub_nr(z3, x2, x3); /* DA-CB */ /* 3+e */
		gf_sqr(z2, z3); /* (DA-CB)^2 */
		gf_mul(z3, x1, z2); /* z3 = x1(DA-CB)^2 */
		gf_add_nr(z2, x2, x3); /* (DA+CB) */ /* 2+e */
		gf_sqr(x3, z2); /* x3 = (DA+CB)^2 */

		gf_sqr(z2, t1); /* AA = A^2 */
		gf_sqr(t1, t2); /* BB = B^2 */
		gf_mul(x2, z2, t1); /* x2 = AA*BB */
		gf_sub_nr(t2, z2, t1); /* E = AA-BB */ /* 3+e */

		gf_mulw(t1, t2, -EDWARDS_D); /* E*-d = a24*E */
		gf_add_nr(t1, t1, z2); /* AA + a24*E */ /* 2+e */
		gf_mul(z2, t2, t1); /* z2 = E(AA+a24*E) */
	}

	/* Finish */
	gf_cond_swap(x2, x3, swap);
	gf_cond_swap(z2, z3, swap);
	gf_invert(z2, z2);
	gf_mul(x1, x2, z2);
	gf_serialize(out, x1, 1);

	/*
	 * Side channel countermeasure: the result of the gf_eq depends on
	 * the secret key.
	 */
	cmov_int(&ret, -EFAULT, !!gf_eq(x1, ZERO));
	unpoison(&ret, sizeof(ret));

	lc_memset_secure(scalar_tmp, 0, sizeof(scalar_tmp));
	lc_memset_secure(x1, 0, sizeof(x1));
	lc_memset_secure(x2, 0, sizeof(x2));
	lc_memset_secure(z2, 0, sizeof(z2));
	lc_memset_secure(x3, 0, sizeof(x3));
	lc_memset_secure(z3, 0, sizeof(z3));
	lc_memset_secure(t1, 0, sizeof(t1));
	lc_memset_secure(t2, 0, sizeof(t2));

	return ret;
}
