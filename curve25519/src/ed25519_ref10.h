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

#ifndef ED25519_REF10_H
#define ED25519_REF10_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 fe means field element.
 Here the field is \Z/(2^255-19).
 */
#ifdef LC_HOST_X86_64
typedef unsigned int uint128_t __attribute__((mode(TI)));
typedef uint64_t fe25519[5];
#else
typedef int32_t fe25519[10];
#endif

void fe25519_invert(fe25519 out, const fe25519 z);
void fe25519_frombytes(fe25519 h, const unsigned char *s);
void fe25519_tobytes(unsigned char *s, const fe25519 h);

#ifdef LC_HOST_X86_64
#include "ed25519_ref10_fe_51.h"
#else
#include "ed25519_ref10_fe_25_5.h"
#endif

/*
 ge means group element.

 Here the group is the set of pairs (x,y) of field elements
 satisfying -x^2 + y^2 = 1 + d x^2y^2
 where d = -121665/121666.

 Representations:
 ge25519_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 ge25519_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 ge25519_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 ge25519_precomp (Duif): (y+x,y-x,2dxy)
 */

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
} ge25519_p2;

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
} ge25519_p3;

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
} ge25519_p1p1;

typedef struct {
	fe25519 yplusx;
	fe25519 yminusx;
	fe25519 xy2d;
} ge25519_precomp;

typedef struct {
	fe25519 YplusX;
	fe25519 YminusX;
	fe25519 Z;
	fe25519 T2d;
} ge25519_cached;

void ge25519_tobytes(unsigned char *s, const ge25519_p2 *h);

void ge25519_p3_tobytes(unsigned char *s, const ge25519_p3 *h);

unsigned int ge25519_frombytes(ge25519_p3 *h, const unsigned char *s);

int ge25519_frombytes_negate_vartime(ge25519_p3 *h, const unsigned char *s);

void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p);

void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p);

void ge25519_p2_to_p3(ge25519_p3 *r, const ge25519_p2 *p);

void ge25519_p3_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q);

void ge25519_p3_sub(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q);

void ge25519_scalarmult_base(ge25519_p3 *h, const unsigned char *a);

void ge25519_double_scalarmult_vartime(ge25519_p2 *r, const unsigned char *a,
				       const ge25519_p3 *A,
				       const unsigned char *b);

void ge25519_scalarmult(ge25519_p3 *h, const unsigned char *a,
			const ge25519_p3 *p);

void ge25519_clear_cofactor(ge25519_p3 *p3);

int ge25519_is_canonical(const unsigned char *s);

unsigned int ge25519_is_on_curve(const ge25519_p3 *p);

unsigned int ge25519_is_on_main_subgroup(const ge25519_p3 *p);

unsigned int ge25519_has_small_order(const ge25519_p3 *p);

void ge25519_from_uniform(unsigned char s[32], const unsigned char r[32]);

void ge25519_from_hash(unsigned char s[32], const unsigned char h[64]);

/*
 Ristretto group
 */

int ristretto255_frombytes(ge25519_p3 *h, const unsigned char *s);

void ristretto255_p3_tobytes(unsigned char *s, const ge25519_p3 *h);

void ristretto255_from_hash(unsigned char s[32], const unsigned char h[64]);

/*
 The set of scalars is \Z/l
 where l = 2^252 + 27742317777372353535851937790883648493.
 */

void sc25519_invert(unsigned char recip[32], const unsigned char s[32]);

void sc25519_reduce(unsigned char s[64]);

void sc25519_mul(unsigned char s[32], const unsigned char a[32],
		 const unsigned char b[32]);

void sc25519_muladd(unsigned char s[32], const unsigned char a[32],
		    const unsigned char b[32], const unsigned char c[32]);

int sc25519_is_canonical(const unsigned char s[32]);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_REF10_H */
