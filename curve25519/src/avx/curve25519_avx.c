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

/*
   This file is adapted from ref10/scalarmult.c:
   The code for Mongomery ladder is replace by the ladder assembly function;
   Inversion is done in the same way as amd64-51/.
   (fe is first converted into fe51 after Mongomery ladder)
*/

#include "cpufeatures.h"
#include "curve25519_avx.h"
#include "ext_headers_x86.h"
#include "fe.h"
#include "fe51.h"
#include "ladder.h"
#include "lc_memset_secure.h"
#include "../x25519_scalarmult.h"
#include "../x25519_scalarmult_c.h"

#define x1 var[0]
#define x2 var[1]
#define z2 var[2]

int crypto_scalarmult_curve25519_avx2(unsigned char *q, const unsigned char *n,
				      const unsigned char *p)
{
	unsigned char t[32];
	fe var[3];
	fe51 x_51;
	fe51 z_51;

	memcpy(t, n, sizeof(t));
	t[0] &= 248;
	t[31] &= 127;
	t[31] |= 64;

	LC_FPU_ENABLE;

	curve25519_fe_frombytes_avx(x1, p);

	curve25519_ladder_avx2(var, t);

	z_51.v[0] = (z2[1] << 26) + z2[0];
	z_51.v[1] = (z2[3] << 26) + z2[2];
	z_51.v[2] = (z2[5] << 26) + z2[4];
	z_51.v[3] = (z2[7] << 26) + z2[6];
	z_51.v[4] = (z2[9] << 26) + z2[8];

	x_51.v[0] = (x2[1] << 26) + x2[0];
	x_51.v[1] = (x2[3] << 26) + x2[2];
	x_51.v[2] = (x2[5] << 26) + x2[4];
	x_51.v[3] = (x2[7] << 26) + x2[6];
	x_51.v[4] = (x2[9] << 26) + x2[8];

	curve25519_fe51_invert_avx(&z_51, &z_51);
	curve25519_fe51_mul_avx(&x_51, &x_51, &z_51);
	curve25519_fe51_pack_avx(q, &x_51);

	LC_FPU_DISABLE;

	lc_memset_secure(t, 0, sizeof(t));

	return 0;
}

int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
				 const unsigned char *p)
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return crypto_scalarmult_curve25519_avx2(q, n, p);
	return crypto_scalarmult_curve25519_c(q, n, p);
}
