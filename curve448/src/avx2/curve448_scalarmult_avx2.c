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
+-----------------------------------------------------------------------------+
| This code corresponds to the the paper "Efficient 4-way Vectorizations of   |
| the Montgomery Ladder" authored by   			       	       	      |
| Kaushik Nath,  Indian Statistical Institute, Kolkata, India, and            |
| Palash Sarkar, Indian Statistical Institute, Kolkata, India.	              |
+-----------------------------------------------------------------------------+
| Copyright (c) 2020, Kaushik Nath and Palash Sarkar.                         |
|                                                                             |
| Permission to use this code is granted.                          	      |
|                                                                             |
| Redistribution and use in source and binary forms, with or without          |
| modification, are permitted provided that the following conditions are      |
| met:                                                                        |
|                                                                             |
| * Redistributions of source code must retain the above copyright notice,    |
|   this list of conditions and the following disclaimer.                     |
|                                                                             |
| * Redistributions in binary form must reproduce the above copyright         |
|   notice, this list of conditions and the following disclaimer in the       |
|   documentation and/or other materials provided with the distribution.      |
|                                                                             |
| * The names of the contributors may not be used to endorse or promote       |
|   products derived from this software without specific prior written        |
|   permission.                                                               |
+-----------------------------------------------------------------------------+
| THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY EXPRESS OR       |
| IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES   |
| OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.     |
| IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,      |
| INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT    |
| NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   |
| DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY       |
| THEORY LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING |
| NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,| 
| EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                          |
+-----------------------------------------------------------------------------+
*/

#include "cpufeatures.h"
#include "ext_headers_x86.h"
#include "gf_p4482241_type.h"
#include "gf_p4482241_pack.h"
#include "gf_p4482241_arith.h"
#include "lc_memcpy_secure.h"
#include "lc_memset_secure.h"
#include "lc_x448.h"
#include "small_stack_support.h"
#include "../x448_scalarmult.h"
#include "../x448_scalarmult_c.h"

static const uint8_t curve448_base_point[LC_X448_PUBLICKEYBYTES] = { 5 };

extern void SYSV_ABI curve448_mladder_avx2(vec *, const vec *, const uint8_t *);
extern void SYSV_ABI curve448_mladder_base_avx2(vec *, const vec,
						const uint8_t *);

static int curve448_scalarmult_avx2(uint8_t *out, const uint8_t *base,
				    const uint8_t *scalar)
{
	vec r[NLIMBS_VEC] ALIGN32 = { 0 };
	vec t[NLIMBS_VEC] ALIGN32 = { 0 };
	struct workspace {
		gfe_p4482241_16L u, v;
		gfe_p4482241_7L w, x, z;
		gfe_p4482241_8L a, b, c, binv;
		uint8_t s[LC_X448_SECRETKEYBYTES];
	};
	uint8_t i;
	LC_DECLARE_MEM(ws, struct workspace, 32);

	memcpy(ws->s, scalar, sizeof(ws->s));
	ws->s[LC_X448_SECRETKEYBYTES - 1] =
		ws->s[LC_X448_SECRETKEYBYTES - 1] | 0x80;
	ws->s[0] = ws->s[0] & 0xFC;

	LC_FPU_ENABLE;

	gfp4482241pack(&ws->u, base);

	t[0][0] = t[0][3] = r[0][2] = 1;

	for (i = 0; i < NLIMBS_VEC; ++i) {
		t[i][2] = ws->u.l[i];
		r[i][3] = ws->u.l[i];
	}

	curve448_mladder_avx2(t, (const vec *)r, ws->s);

	for (i = 0; i < NLIMBS_VEC; ++i) {
		ws->u.l[i] = t[i][0];
		ws->v.l[i] = t[i][1];
	}

	gfp4482241pack167(&ws->x, &ws->u);
	gfp4482241pack167(&ws->z, &ws->v);

	gfp4482241pack78(&ws->a, &ws->x);
	gfp4482241pack78(&ws->b, &ws->z);
	gfp4482241inv(&ws->binv, &ws->b);
	gfp4482241mul(&ws->c, &ws->binv, &ws->a);
	gfp4482241reduce(&ws->c);
	gfp4482241pack87(&ws->w, &ws->c);

	gfp4482241makeunique(&ws->w);
	gfp4482241unpack(out, &ws->w);

	LC_FPU_DISABLE;

	LC_RELEASE_MEM(ws);
	return 0;
}

int x448_scalarmult(uint8_t out[LC_X448_PUBLICKEYBYTES],
		    const uint8_t base[LC_X448_PUBLICKEYBYTES],
		    const uint8_t scalar[LC_X448_SECRETKEYBYTES])
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return curve448_scalarmult_avx2(out, base, scalar);
	return x448_scalarmult_c(out, base, scalar);
}

static int curve448_scalarmult_base_avx2(uint8_t *out, const uint8_t *base,
					 const uint8_t *scalar)
{
	vec r ALIGN32 = { 0 };
	vec t[NLIMBS_VEC] ALIGN32 = { 0 };
	struct workspace {
		gfe_p4482241_16L u, v;
		gfe_p4482241_7L w, x, z;
		gfe_p4482241_8L a, b, c, binv;
		uint8_t s[LC_X448_SECRETKEYBYTES];
	};
	uint8_t i;
	LC_DECLARE_MEM(ws, struct workspace, 32);

	memcpy(ws->s, scalar, sizeof(ws->s));
	ws->s[LC_X448_SECRETKEYBYTES - 1] =
		ws->s[LC_X448_SECRETKEYBYTES - 1] | 0x80;
	ws->s[0] = ws->s[0] & 0xFC;

	LC_FPU_ENABLE;

	gfp4482241pack(&ws->u, base);

	t[0][0] = t[0][3] = r[0] = r[1] = r[2] = 1;
	r[3] = ws->u.l[0];

	for (i = 0; i < NLIMBS_VEC; ++i)
		t[i][2] = ws->u.l[i];

	curve448_mladder_base_avx2(t, r, ws->s);

	for (i = 0; i < NLIMBS_VEC; ++i) {
		ws->u.l[i] = t[i][0];
		ws->v.l[i] = t[i][1];
	}

	gfp4482241pack167(&ws->x, &ws->u);
	gfp4482241pack167(&ws->z, &ws->v);

	gfp4482241pack78(&ws->a, &ws->x);
	gfp4482241pack78(&ws->b, &ws->z);
	gfp4482241inv(&ws->binv, &ws->b);
	gfp4482241mul(&ws->c, &ws->binv, &ws->a);
	gfp4482241reduce(&ws->c);
	gfp4482241pack87(&ws->w, &ws->c);

	gfp4482241makeunique(&ws->w);
	gfp4482241unpack(out, &ws->w);

	LC_FPU_DISABLE;

	LC_RELEASE_MEM(ws);
	return 0;
}

int x448_derive_public_key(uint8_t out[LC_X448_PUBLICKEYBYTES],
			   const uint8_t scalar[LC_X448_SECRETKEYBYTES])
{
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) {
		return curve448_scalarmult_base_avx2(out, curve448_base_point,
						     scalar);
	}

	x448_derive_public_key_c(out, scalar);
	return 0;
}
