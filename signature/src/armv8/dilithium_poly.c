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
 * https://github.com/PQClean/PQClean
 *
 * This file was originally licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html) or
 * public domain at https://github.com/pq-crystals/dilithium/tree/master/ref
 *
 * We choose
 * CC0 1.0 Universal or the following MIT License
 *
 * MIT License
 *
 * Copyright (c) 2023 - 2024: Hanno Becker, Vincent Hwang, Matthias J. Kannwischer, Bo-Yin Yang, and Shang-Yi Yang
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "build_bug_on.h"
#include "dilithium_poly.h"
#include "dilithium_poly_armv8.h"
#include "dilithium_service_helpers.h"
#include "lc_sha3.h"

#include "shake_2x_armv8.h"

static void
dilithium_shake128x2_stream_init(keccakx2_state *state,
				 const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
				 uint16_t nonce1, uint16_t nonce2, void *ws_buf)
{
#define LC_DILITHIUM_SHAKE128X2_BUF (LC_DILITHIUM_SEEDBYTES + 2 + 14)
	uint8_t *extseed1 = ws_buf,
		*extseed2 = extseed1 + LC_DILITHIUM_SHAKE128X2_BUF;

	/*
	 * We require 2 LC_DILITHIUM_SHAKE128X2_BUF, and ws_buf has twice
	 * (POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2).
	 */
	BUILD_BUG_ON(LC_DILITHIUM_SHAKE128X2_BUF >
		     (POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2));

	memcpy(extseed1, seed, LC_DILITHIUM_SEEDBYTES);
	memcpy(extseed2, seed, LC_DILITHIUM_SEEDBYTES);

	extseed1[LC_DILITHIUM_SEEDBYTES] = (uint8_t)nonce1;
	extseed1[LC_DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce1 >> 8);

	extseed2[LC_DILITHIUM_SEEDBYTES] = (uint8_t)nonce2;
	extseed2[LC_DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce2 >> 8);

	shake128x2_armv8_absorb(state, extseed1, extseed2,
				LC_DILITHIUM_SEEDBYTES + 2);

#undef LC_DILITHIUM_SHAKE128X2_BUF
}

static void
dilithium_shake256x2_stream_init(keccakx2_state *state,
				 const uint8_t seed[LC_DILITHIUM_CRHBYTES],
				 uint16_t nonce1, uint16_t nonce2, void *ws_buf)
{
#define LC_DILITHIUM_SHAKE256X2_BUF (LC_DILITHIUM_CRHBYTES + 2 + 14)
	uint8_t *extseed1 = ws_buf,
		*extseed2 = extseed1 + LC_DILITHIUM_SHAKE256X2_BUF;

	/*
	 * We require 2 LC_DILITHIUM_SHAKE128X2_BUF, and ws_buf has twice
	 * (POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2).
	 */
	BUILD_BUG_ON(LC_DILITHIUM_SHAKE256X2_BUF >
		     (POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2));

	memcpy(extseed1, seed, LC_DILITHIUM_CRHBYTES);
	memcpy(extseed2, seed, LC_DILITHIUM_CRHBYTES);

	extseed1[LC_DILITHIUM_CRHBYTES] = (uint8_t)nonce1;
	extseed1[LC_DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce1 >> 8);

	extseed2[LC_DILITHIUM_CRHBYTES] = (uint8_t)nonce2;
	extseed2[LC_DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce2 >> 8);

	shake256x2_armv8_absorb(state, extseed1, extseed2,
				LC_DILITHIUM_CRHBYTES + 2);

#undef LC_DILITHIUM_SHAKE256X2_BUF
}

void poly_uniformx2(poly *a0, poly *a1,
		    const uint8_t seed[LC_DILITHIUM_SEEDBYTES], uint16_t nonce0,
		    uint16_t nonce1, void *ws_buf)
{
#define LC_POLY_UNIFORMX2_BUF (POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK)
	unsigned int ctr0, ctr1;
	uint8_t *buf0 = ws_buf, *buf1 = buf0 + (LC_POLY_UNIFORMX2_BUF + 2);
	keccakx2_state statex2;

	dilithium_shake128x2_stream_init(&statex2, seed, nonce0, nonce1,
					 ws_buf);
	shake128x2_armv8_squeezeblocks(buf0, buf1, POLY_UNIFORM_NBLOCKS,
				       &statex2);

	ctr0 = rej_uniform(a0->coeffs, LC_DILITHIUM_N, buf0,
			   LC_POLY_UNIFORMX2_BUF);
	ctr1 = rej_uniform(a1->coeffs, LC_DILITHIUM_N, buf1,
			   LC_POLY_UNIFORMX2_BUF);

	while (ctr0 < LC_DILITHIUM_N || ctr1 < LC_DILITHIUM_N) {
		shake128x2_armv8_squeezeblocks(buf0, buf1, 1, &statex2);
		ctr0 += rej_uniform(a0->coeffs + ctr0, LC_DILITHIUM_N - ctr0,
				    buf0, LC_POLY_UNIFORMX2_BUF);
		ctr1 += rej_uniform(a1->coeffs + ctr1, LC_DILITHIUM_N - ctr1,
				    buf1, LC_POLY_UNIFORMX2_BUF);
	}

	lc_memset_secure(&statex2, 0, sizeof(statex2));

#undef LC_POLY_UNIFORMX2_BUF
}

void poly_uniform_etax2(poly *a0, poly *a1,
			const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			uint16_t nonce0, uint16_t nonce1, void *ws_buf)
{
#define LC_POLY_UNIFORM_ETAX2_BUF                                              \
	(POLY_UNIFORM_ETA_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK)
	unsigned int ctr0, ctr1;
	uint8_t *buf0 = ws_buf, *buf1 = buf0 + LC_POLY_UNIFORM_ETAX2_BUF;
	keccakx2_state statex2;

	dilithium_shake256x2_stream_init(&statex2, seed, nonce0, nonce1,
					 ws_buf);
	shake256x2_armv8_squeezeblocks(buf0, buf1, POLY_UNIFORM_ETA_NBLOCKS,
				       &statex2);

	ctr0 = rej_eta(a0->coeffs, LC_DILITHIUM_N, buf0,
		       LC_POLY_UNIFORM_ETAX2_BUF);
	ctr1 = rej_eta(a1->coeffs, LC_DILITHIUM_N, buf1,
		       LC_POLY_UNIFORM_ETAX2_BUF);

	while (ctr0 < LC_DILITHIUM_N || ctr1 < LC_DILITHIUM_N) {
		shake256x2_armv8_squeezeblocks(buf0, buf1, 1, &statex2);
		ctr0 += rej_eta(a0->coeffs + ctr0, LC_DILITHIUM_N - ctr0, buf0,
				LC_SHAKE_256_SIZE_BLOCK);
		ctr1 += rej_eta(a1->coeffs + ctr1, LC_DILITHIUM_N - ctr1, buf1,
				LC_SHAKE_256_SIZE_BLOCK);
	}

	lc_memset_secure(&statex2, 0, sizeof(statex2));

#undef LC_POLY_UNIFORM_ETAX2_BUF
}

void poly_uniform_gamma1x2(poly *a0, poly *a1,
			   const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			   uint16_t nonce0, uint16_t nonce1, void *ws_buf)
{
	uint8_t *buf0 = ws_buf, *buf1 = buf0 + (POLY_UNIFORM_GAMMA1_NBLOCKS *
						LC_SHAKE_256_SIZE_BLOCK);
	keccakx2_state statex2;

	dilithium_shake256x2_stream_init(&statex2, seed, nonce0, nonce1,
					 ws_buf);
	shake256x2_armv8_squeezeblocks(buf0, buf1, POLY_UNIFORM_GAMMA1_NBLOCKS,
				       &statex2);

	polyz_unpack(a0, buf0);
	polyz_unpack(a1, buf1);

	lc_memset_secure(&statex2, 0, sizeof(statex2));
}
