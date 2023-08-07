/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "dilithium_pack_avx2.h"
#include "dilithium_poly_avx2.h"
#include "lc_dilithium.h"

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param rho [out] output byte array for rho
 * @param tr [out] output byte array for tr
 * @param key [out] output byte array for key
 * @param t0 [out] pointer to output vector t0
 * @param s1 [out] pointer to output vector s1
 * @param s2 [out] pointer to output vector s2
 * @param sk [in] byte array containing bit-packed sk
 */
void unpack_sk_avx2(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
		    uint8_t tr[LC_DILITHIUM_SEEDBYTES],
		    uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0,
		    polyvecl *s1, polyveck *s2,
		    const uint8_t sk[LC_DILITHIUM_SECRETKEYBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		rho[i] = sk[i];
	sk += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		key[i] = sk[i];
	sk += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		tr[i] = sk[i];
	sk += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_unpack_avx(&s1->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	sk += LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_unpack_avx(&s2->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	sk += LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_unpack_avx(&t0->vec[i],
				  sk + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
}

void unpack_sk_avx2_tr(uint8_t tr[LC_DILITHIUM_SEEDBYTES],
		       const struct lc_dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		tr[i] = seckey[i];
}

void unpack_sk_avx2_ex_tr(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
			  uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0,
			  polyvecl *s1, polyveck *s2,
			  const uint8_t sk[LC_DILITHIUM_SECRETKEYBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		rho[i] = sk[i];
	sk += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		key[i] = sk[i];
	sk += LC_DILITHIUM_SEEDBYTES;

	/* Skip tr */
	sk += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_unpack_avx(&s1->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	sk += LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_unpack_avx(&s2->vec[i],
				   sk + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	sk += LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_unpack_avx(&t0->vec[i],
				  sk + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
}
