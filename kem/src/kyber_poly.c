/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "kyber_cbd.h"
#include "kyber_kdf.h"
#include "kyber_poly.h"

#include "lc_sha3.h"

void poly_getnoise_eta1(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			uint8_t nonce, void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA1_BUFSIZE, seed, nonce);
	poly_cbd_eta1(r, buf);
}

void poly_getnoise_eta2(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			uint8_t nonce, void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA2_BUFSIZE, seed, nonce);
	poly_cbd_eta2(r, buf);
}

void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
	r[0] = fqmul(a[1], b[1]);
	r[0] = fqmul(r[0], zeta);
	r[0] += fqmul(a[0], b[0]);
	r[1] = fqmul(a[0], b[1]);
	r[1] += fqmul(a[1], b[0]);
}
