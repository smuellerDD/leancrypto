/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_POLY_AVX2_H
#define KYBER_POLY_AVX2_H

#include "kyber_align_avx2.h"
#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef ALIGNED_INT16(LC_KYBER_N) poly;

void poly_compress_avx(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress_avx(poly *r,
			 const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES]);

void poly_tobytes_avx(uint8_t r[LC_KYBER_POLYBYTES], const poly *a);
void poly_frombytes_avx(poly *r, const uint8_t a[LC_KYBER_POLYBYTES]);

void poly_frommsg_avx(poly *r, const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES]);
void poly_tomsg_avx(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES], const poly *r);

void poly_getnoise_eta1_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			    uint8_t nonce);

void poly_getnoise_eta2_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			    uint8_t nonce);

void poly_getnoise_eta1_4x(poly *r0,
			   poly *r1,
			   poly *r2,
			   poly *r3,
			   const uint8_t seed[32],
			   uint8_t nonce0,
			   uint8_t nonce1,
			   uint8_t nonce2,
			   uint8_t nonce3);

void poly_ntt_avx(poly *r);
void poly_invntt_tomont_avx(poly *r);
void poly_nttunpack_avx(poly *r);
void poly_basemul_montgomery_avx(poly *r, const poly *a, const poly *b);
void poly_tomont_avx(poly *r);

void poly_reduce_avx(poly *r);

void poly_add_avx(poly *r, const poly *a, const poly *b);
void poly_sub_avx(poly *r, const poly *a, const poly *b);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_AVX2_H */
