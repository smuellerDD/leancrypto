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
#ifndef KYBER_NTT_AVX2_H
#define KYBER_NTT_AVX2_H

#include <stdint.h>
#include <immintrin.h>

#ifdef __cplusplus
extern "C"
{
#endif

void ntt_avx(__m256i *r, const __m256i *qdata);
void invntt_avx(__m256i *r, const __m256i *qdata);

void nttpack_avx(__m256i *r, const __m256i *qdata);
void nttunpack_avx(__m256i *r, const __m256i *qdata);

void basemul_avx(__m256i *r,
		 const __m256i *a,
		 const __m256i *b,
		 const __m256i *qdata);

void ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *qdata);
void nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *qdata);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_NTT_AVX2_H */
