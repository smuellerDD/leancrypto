/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 *
 * This code is derived from the file
 * https://github.com/ascon/ascon-c/crypto_aead/ascon128v12/avx512/round.h
 * which is subject to the following license:
 *
 * CC0 1.0 Universal
 */

#ifndef ROUND_H_
#define ROUND_H_

#include "ascon_hash.h"
#include "ext_headers_x86.h"

static const __mmask8 mxor1 = 0x15;
static const __mmask8 mxor2 = 0x0b;

static inline void ascon_permutation_one_avx512(__m512i *z, long long C)
{
	const __m512i c = _mm512_set_epi64(0, 0, 0, 0, 0, C, 0, 0);
	const __m512i pxor1 = _mm512_set_epi64(0, 0, 0, 3, 0, 1, 0, 4);
	const __m512i pxor2 = _mm512_set_epi64(0, 0, 0, 0, 2, 0, 0, 4);
	const __m512i n = _mm512_set_epi64(0, 0, 0, 0, 0, ~0ll, 0, 0);
	const __m512i pchi1 = _mm512_set_epi64(0, 0, 0, 0, 4, 3, 2, 1);
	const __m512i pchi2 = _mm512_set_epi64(0, 0, 0, 1, 0, 4, 3, 2);
	const __m512i rot1 = _mm512_set_epi64(0, 0, 0, 7, 10, 1, 61, 19);
	const __m512i rot2 = _mm512_set_epi64(0, 0, 0, 41, 17, 6, 39, 28);
	__m512i t0, t1, t2;

	/* round constant + s-box layer */
	t0 = _mm512_maskz_permutexvar_epi64(mxor1, pxor1, *z);
	t0 = _mm512_ternarylogic_epi64(*z, t0, c, 0x96);
	/* keccak s-box start */
	t1 = _mm512_permutexvar_epi64(pchi1, t0);
	t2 = _mm512_permutexvar_epi64(pchi2, t0);
	t0 = _mm512_ternarylogic_epi64(t0, t1, t2, 0xd2);
	/* keccak s-box end */
	t1 = _mm512_maskz_permutexvar_epi64(mxor2, pxor2, t0);
	t0 = _mm512_ternarylogic_epi64(t0, t1, n, 0x96);
	/* linear layer */
	t1 = _mm512_rorv_epi64(t0, rot1);
	t2 = _mm512_rorv_epi64(t0, rot2);
	*z = _mm512_ternarylogic_epi64(t0, t1, t2, 0x96);
}

#endif /* ROUND_H_ */
