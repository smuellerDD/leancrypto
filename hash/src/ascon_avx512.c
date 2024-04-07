/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "asm/ascon_avx512/round.h"

#include "ascon_avx512.h"
#include "ascon_hash.h"
#include "ascon_hash_common.h"
#include "lc_ascon_hash.h"
#include "visibility.h"

static inline void
ascon_permutation_6(uint64_t s[LC_ASCON_HASH_STATE_WORDS + 3])
{
	__m512i *z = (void *)s;
	__m512i pxor1 = _mm512_set_epi64(0, 0, 0, 3, 0, 1, 0, 4);
	__m512i pxor2 = _mm512_set_epi64(0, 0, 0, 0, 2, 0, 0, 4);
	__m512i n = _mm512_set_epi64(0, 0, 0, 0, 0, ~0ll, 0, 0);
	__m512i pchi1 = _mm512_set_epi64(0, 0, 0, 0, 4, 3, 2, 1);
	__m512i pchi2 = _mm512_set_epi64(0, 0, 0, 1, 0, 4, 3, 2);
	__m512i rot1 = _mm512_set_epi64(0, 0, 0, 7, 10, 1, 61, 19);
	__m512i rot2 = _mm512_set_epi64(0, 0, 0, 41, 17, 6, 39, 28);

	ascon_permutation_one_avx512(z, 0x96, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x87, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x78, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x69, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x5a, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x4b, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
}

static inline void
ascon_permutation_8(uint64_t s[LC_ASCON_HASH_STATE_WORDS + 3])
{
	__m512i *z = (void *)s;
	__m512i pxor1 = _mm512_set_epi64(0, 0, 0, 3, 0, 1, 0, 4);
	__m512i pxor2 = _mm512_set_epi64(0, 0, 0, 0, 2, 0, 0, 4);
	__m512i n = _mm512_set_epi64(0, 0, 0, 0, 0, ~0ll, 0, 0);
	__m512i pchi1 = _mm512_set_epi64(0, 0, 0, 0, 4, 3, 2, 1);
	__m512i pchi2 = _mm512_set_epi64(0, 0, 0, 1, 0, 4, 3, 2);
	__m512i rot1 = _mm512_set_epi64(0, 0, 0, 7, 10, 1, 61, 19);
	__m512i rot2 = _mm512_set_epi64(0, 0, 0, 41, 17, 6, 39, 28);

	ascon_permutation_one_avx512(z, 0xb4, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xa5, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x96, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x87, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x78, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x69, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x5a, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x4b, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
}

static inline void
ascon_permutation_12(uint64_t s[LC_ASCON_HASH_STATE_WORDS + 3])
{
	__m512i *z = (void *)s;
	__m512i pxor1 = _mm512_set_epi64(0, 0, 0, 3, 0, 1, 0, 4);
	__m512i pxor2 = _mm512_set_epi64(0, 0, 0, 0, 2, 0, 0, 4);
	__m512i n = _mm512_set_epi64(0, 0, 0, 0, 0, ~0ll, 0, 0);
	__m512i pchi1 = _mm512_set_epi64(0, 0, 0, 0, 4, 3, 2, 1);
	__m512i pchi2 = _mm512_set_epi64(0, 0, 0, 1, 0, 4, 3, 2);
	__m512i rot1 = _mm512_set_epi64(0, 0, 0, 7, 10, 1, 61, 19);
	__m512i rot2 = _mm512_set_epi64(0, 0, 0, 41, 17, 6, 39, 28);

	ascon_permutation_one_avx512(z, 0xf0, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xe1, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xd2, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xc3, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xb4, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0xa5, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x96, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x87, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x78, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x69, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x5a, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
	ascon_permutation_one_avx512(z, 0x4b, pxor1, pxor2, n, pchi1, pchi2,
				     rot1, rot2);
}

static void ascon_avx512_permutation(void *state, unsigned int rounds)
{
	switch (rounds) {
	case 12:
		ascon_permutation_12((uint64_t *)state);
		break;
	case 8:
		ascon_permutation_8((uint64_t *)state);
		break;
	case 6:
		ascon_permutation_6((uint64_t *)state);
		break;
	default:
		break;
	}
}

static void ascon_absorb(void *state, const uint8_t *in, size_t inlen)
{
	ascon_absorb_common(state, in, inlen, ascon_avx512_permutation);
}

static void ascon_squeeze(void *state, uint8_t *digest)
{
	ascon_squeeze_common(state, digest, ascon_permutation_12,
			     ascon_avx512_permutation);
}

static const struct lc_hash _ascon_128_avx512 = {
	.init = ascon_128_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_avx512_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_128_avx512) = &_ascon_128_avx512;

static const struct lc_hash _ascon_128a_avx512 = {
	.init = ascon_128a_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_avx512_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 128 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_128a_avx512) = &_ascon_128a_avx512;

static const struct lc_hash _ascon_xof_avx512 = {
	.init = ascon_xof_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_avx512_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_xof_avx512) = &_ascon_xof_avx512;

static const struct lc_hash _ascon_xofa_avx512 = {
	.init = ascon_xofa_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_avx512_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_xofa_avx512) = &_ascon_xofa_avx512;
