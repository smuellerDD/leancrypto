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
 */

#include "ascon_c.h"
#include "ascon_hash.h"
#include "ascon_hash_common.h"
#include "conv_be_le.h"
#include "lc_ascon_hash.h"
#include "visibility.h"

/***************************** Ascon Permutation ******************************/

#if 0
/* This code may be suitable for bit-slicing code */
static inline void ascon_permutation_ps(uint64_t s[LC_ASCON_HASH_STATE_WORDS],
					uint64_t constant)
{
	uint64_t t[5];

	s[2] ^= constant;

	// clang-format off
	s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1];
	t[0]  = s[0]; t[1]  = s[1]; t[2]  = s[2]; t[3]  = s[3]; t[4]  = s[4];
	t[0] =~ t[0]; t[1] =~ t[1]; t[2] =~ t[2]; t[3] =~ t[3]; t[4] =~ t[4];
	t[0] &= s[1]; t[1] &= s[2]; t[2] &= s[3]; t[3] &= s[4]; t[4] &= s[0];
	s[0] ^= t[1]; s[1] ^= t[2]; s[2] ^= t[3]; s[3] ^= t[4]; s[4] ^= t[0];
	s[1] ^= s[0]; s[0] ^= s[4]; s[3] ^= s[2]; s[2] =~ s[2];
	// clang-format on
}

static inline void ascon_permutation_pl(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	// clang-format off
	s[0] ^= ror64(s[0], 19) ^ ror64(s[0], 28);
	s[1] ^= ror64(s[1], 61) ^ ror64(s[1], 39);
	s[2] ^= ror64(s[2],  1) ^ ror64(s[2],  6);
	s[3] ^= ror64(s[3], 10) ^ ror64(s[3], 17);
	s[4] ^= ror64(s[4],  7) ^ ror64(s[4], 41);
	// clang-format on
}

static inline void ascon_permutation_one(
	uint64_t s[LC_ASCON_HASH_STATE_WORDS], uint8_t constant)
{
	ascon_permutation_ps(s, constant);
	ascon_permutation_pl(s);
}

#else
static inline void ascon_permutation_one(uint64_t s[LC_ASCON_HASH_STATE_WORDS],
					 uint8_t constant)
{
	uint64_t t[5];

	/* addition of constants */
	s[2] ^= constant;

	/* substitution layer */
	s[0] ^= s[4];
	s[4] ^= s[3];
	s[2] ^= s[1];
	t[0] = s[0] ^ (~s[1] & s[2]);
	t[1] = s[1] ^ (~s[2] & s[3]);
	t[2] = s[2] ^ (~s[3] & s[4]);
	t[3] = s[3] ^ (~s[4] & s[0]);
	t[4] = s[4] ^ (~s[0] & s[1]);

	t[1] ^= t[0];
	t[0] ^= t[4];
	t[3] ^= t[2];
	t[2] = ~t[2];

	/* linear diffusion layer */
	s[0] = t[0] ^ ror64(t[0], 19) ^ ror64(t[0], 28);
	s[1] = t[1] ^ ror64(t[1], 61) ^ ror64(t[1], 39);
	s[2] = t[2] ^ ror64(t[2], 1) ^ ror64(t[2], 6);
	s[3] = t[3] ^ ror64(t[3], 10) ^ ror64(t[3], 17);
	s[4] = t[4] ^ ror64(t[4], 7) ^ ror64(t[4], 41);
}
#endif

static inline void ascon_permutation_6(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static inline void ascon_permutation_8(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0xb4);
	ascon_permutation_one(s, 0xa5);
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static inline void ascon_permutation_12(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0xf0);
	ascon_permutation_one(s, 0xe1);
	ascon_permutation_one(s, 0xd2);
	ascon_permutation_one(s, 0xc3);
	ascon_permutation_one(s, 0xb4);
	ascon_permutation_one(s, 0xa5);
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static void ascon_c_permutation(void *state, unsigned int rounds)
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
	ascon_absorb_common(state, in, inlen, ascon_c_permutation);
}

static void ascon_squeeze(void *state, uint8_t *digest)
{
	ascon_squeeze_common(state, digest, ascon_permutation_12,
			     ascon_c_permutation);
}

static const struct lc_hash _ascon_256_c = {
	.init = ascon_256_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_256_c) = &_ascon_256_c;

static const struct lc_hash _ascon_128a_c = {
	.init = ascon_128a_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 128 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128a_c) = &_ascon_128a_c;

static const struct lc_hash _ascon_xof_c = {
	.init = ascon_xof_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_xof_c) = &_ascon_xof_c;

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_256) = &_ascon_256_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128a) = &_ascon_128a_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_xof) = &_ascon_xof_c;
