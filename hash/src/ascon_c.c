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

#include "bitshift.h"
#include "conv_be_le.h"
#include "lc_ascon_hash.h"
#include "rotate.h"
#include "sponge_common.h"
#include "visibility.h"

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
static inline void ascon_permutation_ps_pl(
	uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_ps(s);
	ascon_permutation_pl(s);
}

#else
static inline void ascon_permutation_one(
	uint64_t s[LC_ASCON_HASH_STATE_WORDS], uint8_t constant)
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

#if defined(LC_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN)

/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for little endian.
 */
static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	sponge_fill_state_bytes(state, in, byte_offset, inlen, be_bswap64);
}

#elif defined(LC_BIG_ENDIAN) || defined(__BIG_ENDIAN)

static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + byte_offset, in, inlen);
}

#else
#error "Endianess not defined"
#endif

static void ascon_c_add_bytes(void *state, const uint8_t *data,
			      unsigned int offset, unsigned int length)
{
	ascon_fill_state_bytes((uint64_t *)state, data, offset, length);
}

static void ascon_c_extract_bytes(const void *state, uint8_t *data,
				  size_t offset, size_t length)
{
	sponge_extract_bytes(state, data, offset, length,
			     LC_ASCON_HASH_STATE_WORDS, be_bswap64, be_bswap32,
			     be64_to_ptr, be32_to_ptr);
}

static void ascon_c_newstate(void *state, const uint8_t *data, size_t offset,
			      size_t length)
{
	sponge_newstate(state, data, offset, length, be_bswap64);
}

static const struct lc_hash _ascon_128_c = {
	.init = NULL,
	.update = NULL,
	.final = NULL,
	.set_digestsize = NULL,
	.get_digestsize = NULL,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128) = &_ascon_128_c;


static const struct lc_hash _ascon_128a_c = {
	.init = NULL,
	.update = NULL,
	.final = NULL,
	.set_digestsize = NULL,
	.get_digestsize = NULL,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.rate = 128 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128a) = &_ascon_128a_c;
