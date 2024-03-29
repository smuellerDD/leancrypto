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
	unsigned int i;
	union {
		uint64_t dw;
		uint8_t b[sizeof(uint64_t)];
	} tmp;

	state += byte_offset / sizeof(state[0]);

	i = byte_offset & (sizeof(tmp) - 1);

	tmp.dw = 0;

	/*
	 * This loop simply XORs the data in *in with the state starting from
	 * byte_offset. The complication is that the simple XOR of the *in bytes
	 * with the respective bytes in the state only works on little endian
	 * systems. For big endian systems, we must apply a byte swap! This
	 * loop therefore concatenates the *in bytes in chunks of uint64_t
	 * and then XORs the byte swapped value into the state.
	 */
	while (inlen) {
		uint8_t ctr;

		for (ctr = 0; i < sizeof(tmp) && (size_t)ctr < inlen;
		     i++, in++, ctr++)
			tmp.b[i] = *in;

		*state ^= be_bswap64(tmp.dw);
		state++;
		inlen -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
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
	size_t i;
	const uint64_t *s = state;
	union {
		uint64_t dw;
		uint32_t w[2];
	} val;

	if (offset) {
		/*
		 * Access requests when squeezing more data that happens to be
		 * not aligned with the block size of the used SHAKE algorithm
		 * are processed byte-wise.
		 */
		size_t word, byte;
		for (i = offset; i < length + offset; i++, data++) {
			uint64_t tmp;
			word = i / sizeof(*s);
			byte = (i % sizeof(*s)) << 3;

			tmp = be_bswap64(s[word]);
			*data = (uint8_t)(tmp >> byte);
		}
	} else {
		uint32_t part;
		unsigned int j;
		uint8_t todo_64, todo_32, todo;

		/* How much 64-bit aligned data can we obtain? */
		todo_64 = (uint8_t)(length >> 3);

		/* How much 32-bit aligned data can we obtain? */
		todo_32 = (uint8_t)((length - (uint8_t)(todo_64 << 3)) >> 2);

		/* How much non-aligned do we have to obtain? */
		todo = (uint8_t)(length -
				 (uint8_t)((todo_64 << 3) + (todo_32 << 2)));

		/* Sponge squeeze phase */

		/* 64-bit aligned request */
		for (i = 0; i < todo_64; i++, data += 8)
			be64_to_ptr(data, s[i]);

		if (i < LC_ASCON_HASH_STATE_WORDS)
			val.dw = be_bswap64(s[i]);
		else
			val.dw = 0;

		if (todo_32) {
			/* 32-bit aligned request */
			be32_to_ptr(data, val.w[0]);
			data += 4;
			part = be_bswap32(val.w[1]);
		} else {
			/* non-aligned request */
			part = be_bswap32(val.w[0]);
		}

		for (j = 0; j < (unsigned int)(todo << 3); j += 8, data++)
			*data = (uint8_t)(part >> j);
	}
}

static void ascon_c_newstate(void *state, const uint8_t *data, size_t offset,
			      size_t length)
{
	uint64_t *s = state;
	unsigned int i;
	union {
		uint64_t dw;
		uint8_t b[sizeof(uint64_t)];
	} tmp;

	s += offset / sizeof(s[0]);

	i = offset & (sizeof(tmp) - 1);

	/*
	 * This loop simply copy the data in *data with the state starting from
	 * byte_offset. The complication is that the simple copy of the *data
	 * bytes with the respective bytes in the state only works on little
	 * endian systems. For big endian systems, we must apply a byte swap!
	 * This loop therefore concatenates the *data bytes in chunks of
	 * uint64_t and then copies the byte swapped value into the state.
	 */
	while (length) {
		uint8_t ctr;

		/* Copy the current state data into tmp */
		tmp.dw = *s;

		/* Overwrite the existing tmp data with new data */
		for (ctr = 0; i < sizeof(tmp) && (size_t)ctr < length;
		     i++, data++, ctr++)
			tmp.b[i] = *data;

		*s = be_bswap64(tmp.dw);
		s++;
		length -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
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
