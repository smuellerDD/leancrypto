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

#ifndef SPONGE_COMMON_H
#define SPONGE_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

static inline void sponge_fill_state_bytes(uint64_t *state, const uint8_t *in,
					   size_t byte_offset, size_t inlen,
					   uint64_t (*bswap64)(uint64_t))
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

		*state ^= bswap64(tmp.dw);
		state++;
		inlen -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
}

static inline void sponge_extract_bytes(const void *state, uint8_t *data,
					size_t offset, size_t length,
					unsigned int state_len,
					uint64_t (*bswap64)(uint64_t),
					uint32_t (*bswap32)(uint32_t),
					void (*to_ptr64)(uint8_t *p,
							const uint64_t value),
					void (*to_ptr32)(uint8_t *p,
							const uint32_t value))
{
	size_t i;
	const uint64_t *s = state;
	union {
		uint64_t dw;
		uint32_t w[2];
	} val;

	if (offset) {
		uint64_t tmp;

		/*
		 * Access requests when squeezing more data that happens to be
		 * not aligned with the block size of the used SHAKE algorithm
		 * are processed byte-wise.
		 */
		size_t word, byte;
		for (i = offset; i < length + offset; i++, data++) {
			word = i / sizeof(*s);
			byte = (i % sizeof(*s)) << 3;

			tmp = bswap64(s[word]);
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
			to_ptr64(data, s[i]);

		if (i < state_len)
			val.dw = bswap64(s[i]);
		else
			val.dw = 0;

		if (todo_32) {
			/* 32-bit aligned request */
			to_ptr32(data, val.w[0]);
			data += 4;
			part = bswap32(val.w[1]);
		} else {
			/* non-aligned request */
			part = bswap32(val.w[0]);
		}

		for (j = 0; j < (unsigned int)(todo << 3); j += 8, data++)
			*data = (uint8_t)(part >> j);
	}
}

static inline void sponge_newstate(void *state, const uint8_t *data,
				   size_t offset, size_t length,
				   uint64_t (*bswap64)(uint64_t))
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

		*s = bswap64(tmp.dw);
		s++;
		length -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* SPONGE_COMMON_H */
