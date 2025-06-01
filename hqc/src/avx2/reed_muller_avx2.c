/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://pqc-hqc.org/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file reed_muller.c
 * @brief Constant time implementation of Reed-Muller code RM(1,7)
 */

#include "ext_headers_x86.h"
#include "reed_muller_avx2.h"

// number of repeated code words
#define MULTIPLICITY LC_HQC_CEIL_DIVIDE(LC_HQC_PARAM_N2, 128)

static __inline__ int __bsfd(int __A)
{
	return __builtin_ctz((unsigned int)__A);
}
#define _bit_scan_forward(A) __bsfd((A))

// copy bit 0 into all bits of a 64 bit value
#define BIT0MASK(x) (int32_t)(-((x) & 1))

/**
 * @brief Encode a single byte into a single codeword using RM(1,7)
 *
 * Encoding matrix of this code:
 * bit pattern (note that bits are numbered big endian)
 * 0   aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa
 * 1   cccccccc cccccccc cccccccc cccccccc
 * 2   f0f0f0f0 f0f0f0f0 f0f0f0f0 f0f0f0f0
 * 3   ff00ff00 ff00ff00 ff00ff00 ff00ff00
 * 4   ffff0000 ffff0000 ffff0000 ffff0000
 * 5   00000000 ffffffff 00000000 ffffffff
 * 6   00000000 00000000 ffffffff ffffffff
 * 7   ffffffff ffffffff ffffffff ffffffff
 *
 * @param[out] word An RM(1,7) codeword
 * @param[in] message A message to encode
 */
static inline void encode(codeword *word, int32_t message)
{
	int32_t first_word;

	first_word = BIT0MASK(message >> 7);
	first_word ^= BIT0MASK(message >> 0) & (int32_t)0xaaaaaaaa;
	first_word ^= BIT0MASK(message >> 1) & (int32_t)0xcccccccc;
	first_word ^= BIT0MASK(message >> 2) & (int32_t)0xf0f0f0f0;
	first_word ^= BIT0MASK(message >> 3) & (int32_t)0xff00ff00;
	first_word ^= BIT0MASK(message >> 4) & (int32_t)0xffff0000;
	word->u32[0] = (uint32_t)first_word;
	first_word ^= BIT0MASK(message >> 5);
	word->u32[1] = (uint32_t)first_word;
	first_word ^= BIT0MASK(message >> 6);
	word->u32[3] = (uint32_t)first_word;
	first_word ^= BIT0MASK(message >> 5);
	word->u32[2] = (uint32_t)first_word;
}

/**
 * @brief Add multiple codewords into expanded codeword
 *
 * Note: this does not write the codewords as -1 or +1 as the green machine does
 * instead, just 0 and 1 is used.
 * The resulting hadamard transform has:
 * all values are halved
 * the first entry is 64 too high
 *
 * @param[out] dst Structure that contain the expanded codeword
 * @param[in] src Structure that contain the codeword
 */
static inline void expand_and_sum(expandedCodeword *dst, codeword src[])
{
	// start converting the first copy
	for (size_t part = 0; part < 8; part++) {
		for (size_t i = 0; i < 16; ++i) {
			dst->i16[(part << 4) + i] = src->u16[part] >> i & 1;
		}
	}
	// sum the rest of the copies
	for (size_t copy = 1; copy < MULTIPLICITY; copy++) {
		for (size_t part = 0; part < 8; part++) {
			for (size_t i = 0; i < 16; ++i) {
				dst->i16[(part << 4) + i] +=
					src[copy].u16[part] >> i & 1;
			}
		}
	}
}

/**
 * @brief Hadamard transform
 *
 * Perform hadamard transform of src and store result in dst
 * src is overwritten: it is also used as intermediate buffer
 *
 * @param[out] src Structure that contain the expanded codeword
 * @param[out] dst Structure that contain the expanded codeword
 */
static inline void hadamard(expandedCodeword *src, expandedCodeword *dst)
{
	// the passes move data:
	// src -> dst -> src -> dst -> src -> dst -> src -> dst
	// using p1 and p2 alternately
	expandedCodeword *p1 = src;
	expandedCodeword *p2 = dst;
	for (size_t pass = 0; pass < 7; pass++) {
		// warning: hadd works "within lanes" as Intel call it
		// so you have to swap the middle 64 bit blocks of the result
		for (size_t part = 0; part < 4; part++) {
			p2->mm[part] = _mm256_permute4x64_epi64(
				_mm256_hadd_epi16(p1->mm[2 * part],
						  p1->mm[2 * part + 1]),
				0xd8);
			p2->mm[part + 4] = _mm256_permute4x64_epi64(
				_mm256_hsub_epi16(p1->mm[2 * part],
						  p1->mm[2 * part + 1]),
				0xd8);
		}
		// swap p1, p2 for next round
		expandedCodeword *p3 = p1;
		p1 = p2;
		p2 = p3;
	}
}

/**
 * @brief Finding the location of the highest value
 *
 * This is the final step of the green machine: find the location of the highest
 * value, and add 128 if the peak is positive.
 *
 * Notes on decoding
 * The standard "Green machine" decoder works as follows:
 * if the received codeword is W, compute (2 * W - 1) * H7
 * The entries of the resulting vector are always even and vary from
 * -128 (= the complement is a code word, add bit 7 to decode)
 * via 0 (this is a different codeword)
 * to 128 (this is the code word).
 *
 * Our decoding differs in two ways:
 * - We take W instead of 2 * W - 1 (so the entries are 0,1 instead of -1,1)
 * - We take the sum of the repititions (so the entries are 0..MULTIPLICITY)
 * This implies that we have to subtract 64M (M=MULTIPLICITY)
 * from the first entry to make sure the first codewords is handled properly
 * and that the entries vary from -64M to 64M.
 * -64M or 64M stands for a perfect codeword.
 *
 * @param [in] ws Structure that contain the expanded codeword
 */
static inline uint8_t find_peaks(struct reed_muller_decode_ws *ws)
{
	// compute absolute value of transform
	for (size_t i = 0; i < 8; i++)
		ws->abs_rows[i] = _mm256_abs_epi16(ws->transform.mm[i]);

	// compute a vector of 16 elements which contains the maximum somewhere
	ws->max_abs_rows = ws->abs_rows[0];
	for (size_t i = 1; i < 8; i++) {
		ws->max_abs_rows =
			_mm256_max_epi16(ws->max_abs_rows, ws->abs_rows[i]);
	}

	// do binary search for the highest value that is lower than the maximum
	int32_t lower = 1;
	// this gives 64, 128 or 256 for MULTIPLICITY = 2, 4, 6
	int32_t width = 1 << (5 + MULTIPLICITY / 2);

	while (width > 1) {
		width >>= 1;
		// compare with lower + width; put result in bitmap
		// make vector from value of new bound
		ws->bound = _mm256_broadcastw_epi16(
			_mm_cvtsi32_si128(lower + width));
		ws->bitmap = _mm256_cmpgt_epi16(ws->max_abs_rows, ws->bound);
		// step up if there are any matches
		int32_t step_mask =
			_mm256_testz_si256(ws->bitmap, ws->bitmap) - 1;
		lower += step_mask & width;
	}
	// lower+width contains the maximum value of the vector
	// construct vector filled with bound-1
	ws->bound =
		_mm256_broadcastw_epi16(_mm_cvtsi32_si128(lower + width - 1));

	/*
	 * find in which of the 8 groups a maximum occurs to compute bits 4, 5,
	 * 6 of message
	 */
	uint8_t message = 0x70;
	for (int32_t i = 7; i >= 0; i--) {
		ws->bitmap = _mm256_cmpgt_epi16(ws->abs_rows[i], ws->bound);
		int message_mask =
			(-(int16_t)(_mm256_testz_si256(ws->bitmap,
						       ws->bitmap) == 0)) >>
			15;
		message ^= (uint8_t)message_mask & (message ^ (unsigned)i << 4);
	}
	// we decided which row of the matrix contains the lowest match
	// select proper row
	int8_t index = message >> 4;
	ws->tmp = (__m256i){ 0ULL, 0ULL, 0ULL, 0ULL };

	for (int8_t i = 0; i < 8; i++) {
		int8_t abs_value = (int8_t)(index - i);
		int8_t mask1 = abs_value >> 7;
		abs_value ^= mask1;
		abs_value -= mask1;
		int8_t mask2 = ((uint8_t)-abs_value >> 7);
		int64_t mask3 = (int64_t)(-1ULL) + (int64_t)mask2;
		ws->vect_mask = (__m256i){ mask3, mask3, mask3, mask3 };

		ws->res = _mm256_and_si256(ws->abs_rows[i], ws->vect_mask);
		ws->tmp = _mm256_or_si256(ws->tmp, ws->res);
	}

	ws->active_row = ws->tmp;

	// get the column number of the vector element
	ws->peak_mask.mm = _mm256_cmpgt_epi16(ws->active_row, ws->bound);
	for (size_t i = 0; i < 16; ++i) {
		ws->peak_mask.u16[i] &= 1 << i;
	}

	for (int32_t i = 0; i < 3; i++) {
		ws->peak_mask.mm =
			_mm256_hadd_epi16(ws->peak_mask.mm, ws->peak_mask.mm);
	}
	// add low 4 bits of message
	message |=
		_bit_scan_forward(ws->peak_mask.u16[0] + ws->peak_mask.u16[8]);

	// set bit 7 if sign of biggest value is positive
	ws->tmp = (__m256i){ 0ULL, 0ULL, 0ULL, 0ULL };
	for (uint32_t i = 0; i < 8; i++) {
		int64_t message_mask = (-(int64_t)(i == message / 16)) >> 63;
		ws->vect_mask = (__m256i){ message_mask, message_mask,
					   message_mask, message_mask };
		ws->tmp = _mm256_or_si256(
			ws->tmp,
			_mm256_and_si256(ws->vect_mask, ws->transform.mm[i]));
	}
	uint16_t result = 0;
	for (uint32_t i = 0; i < 16; i++) {
		uint16_t *ptr = (uint16_t *)&ws->tmp;
		int32_t message_mask = (-(int32_t)(i == message % 16)) >>
				       (sizeof(int32_t) * 8 - 1);
		result |= message_mask & ptr[i];
	}
	message |= (0x8000 & ~result) >> 8;
	return message;
}

/**
 * @brief Encodes the received word
 *
 * The message consists of N1 bytes each byte is encoded into PARAM_N2 bits,
 * or MULTIPLICITY repeats of 128 bits
 *
 * @param[out] cdw Array of size VEC_N1N2_SIZE_64 receiving the encoded message
 * @param[in] msg Array of size VEC_N1_SIZE_64 storing the message
 */
void reed_muller_encode_avx2(uint64_t *cdw, const uint64_t *msg)
{
	uint8_t *message_array = (uint8_t *)msg;
	codeword *codeArray = (codeword *)cdw;
	for (size_t i = 0; i < LC_HQC_VEC_N1_SIZE_BYTES; i++) {
		// fill entries i * MULTIPLICITY to (i+1) * MULTIPLICITY
		size_t pos = i * MULTIPLICITY;

		// encode first word
		encode(&codeArray[pos], message_array[i]);
		// copy to other identical codewords
		for (size_t copy = 1; copy < MULTIPLICITY; copy++) {
			memcpy(&codeArray[pos + copy], &codeArray[pos],
			       sizeof(codeword));
		}
	}
	return;
}

/**
 * @brief Decodes the received word
 *
 * Decoding uses fast hadamard transform, for a more complete picture on
 * Reed-Muller decoding, see MacWilliams, Florence Jessie, and Neil James
 * Alexander Sloane. The theory of error-correcting codes codes
 * @cite macwilliams1977theory
 *
 * @param[out] msg Array of size VEC_N1_SIZE_64 receiving the decoded message
 * @param[in] cdw Array of size VEC_N1N2_SIZE_64 storing the received word
 */
void reed_muller_decode_avx2(uint64_t *msg, const uint64_t *cdw,
			     struct reed_muller_decode_ws *ws)
{
	uint8_t *message_array = (uint8_t *)msg;
	codeword *codeArray = (codeword *)cdw;

	for (size_t i = 0; i < LC_HQC_VEC_N1_SIZE_BYTES; i++) {
		// collect the codewords
		expand_and_sum(&ws->expanded, &codeArray[i * MULTIPLICITY]);
		// apply hadamard transform
		hadamard(&ws->expanded, &ws->transform);
		// fix the first entry to get the half Hadamard transform
		ws->transform.i16[0] -= 64 * MULTIPLICITY;
		// finish the decoding
		message_array[i] = find_peaks(ws);
	}
}
