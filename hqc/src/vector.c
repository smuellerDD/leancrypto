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
 * https://github.com/PQClean/PQClean/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file vector.c
 * @brief Implementation of vectors sampling and some utilities for the HQC
 *	  scheme
 */

#include "bitshift_le.h"
#include "hqc_type.h"
#include "parsing.h"
#include "vector.h"

#if (LC_HQC_TYPE == 128)
static const uint32_t m_val[75] = {
	243079, 243093, 243106, 243120, 243134, 243148, 243161, 243175, 243189,
	243203, 243216, 243230, 243244, 243258, 243272, 243285, 243299, 243313,
	243327, 243340, 243354, 243368, 243382, 243396, 243409, 243423, 243437,
	243451, 243465, 243478, 243492, 243506, 243520, 243534, 243547, 243561,
	243575, 243589, 243603, 243616, 243630, 243644, 243658, 243672, 243686,
	243699, 243713, 243727, 243741, 243755, 243769, 243782, 243796, 243810,
	243824, 243838, 243852, 243865, 243879, 243893, 243907, 243921, 243935,
	243949, 243962, 243976, 243990, 244004, 244018, 244032, 244046, 244059,
	244073, 244087, 244101
};

#elif (LC_HQC_TYPE == 192)
static const uint32_t m_val[114] = {
	119800, 119803, 119807, 119810, 119813, 119817, 119820, 119823, 119827,
	119830, 119833, 119837, 119840, 119843, 119847, 119850, 119853, 119857,
	119860, 119864, 119867, 119870, 119874, 119877, 119880, 119884, 119887,
	119890, 119894, 119897, 119900, 119904, 119907, 119910, 119914, 119917,
	119920, 119924, 119927, 119930, 119934, 119937, 119941, 119944, 119947,
	119951, 119954, 119957, 119961, 119964, 119967, 119971, 119974, 119977,
	119981, 119984, 119987, 119991, 119994, 119997, 120001, 120004, 120008,
	120011, 120014, 120018, 120021, 120024, 120028, 120031, 120034, 120038,
	120041, 120044, 120048, 120051, 120054, 120058, 120061, 120065, 120068,
	120071, 120075, 120078, 120081, 120085, 120088, 120091, 120095, 120098,
	120101, 120105, 120108, 120112, 120115, 120118, 120122, 120125, 120128,
	120132, 120135, 120138, 120142, 120145, 120149, 120152, 120155, 120159,
	120162, 120165, 120169, 120172, 120175, 120179
};

#elif (LC_HQC_TYPE == 256)
static const uint32_t m_val[149] = {
	74517, 74518, 74520, 74521, 74522, 74524, 74525, 74526, 74527, 74529,
	74530, 74531, 74533, 74534, 74535, 74536, 74538, 74539, 74540, 74542,
	74543, 74544, 74545, 74547, 74548, 74549, 74551, 74552, 74553, 74555,
	74556, 74557, 74558, 74560, 74561, 74562, 74564, 74565, 74566, 74567,
	74569, 74570, 74571, 74573, 74574, 74575, 74577, 74578, 74579, 74580,
	74582, 74583, 74584, 74586, 74587, 74588, 74590, 74591, 74592, 74593,
	74595, 74596, 74597, 74599, 74600, 74601, 74602, 74604, 74605, 74606,
	74608, 74609, 74610, 74612, 74613, 74614, 74615, 74617, 74618, 74619,
	74621, 74622, 74623, 74625, 74626, 74627, 74628, 74630, 74631, 74632,
	74634, 74635, 74636, 74637, 74639, 74640, 74641, 74643, 74644, 74645,
	74647, 74648, 74649, 74650, 74652, 74653, 74654, 74656, 74657, 74658,
	74660, 74661, 74662, 74663, 74665, 74666, 74667, 74669, 74670, 74671,
	74673, 74674, 74675, 74676, 74678, 74679, 74680, 74682, 74683, 74684,
	74685, 74687, 74688, 74689, 74691, 74692, 74693, 74695, 74696, 74697,
	74698, 74700, 74701, 74702, 74704, 74705, 74706, 74708, 74709
};

#endif

/**
 * @brief Constant-time comparison of two integers v1 and v2
 *
 * Returns 1 if v1 is equal to v2 and 0 otherwise
 * https://gist.github.com/sneves/10845247
 *
 * @param[in] v1
 * @param[in] v2
 */
static inline uint32_t compare_u32(uint32_t v1, uint32_t v2)
{
	return 1 ^ ((uint32_t)((v1 - v2) | (v2 - v1)) >> 31);
}

static uint64_t single_bit_mask(uint32_t pos)
{
	uint64_t ret = 0;
	uint64_t mask = 1;
	uint64_t tmp;
	size_t i;

	for (i = 0; i < 64; ++i) {
		tmp = pos - i;
		tmp = 0 - (1 - ((uint64_t)(tmp | (0 - tmp)) >> 63));
		ret |= mask & tmp;
		mask <<= 1;
	}

	return ret;
}

static inline uint32_t cond_sub(uint32_t r, uint32_t n)
{
	uint32_t mask;

	r -= n;
	mask = 0 - (r >> 31);

	return r + (n & mask);
}

static inline uint32_t reduce(uint32_t a, size_t i)
{
	uint32_t q, n, r;

	q = ((uint64_t)a * m_val[i]) >> 32;
	n = (uint32_t)(LC_HQC_PARAM_N - i);
	r = a - q * n;

	return cond_sub(r, n);
}

/**
 * @brief Generates a vector of a given Hamming weight
 *
 * Implementation of Algorithm 5 in https://eprint.iacr.org/2021/1631.pdf
 *
 * @param[in] ctx Pointer to the context of the seed expander
 * @param[in] v Pointer to an array
 * @param[in] weight Integer that is the Hamming weight
 */
void vect_set_random_fixed_weight(struct lc_hash_ctx *shake256, uint64_t *v,
				  uint16_t weight)
{
	/* to be interpreted as LC_HQC_PARAM_OMEGA_R 32-bit unsigned ints */
	uint8_t rand_bytes[4 * LC_HQC_PARAM_OMEGA_R] = { 0 };
	uint32_t support[LC_HQC_PARAM_OMEGA_R] = { 0 };
	uint32_t index_tab[LC_HQC_PARAM_OMEGA_R] = { 0 };
	uint64_t bit_tab[LC_HQC_PARAM_OMEGA_R] = { 0 };
	uint32_t pos, found, mask32, tmp;
	uint64_t mask64, val;
	size_t i, j;

	seedexpander(shake256, rand_bytes, 4 * weight);

	for (i = 0; i < weight; ++i) {
		support[i] = ptr_to_le32(&rand_bytes[4 * i]);

		// use constant-time reduction
		support[i] = (uint32_t)(i + reduce(support[i], i));
	}

	for (i = (weight - 1); i-- > 0;) {
		found = 0;

		for (j = i + 1; j < weight; ++j)
			found |= compare_u32(support[j], support[i]);

		mask32 = 0 - found;
		support[i] = (mask32 & i) ^ (~mask32 & support[i]);
	}

	for (i = 0; i < weight; ++i) {
		index_tab[i] = support[i] >> 6;
		pos = support[i] & 0x3f;
		bit_tab[i] = single_bit_mask(pos); // avoid secret shift
	}

	for (i = 0; i < LC_HQC_VEC_N_SIZE_64; ++i) {
		val = 0;
		for (j = 0; j < weight; ++j) {
			tmp = (uint32_t)(i - index_tab[j]);
			tmp = 1 ^ ((uint32_t)(tmp | (0 - tmp)) >> 31);
			mask64 = 0 - (uint64_t)tmp;
			val |= (bit_tab[j] & mask64);
		}
		v[i] |= val;
	}
}

/**
 * @brief Generates a random vector of dimension <b>LC_HQC_PARAM_N</b>
 *
 * This function generates a random binary vector of dimension
 * <b>LC_HQC_PARAM_N</b>. It generates a random array of bytes using the
 * seedexpander function, and drop the extra bits using a mask.
 *
 * @param[in] v Pointer to an array
 * @param[in] ctx Pointer to the context of the seed expander
 */
void vect_set_random(struct lc_hash_ctx *shake256, uint64_t *v)
{
	uint8_t rand_bytes[LC_HQC_VEC_N_SIZE_BYTES] = { 0 };

	seedexpander(shake256, rand_bytes, LC_HQC_VEC_N_SIZE_BYTES);

	load8_arr(v, LC_HQC_VEC_N_SIZE_64, rand_bytes, LC_HQC_VEC_N_SIZE_BYTES);
	v[LC_HQC_VEC_N_SIZE_64 - 1] &= LC_HQC_RED_MASK;
}

/**
 * @brief Adds two vectors
 *
 * @param[out] o Pointer to an array that is the result
 * @param[in] v1 Pointer to an array that is the first vector
 * @param[in] v2 Pointer to an array that is the second vector
 * @param[in] size Integer that is the size of the vectors
 */
void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, size_t size)
{
	size_t i;

	for (i = 0; i < size; ++i)
		o[i] = v1[i] ^ v2[i];
}

/**
 * @brief Compares two vectors
 *
 * @param[in] v1 Pointer to an array that is first vector
 * @param[in] v2 Pointer to an array that is second vector
 * @param[in] size Integer that is the size of the vectors
 * @returns 0 if the vectors are equal and 1 otherwise
 */
uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, size_t size)
{
	size_t i;
	uint16_t r = 0x0100;

	for (i = 0; i < size; i++)
		r |= v1[i] ^ v2[i];

	return (r - 1) >> 8;
}

/**
 * @brief Resize a vector so that it contains <b>size_o</b> bits
 *
 * @param[out] o Pointer to the output vector
 * @param[in] size_o Integer that is the size of the output vector in bits
 * @param[in] v Pointer to the input vector
 * @param[in] size_v Integer that is the size of the input vector in bits
 */
void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v,
		 uint32_t size_v)
{
	uint64_t mask = 0x7FFFFFFFFFFFFFFF;
	size_t i, val = 0;

	if (size_o < size_v) {
		if (size_o % 64)
			val = 64 - (size_o % 64);

		memcpy(o, v, LC_HQC_VEC_N1N2_SIZE_BYTES);

		for (i = 0; i < val; ++i)
			o[LC_HQC_VEC_N1N2_SIZE_64 - 1] &= (mask >> i);
	} else {
		memcpy(o, v, 8 * LC_HQC_CEIL_DIVIDE(size_v, 64));
	}
}
