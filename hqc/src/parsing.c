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
 * @file parsing.c
 * @brief Functions to parse secret key, public key and ciphertext of the HQC
 * scheme
 */

#include "ext_headers_internal.h"
#include "hqc_type.h"
#include "hqc_internal.h"
#include "lc_sha3.h"
#include "parsing.h"
#include "vector.h"

static uint64_t load8(const uint8_t *in)
{
	uint64_t ret = in[7];
	int8_t i;

	for (i = 6; i >= 0; --i) {
		ret <<= 8;
		ret |= in[i];
	}

	return ret;
}

void load8_arr(uint64_t *out64, size_t outlen, const uint8_t *in8, size_t inlen)
{
	size_t index_in = 0;
	size_t index_out = 0;
	int8_t i;

	// first copy by 8 bytes
	if (inlen >= 8 && outlen >= 1) {
		while (index_out < outlen && index_in + 8 <= inlen) {
			out64[index_out] = load8(in8 + index_in);

			index_in += 8;
			index_out += 1;
		}
	}

	// we now need to do the last 7 bytes if necessary
	if (index_in >= inlen || index_out >= outlen)
		return;

	out64[index_out] = in8[inlen - 1];
	for (i = (int8_t)(inlen - index_in) - 2; i >= 0; --i) {
		out64[index_out] <<= 8;
		out64[index_out] |= in8[index_in + (size_t)i];
	}
}

void store8_arr(uint8_t *out8, size_t outlen, const uint64_t *in64,
		size_t inlen)
{
	size_t index_out, index_in;

	for (index_out = 0, index_in = 0;
	     index_out < outlen && index_in < inlen;) {
		out8[index_out] =
			(in64[index_in] >> ((index_out % 8) * 8)) & 0xFF;
		++index_out;
		if (index_out % 8 == 0)
			++index_in;
	}
}

/**
 * @brief Parse a secret key into a string
 *
 * The secret key is composed of the seed used to generate vectors
 * <b>x</b> and <b>y</b>. As technicality, the public key is appended to the
 * secret key in order to respect NIST API.
 *
 * @param[out] sk String containing the secret key
 * @param[in] sk_seed Seed used to generate the secret key
 * @param[in] sigma String used in HHK transform
 * @param[in] pk String containing the public key
 */
void hqc_secret_key_to_string(uint8_t *sk, const uint8_t *sk_seed,
			      const uint8_t *sigma, const uint8_t *pk)
{
	memcpy(sk, sk_seed, LC_HQC_SEED_BYTES);
	memcpy(sk + LC_HQC_SEED_BYTES, sigma, LC_HQC_VEC_K_SIZE_BYTES);
	memcpy(sk + LC_HQC_SEED_BYTES + LC_HQC_VEC_K_SIZE_BYTES, pk,
	       LC_HQC_PUBLIC_KEY_BYTES);
}

/**
 * @brief Parse a secret key from a string
 *
 * The secret key is composed of the seed used to generate vectors
 * <b>x</b> and <b>y</b>. As technicality, the public key is appended to the
 * secret key in order to respect NIST API.
 *
 * @param[out] y uint64_t representation of vector y
 * @param[out] pk String containing the public key
 * @param[in] sk String containing the secret key
 */
void hqc_secret_key_from_string(uint64_t *y, uint8_t *sigma, uint8_t *pk,
				const uint8_t *sk,
				struct vect_set_random_fixed_weight_ws *ws)
{
	LC_SHAKE_256_CTX_ON_STACK(sk_seedexpander);

	memcpy(sigma, sk + LC_HQC_SEED_BYTES, LC_HQC_VEC_K_SIZE_BYTES);
	seedexpander_init(sk_seedexpander, sk, LC_HQC_SEED_BYTES);

	vect_set_random_fixed_weight(sk_seedexpander, y, LC_HQC_PARAM_OMEGA,
				     ws);
	memcpy(pk, sk + LC_HQC_SEED_BYTES + LC_HQC_VEC_K_SIZE_BYTES,
	       LC_HQC_PUBLIC_KEY_BYTES);

	lc_hash_zero(sk_seedexpander);
}

/**
 * @brief Parse a public key into a string
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used
 * to generate the vector <b>h</b>
 *
 * @param[out] pk String containing the public key
 * @param[in] pk_seed Seed used to generate the public key
 * @param[in] s uint64_t representation of vector s
 */
void hqc_public_key_to_string(uint8_t *pk, const uint8_t *pk_seed,
			      const uint64_t *s)
{
	memcpy(pk, pk_seed, LC_HQC_SEED_BYTES);
	store8_arr(pk + LC_HQC_SEED_BYTES, LC_HQC_VEC_N_SIZE_BYTES, s,
		   LC_HQC_VEC_N_SIZE_64);
}

/**
 * @brief Parse a public key from a string
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used
 * to generate the vector <b>h</b>
 *
 * @param[out] h uint64_t representation of vector h
 * @param[out] s uint64_t representation of vector s
 * @param[in] pk String containing the public key
 */
void hqc_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk,
				struct vect_set_random_ws *ws)
{
	LC_SHAKE_256_CTX_ON_STACK(pk_seedexpander);

	seedexpander_init(pk_seedexpander, pk, LC_HQC_SEED_BYTES);
	vect_set_random(pk_seedexpander, h, ws);

	load8_arr(s, LC_HQC_VEC_N_SIZE_64, pk + LC_HQC_SEED_BYTES,
		  LC_HQC_VEC_N_SIZE_BYTES);

	lc_hash_zero(pk_seedexpander);
}

/**
 * @brief Parse a ciphertext into a string
 *
 * The ciphertext is composed of vectors <b>u</b>, <b>v</b> and salt.
 *
 * @param[out] ct String containing the ciphertext
 * @param[in] u uint64_t representation of vector u
 * @param[in] v uint64_t representation of vector v
 * @param[in] salt String containing a salt
 */
void hqc_ciphertext_to_string(uint8_t *ct, const uint64_t *u, const uint64_t *v,
			      const uint8_t *salt)
{
	store8_arr(ct, LC_HQC_VEC_N_SIZE_BYTES, u, LC_HQC_VEC_N_SIZE_64);
	store8_arr(ct + LC_HQC_VEC_N_SIZE_BYTES, LC_HQC_VEC_N1N2_SIZE_BYTES, v,
		   LC_HQC_VEC_N1N2_SIZE_64);
	memcpy(ct + LC_HQC_VEC_N_SIZE_BYTES + LC_HQC_VEC_N1N2_SIZE_BYTES, salt,
	       LC_HQC_SALT_SIZE_BYTES);
}

/**
 * @brief Parse a ciphertext from a string
 *
 * The ciphertext is composed of vectors <b>u</b>, <b>v</b> and salt.
 *
 * @param[out] u uint64_t representation of vector u
 * @param[out] v uint64_t representation of vector v
 * @param[out] d String containing the hash d
 * @param[in] ct String containing the ciphertext
 */
void hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *salt,
				const uint8_t *ct)
{
	load8_arr(u, LC_HQC_VEC_N_SIZE_64, ct, LC_HQC_VEC_N_SIZE_BYTES);
	load8_arr(v, LC_HQC_VEC_N1N2_SIZE_64, ct + LC_HQC_VEC_N_SIZE_BYTES,
		  LC_HQC_VEC_N1N2_SIZE_BYTES);
	memcpy(salt, ct + LC_HQC_VEC_N_SIZE_BYTES + LC_HQC_VEC_N1N2_SIZE_BYTES,
	       LC_HQC_SALT_SIZE_BYTES);
}
