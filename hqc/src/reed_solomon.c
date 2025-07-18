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
 * @file reed_solomon.c
 * @brief Constant time implementation of Reed-Solomon codes
 */

#include "hqc_type.h"
#include "hqc_internal.h"
#include "fft.h"
#include "gf.h"
#include "small_stack_support.h"
#include "reed_solomon.h"

static const uint16_t PARAM_RS_POLY[] = { LC_HQC_RS_POLY_COEFS };

/**
 * @brief Encodes a message message of PARAM_K bits to a Reed-Solomon codeword
 * codeword of LC_HQC_PARAM_N1 bytes
 *
 * Following @cite lin1983error (Chapter 4 - Cyclic Codes),
 * We perform a systematic encoding using a linear
 * (PARAM_N1 - PARAM_K)-stage shift register with feedback connections based on
 * the generator polynomial PARAM_RS_POLY of the Reed-Solomon code.
 *
 * @param[out] cdw Array of size VEC_N1_SIZE_64 receiving the encoded message
 * @param[in] msg Array of size VEC_K_SIZE_64 storing the message
 */
void reed_solomon_encode(uint8_t *cdw, const uint8_t *msg)
{
	size_t i, j, k;
	uint8_t gate_value = 0;
	uint16_t tmp[LC_HQC_PARAM_G] = { 0 };

	memset(cdw, 0, LC_HQC_PARAM_N1);

	for (i = 0; i < LC_HQC_PARAM_K; ++i) {
		gate_value = msg[LC_HQC_PARAM_K - 1 - i] ^
			     cdw[LC_HQC_PARAM_N1 - LC_HQC_PARAM_K - 1];

		for (j = 0; j < LC_HQC_PARAM_G; ++j)
			tmp[j] = gf_mul(gate_value, PARAM_RS_POLY[j]);

		for (k = LC_HQC_PARAM_N1 - LC_HQC_PARAM_K - 1; k; --k)
			cdw[k] = (uint8_t)(cdw[k - 1] ^ tmp[k]);

		cdw[0] = (uint8_t)tmp[0];
	}

	memcpy(cdw + LC_HQC_PARAM_N1 - LC_HQC_PARAM_K, msg, LC_HQC_PARAM_K);
}

/**
 * @brief Computes 2 * PARAM_DELTA syndromes
 *
 * @param[out] syndromes Array of size 2 * PARAM_DELTA receiving the computed
 *			 syndromes
 * @param[in] cdw Array of size PARAM_N1 storing the received vector
 */
static void compute_syndromes(uint16_t *syndromes, uint8_t *cdw)
{
	size_t i, j;

	for (i = 0; i < 2 * LC_HQC_PARAM_DELTA; ++i) {
		for (j = 1; j < LC_HQC_PARAM_N1; ++j)
			syndromes[i] ^= gf_mul(cdw[j], alpha_ij_pow[i][j - 1]);

		syndromes[i] ^= cdw[0];
	}
}

/**
 * @brief Computes the error locator polynomial (ELP) sigma
 *
 * This is a constant time implementation of Berlekamp's simplified algorithm
 * (see @cite lin1983error (Chapter 6 - BCH Codes). <br>
 * We use the letter p for rho which is initialized at -1. <br>
 * The array X_sigma_p represents the polynomial X^(mu-rho)*sigma_p(X). <br>
 * Instead of maintaining a list of sigmas, we update in place both sigma and
 * X_sigma_p. <br>
 * sigma_copy serves as a temporary save of sigma in case X_sigma_p needs to be
 * updated. <br>
 * We can properly correct only if the degree of sigma does not exceed
 * LC_HQC_PARAM_DELTA.
 * This means only the first PARAM_DELTA + 1 coefficients of sigma are of value
 * and we only need to save its first LC_HQC_PARAM_DELTA - 1 coefficients.
 *
 * @param[out] sigma Array of size (at least) PARAM_DELTA receiving the ELP
 * @param[in] syndromes Array of size (at least) 2*PARAM_DELTA storing the
 *			syndromes
 *
 * @returns the degree of the ELP sigma
 */
static uint16_t compute_elp(uint16_t *sigma, const uint16_t *syndromes)
{
	uint16_t deg_sigma = 0;
	uint16_t deg_sigma_p = 0;
	uint16_t deg_sigma_copy = 0;
	uint16_t sigma_copy[LC_HQC_PARAM_DELTA + 1] = { 0 };
	uint16_t X_sigma_p[LC_HQC_PARAM_DELTA + 1] = { 0, 1 };
	uint16_t pp = (uint16_t)-1; // 2*rho
	uint16_t d_p = 1;
	uint16_t d = syndromes[0];

	uint16_t mask1, mask2, mask12;
	uint16_t deg_X, deg_X_sigma_p;
	uint16_t dd;
	uint16_t mu;

	uint16_t i;

	sigma[0] = 1;
	for (mu = 0; (mu < (2 * LC_HQC_PARAM_DELTA)); ++mu) {
		/* Save sigma in case we need it to update X_sigma_p */
		memcpy(sigma_copy, sigma, 2 * (LC_HQC_PARAM_DELTA));
		deg_sigma_copy = deg_sigma;

		dd = gf_mul(d, gf_inverse(d_p));

		for (i = 1; (i <= mu + 1) && (i <= LC_HQC_PARAM_DELTA); ++i)
			sigma[i] ^= gf_mul(dd, X_sigma_p[i]);

		deg_X = mu - pp;
		deg_X_sigma_p = deg_X + deg_sigma_p;

		/* mask1 = 0xffff if(d != 0) and 0 otherwise */
		mask1 = -((uint16_t)-d >> 15);

		/*
		 * mask2 = 0xffff if(deg_X_sigma_p > deg_sigma) and 0 otherwise
		 */
		mask2 = -((uint16_t)(deg_sigma - deg_X_sigma_p) >> 15);

		/* mask12 = 0xffff if the deg_sigma increased and 0 otherwise */
		mask12 = mask1 & mask2;
		deg_sigma ^= mask12 & (deg_X_sigma_p ^ deg_sigma);

		if (mu == (2 * LC_HQC_PARAM_DELTA - 1))
			break;

		pp ^= mask12 & (mu ^ pp);
		d_p ^= mask12 & (d ^ d_p);
		for (i = LC_HQC_PARAM_DELTA; i; --i) {
			X_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^
				       (~mask12 & X_sigma_p[i - 1]);
		}

		deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
		d = syndromes[mu + 1];

		for (i = 1; (i <= mu + 1) && (i <= LC_HQC_PARAM_DELTA); ++i)
			d ^= gf_mul(sigma[i], syndromes[mu + 1 - i]);
	}

	return deg_sigma;
}

/**
 * @brief Computes the error polynomial error from the error locator polynomial
 * sigma
 *
 * See function fft for more details.
 *
 * @param[out] error Array of 2^PARAM_M elements receiving the error polynomial
 * @param[in] sigma Array of 2^LC_HQC_PARAM_FFT elements storing the error
 *		    locator polynomial
 * @param[in] ws workspace
 */
static void compute_roots(uint8_t *error, uint16_t *sigma,
			  struct reed_solomon_decode_ws *ws)
{
	fft(ws->compute_roots_w, sigma, LC_HQC_PARAM_DELTA + 1);
	fft_retrieve_error_poly(error, ws->compute_roots_w);
}

/**
 * @brief Computes the polynomial z(x)
 *
 * See @cite lin1983error (Chapter 6 - BCH Codes) for more details.
 *
 * @param[out] z Array of LC_HQC_PARAM_DELTA + 1 elements receiving the
 *		 polynomial z(x)
 * @param[in] sigma Array of 2^LC_HQC_PARAM_FFT elements storing the error
 *		    locator polynomial
 * @param[in] degree Integer that is the degree of polynomial sigma
 * @param[in] syndromes Array of 2 * LC_HQC_PARAM_DELTA storing the syndromes
 */
static void compute_z_poly(uint16_t *z, const uint16_t *sigma, uint16_t degree,
			   const uint16_t *syndromes)
{
	size_t i, j;
	uint16_t mask;

	z[0] = 1;

	for (i = 1; i < LC_HQC_PARAM_DELTA + 1; ++i) {
		mask = -((uint16_t)(i - degree - 1) >> 15);
		z[i] = mask & sigma[i];
	}

	z[1] ^= syndromes[0];

	for (i = 2; i <= LC_HQC_PARAM_DELTA; ++i) {
		mask = -((uint16_t)(i - degree - 1) >> 15);
		z[i] ^= mask & syndromes[i - 1];

		for (j = 1; j < i; ++j)
			z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1]);
	}
}

/**
 * @brief Computes the error values
 *
 * See @cite lin1983error (Chapter 6 - BCH Codes) for more details.
 *
 * @param[out] error_values Array of LC_HQC_PARAM_DELTA elements receiving the
 *			    error values
 * @param[in] z Array of LC_HQC_PARAM_DELTA + 1 elements storing the polynomial
 *		z(x)
 * @param[in] error Array of the error vector
 */
static void compute_error_values(uint16_t *error_values, const uint16_t *z,
				 const uint8_t *error)
{
	size_t i, j, k;
	uint16_t beta_j[LC_HQC_PARAM_DELTA] = { 0 };
	uint16_t e_j[LC_HQC_PARAM_DELTA] = { 0 };

	uint16_t delta_counter;
	uint16_t delta_real_value;
	uint16_t found;
	uint16_t mask1;
	uint16_t mask2;
	uint16_t tmp1;
	uint16_t tmp2;
	uint16_t inverse;
	uint16_t inverse_power_j;

	/* Compute the beta_{j_i} page 31 of the documentation */
	delta_counter = 0;
	for (i = 0; i < LC_HQC_PARAM_N1; i++) {
		found = 0;

		// error[i] != 0
		mask1 = (uint16_t)(-((int32_t)error[i]) >> 31);

		for (j = 0; j < LC_HQC_PARAM_DELTA; j++) {
			// j == delta_counter
			mask2 = ~((uint16_t)(-((int32_t)j ^ delta_counter) >>
					     31));

			beta_j[j] += mask1 & mask2 & gf_exp[i];
			found += mask1 & mask2 & 1;
		}
		delta_counter += found;
	}
	delta_real_value = delta_counter;

	/* Compute the e_{j_i} page 31 of the documentation */
	for (i = 0; i < LC_HQC_PARAM_DELTA; ++i) {
		tmp1 = 1;
		tmp2 = 1;
		inverse = gf_inverse(beta_j[i]);
		inverse_power_j = 1;

		for (j = 1; j <= LC_HQC_PARAM_DELTA; ++j) {
			inverse_power_j = gf_mul(inverse_power_j, inverse);
			tmp1 ^= gf_mul(inverse_power_j, z[j]);
		}
		for (k = 1; k < LC_HQC_PARAM_DELTA; ++k) {
			tmp2 = gf_mul(
				tmp2,
				(1 ^
				 gf_mul(inverse,
					beta_j[(i + k) % LC_HQC_PARAM_DELTA])));
		}

		// i < delta_real_value
		mask1 = (uint16_t)(((int16_t)i - delta_real_value) >> 15);
		e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2));
	}

	/*
	 * Place the delta e_{j_i} values at the right coordinates of the output
	 * vector.
	 */
	delta_counter = 0;
	for (i = 0; i < LC_HQC_PARAM_N1; ++i) {
		found = 0;

		// error[i] != 0
		mask1 = (uint16_t)(-((int32_t)error[i]) >> 31);
		for (j = 0; j < LC_HQC_PARAM_DELTA; j++) {
			// j == delta_counter
			mask2 = ~((uint16_t)(-((int32_t)j ^ delta_counter) >>
					     31));

			error_values[i] += mask1 & mask2 & e_j[j];
			found += mask1 & mask2 & 1;
		}
		delta_counter += found;
	}
}

/**
 * @brief Correct the errors
 *
 * @param[out] cdw Array of PARAM_N1 elements receiving the corrected vector
 * @param[in] error_values Array of LC_HQC_PARAM_DELTA elements storing the
 *			   error values
 */
static void correct_errors(uint8_t *cdw, const uint16_t *error_values)
{
	for (size_t i = 0; i < LC_HQC_PARAM_N1; ++i)
		cdw[i] ^= (uint8_t)error_values[i];
}

/**
 * @brief Decodes the received word
 *
 * This function relies on six steps:
 *    <ol>
 *    <li> The first step, is the computation of the 2*PARAM_DELTA syndromes.
 *    <li> The second step is the computation of the error-locator polynomial sigma.
 *    <li> The third step, done by additive FFT, is finding the error-locator numbers by calculating the roots of the polynomial sigma and takings their inverses.
 *    <li> The fourth step, is the polynomial z(x).
 *    <li> The fifth step, is the computation of the error values.
 *    <li> The sixth step is the correction of the errors in the received polynomial.
 *    </ol>
 * For a more complete picture on Reed-Solomon decoding, see Shu. Lin and Daniel
 * J. Costello in Error Control Coding: Fundamentals and Applications
 * @cite lin1983error
 *
 * @param[out] msg Array of size VEC_K_SIZE_64 receiving the decoded message
 * @param[in] cdw Array of size VEC_N1_SIZE_64 storing the received word
 */
void reed_solomon_decode(uint8_t *msg, uint8_t *cdw,
			 struct reed_solomon_decode_ws *ws)
{
	uint16_t deg;

	/* Calculate the 2*LC_HQC_PARAM_DELTA syndromes */
	compute_syndromes(ws->syndromes, cdw);

	/*
	 * Compute the error locator polynomial sigma
	 * Sigma's degree is at most LC_HQC_PARAM_DELTA but the FFT requires the
	 * extra room.
	 */
	deg = compute_elp(ws->sigma, ws->syndromes);

	/* Compute the error polynomial error */
	compute_roots(ws->error, ws->sigma, ws);

	/* Compute the polynomial z(x) */
	compute_z_poly(ws->z, ws->sigma, deg, ws->syndromes);

	/* Compute the error values */
	compute_error_values(ws->error_values, ws->z, ws->error);

	/* Correct the errors */
	correct_errors(cdw, ws->error_values);

	/* Retrieve the message from the decoded codeword */
	memcpy(msg, cdw + (LC_HQC_PARAM_G - 1), LC_HQC_PARAM_K);
}
