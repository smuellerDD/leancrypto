/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "kyber_cbd.h"

/**
 * @brief load32_littleendian - load 4 bytes into a 32-bit integer
 *				in little-endian order
 *
 * @param x [in] pointer to input byte array
 *
 * @return 32-bit unsigned integer loaded from x
 */
static uint32_t load32_littleendian(const uint8_t x[4])
{
	uint32_t r;

	r = (uint32_t)x[0];
	r |= (uint32_t)x[1] << 8;
	r |= (uint32_t)x[2] << 16;
	r |= (uint32_t)x[3] << 24;
	return r;
}

/**
 * @brief load24_littleendian - load 3 bytes into a 32-bit integer in
 *				little-endian order. This function is only
 *				needed for Kyber-512
 *
 * @param x [in] pointer to input byte array
 *
 * @return 32-bit unsigned integer loaded from x (most significant byte is zero)
 */
//#if LC_KYBER_ETA1 == 3
static uint32_t load24_littleendian(const uint8_t x[3])
{
	uint32_t r;

	r = (uint32_t)x[0];
	r |= (uint32_t)x[1] << 8;
	r |= (uint32_t)x[2] << 16;
	return r;
}
//#endif

/**
 * @brief cbd2 - Given an array of uniformly random bytes, compute polynomial
 *		 with coefficients distributed according to a centered binomial
 *		 distribution with parameter eta=2
 *
 * @param r [out] pointer to output polynomial
 * @param buf in pointer to input byte array
 */
void cbd2(poly *r, const uint8_t buf[2 * LC_KYBER_N / 4])
{
	unsigned int i, j;
	uint32_t t, d;
	int16_t a, b;

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		t = load32_littleendian(buf + 4 * i);
		d = t & 0x55555555;
		d += (t >> 1) & 0x55555555;

		for (j = 0; j < 8; j++) {
			a = (d >> (4 * j + 0)) & 0x3;
			b = (d >> (4 * j + 2)) & 0x3;
			r->coeffs[8 * i + j] = a - b;
		}
	}
}

/**
 * @brief cbd3 - Given an array of uniformly random bytes, compute
 *		 polynomial with coefficients distributed according to
 *		 a centered binomial distribution with parameter eta=3.
 *		 This function is only needed for Kyber-512
 *
 * @param r [out] pointer to output polynomial
 * @param buf [in] pointer to input byte array
 */
//#if LC_KYBER_ETA1 == 3
void cbd3(poly *r, const uint8_t buf[3 * LC_KYBER_N / 4])
{
	unsigned int i, j;
	uint32_t t, d;
	int16_t a, b;

	for (i = 0; i < LC_KYBER_N / 4; i++) {
		t = load24_littleendian(buf + 3 * i);
		d = t & 0x00249249;
		d += (t >> 1) & 0x00249249;
		d += (t >> 2) & 0x00249249;

		for (j = 0; j < 4; j++) {
			a = (d >> (6 * j + 0)) & 0x7;
			b = (d >> (6 * j + 3)) & 0x7;
			r->coeffs[4 * i + j] = a - b;
		}
	}
}
//#endif
