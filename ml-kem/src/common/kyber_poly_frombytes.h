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

#ifndef KYBER_POLY_FROMBYTES_H
#define KYBER_POLY_FROMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_frombytes - De-serialization of a polynomial;
 *			   inverse of poly_tobytes
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to input byte array
 */
static inline void poly_frombytes(poly *r, const uint8_t a[LC_KYBER_POLYBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N / 2; i++) {
		r->coeffs[2 * i] =
			((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) &
			0xFFF;
		r->coeffs[2 * i + 1] =
			((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) &
			0xFFF;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_FROMBYTES_H */
