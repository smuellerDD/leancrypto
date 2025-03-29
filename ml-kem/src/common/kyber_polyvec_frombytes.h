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

#ifndef KYBER_POLYVEC_FROMBYTES_H
#define KYBER_POLYVEC_FROMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief polyvec_frombytes - De-serialize vector of polynomials;
 *			      inverse of polyvec_tobytes
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input vector of polynomials
 */
static inline void polyvec_frombytes(polyvec *r,
				     const uint8_t a[LC_KYBER_POLYVECBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_frombytes(&r->vec[i], a + i * LC_KYBER_POLYBYTES);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_FROMBYTES_H */
