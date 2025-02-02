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

#ifndef KYBER_POLY_TOMONT_H
#define KYBER_POLY_TOMONT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_tomont - Inplace conversion of all coefficients of a polynomial
 *			from normal domain to Montgomery domain
 *
 * @param [in,out] r pointer to input/output polynomial
 */
static inline void poly_tomont(poly *r)
{
	unsigned int i;
	const int16_t f = (1ULL << 32) % LC_KYBER_Q;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_TOMONT_H */
