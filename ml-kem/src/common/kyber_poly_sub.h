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

#ifndef KYBER_POLY_SUB_H
#define KYBER_POLY_SUB_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_sub - Subtract two polynomials; no modular reduction is performed
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial
 */
static inline void poly_sub(poly *r, const poly *a, const poly *b)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_SUB_H */
