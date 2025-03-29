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

#ifndef KYBER_POLYVEC_INVNTT_H
#define KYBER_POLYVEC_INVNTT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief polyvec_invntt_tomont - Apply inverse NTT to all elements of a vector
 *				  of polynomials and multiply by Montgomery
 *				  factor 2^16
 *
 * @param [in,out] r pointer to in/output vector of polynomials
 */
static inline void polyvec_invntt_tomont(polyvec *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_invntt_tomont(&r->vec[i]);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_INVNTT_H */
