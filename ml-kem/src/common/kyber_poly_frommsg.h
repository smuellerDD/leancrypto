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

#ifndef KYBER_POLY_FROMMSG_H
#define KYBER_POLY_FROMMSG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_frommsg - Convert 32-byte message to polynomial
 *
 * @param [out] r pointer to output polynomial
 * @param [in] msg pointer to input message
 */
static inline void poly_frommsg(poly *r,
				const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES])
{
	unsigned int i, j;
	int16_t mask, opt_blocker;

	/*
	 * Goal: copy variable only depending on a given condition without
	 * the use of a branching operation which alters the timing behavior
	 * depending on the condition. As the condition here depends on
	 * secret data (the msg variable), the code has to ensure that no
	 * branching is used to have time-invariant code. This solution
	 * below also shall ensure that the compiler cannot optimize this code
	 * such that it brings back the branching.
	 *
	 * An exploit of the timing channel that would be present with a
	 * branching operation is available at
	 * https://github.com/antoonpurnal/clangover which reportedly
	 * needs <10 minutes for ML-KEM 512 key recovery. More details about
	 * the exploit is given in https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/
	 *
	 * (mask ^ opt_blocker) can be any value at run-time to the compiler,
	 * making it impossible to skip the computation (except the compiler
	 * would care to create a branch for opt_blocker to be either
	 * 0 or -1, which would be extremely unlikely). Yet the volatile
	 * variable has to be loaded only once at the beginning of the function
	 * call.
	 */
	opt_blocker = optimization_blocker_int16;

#if (LC_KYBER_INDCPA_MSGBYTES != LC_KYBER_N / 8)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to LC_KYBER_N/8 bytes!"
#endif

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			/*
			 * Calculate condition when a variable shall be
			 * copied. This depends on the secret msg. The mask is
			 * either zero or all bits are 1.
			 */
			mask = -(int16_t)((msg[i] >> j) & 1);

			/*
			 * XOR the mask with a zero value which is obtained from
			 * a volatile variable to ensure the compiler cannot
			 * turn this into a branching operation. This does not
			 * alter the mask, but is intended to prevent the
			 * compiler to be clever and add a branching instruction
			 * instead.
			 *
			 * See https://microblog.cr.yp.to/1713627640/ for
			 * an analysis.
			 */
			r->coeffs[8 * i + j] =
				(mask ^ opt_blocker) & ((LC_KYBER_Q + 1) / 2);
		}
	}
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_FROMMSG_H */
