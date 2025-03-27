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

#ifndef KYBER_POLY_TOMSG_H
#define KYBER_POLY_TOMSG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_tomsg - Convert polynomial to 32-byte message
 *
 * @param [out] msg pointer to output message
 * @param [in] a pointer to input polynomial
 */
static inline void poly_tomsg(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES],
			      const poly *a)
{
	unsigned int i, j;
	uint32_t t;

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		msg[i] = 0;
		for (j = 0; j < 8; j++) {
			t = (uint32_t)a->coeffs[8 * i + j];

			t <<= 1;
			t += LC_KYBER_Q - (LC_KYBER_Q / 2);
			t *= 80635;
			t >>= 28;
			t &= 1;
			msg[i] |= (uint8_t)(t << j);
		}
	}
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_TOMSG_H */
