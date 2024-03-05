/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_DEBUG_H
#define KYBER_DEBUG_H

#include "kyber_poly.h"
#include "kyber_polyvec.h"
#include "lc_kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_KYBER_DEBUG

/* Disable selftests */
#define LC_KYBER_TEST_INIT 1

void kyber_print_buffer(const uint8_t *buffer, const size_t bufferlen,
			const char *explanation);
void kyber_print_polyvec(polyvec *polyvec_val, const char *explanation);
void kyber_print_polyveck(polyvec polyvec_val[LC_KYBER_K],
			  const char *explanation);
void kyber_print_poly(poly *vec, const char *explanation);

#else /* LC_KYBER_DEBUG */

/* Enable selftests */
#define LC_KYBER_TEST_INIT 0

static inline void kyber_print_buffer(const uint8_t *buffer,
				      const size_t bufferlen,
				      const char *explanation)
{
	(void)buffer;
	(void)bufferlen;
	(void)explanation;
}

static inline void kyber_print_polyvec(polyvec *polyvec_val,
				       const char *explanation)
{
	(void)polyvec_val;
	(void)explanation;
}

static inline void kyber_print_polyveck(polyvec polyvec_val[LC_KYBER_K],
					const char *explanation)
{
	(void)polyvec_val;
	(void)explanation;
}

static inline void kyber_print_poly(poly *vec, const char *explanation)
{
	(void)vec;
	(void)explanation;
}

#endif /* LC_KYBER_DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* KYBER_DEBUG_H */
