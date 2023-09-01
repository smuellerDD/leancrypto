/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_DEBUG_H
#define DILITHIUM_DEBUG_H

#include "dilithium_polyvec.h"
#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_DILITHIUM_DEBUG

/* Disable selftests */
#define LC_DILITHIUM_TEST_INIT	1

void dilithium_print_buffer(const uint8_t *buffer, const size_t bufferlen,
			    const char *explanation);
void dilithium_print_polyvecl_k(polyvecl mat[LC_DILITHIUM_K],
			       const char *explanation);
void dilithium_print_polyvecl(polyvecl *poly, const char *explanation);
void dilithium_print_polyveck(polyveck *poly, const char *explanation);
void dilithium_print_poly(poly *poly, const char *explanation);

#else /* LC_DILITHIUM_DEBUG */

/* Enable selftests */
#define LC_DILITHIUM_TEST_INIT	0

static inline void dilithium_print_buffer(const uint8_t *buffer,
					  const size_t bufferlen,
					  const char *explanation)
{
	(void)buffer;
	(void)bufferlen;
	(void)explanation;
}

static inline void dilithium_print_polyvecl_k(polyvecl mat[LC_DILITHIUM_K],
					      const char *explanation)
{
	(void)mat;
	(void)explanation;
}

static inline void dilithium_print_polyvecl(polyvecl *poly,
					    const char *explanation)
{
	(void)poly;
	(void)explanation;
}

static inline void dilithium_print_polyveck(polyveck *poly,
					    const char *explanation)
{
	(void)poly;
	(void)explanation;
}

static inline void dilithium_print_poly(poly *poly, const char *explanation)
{
	(void)poly;
	(void)explanation;
}

#endif /* LC_DILITHIUM_DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_DEBUG_H */
