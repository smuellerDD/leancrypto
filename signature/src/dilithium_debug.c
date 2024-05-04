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

#include "binhexbin.h"

/* This code is only tuned to the C implementation */
#include "dilithium_type.h"
#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_c.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_c.h"

#include "dilithium_debug.h"

void dilithium_print_buffer(const uint8_t *buffer, const size_t bufferlen,
			    const char *explanation)
{
	bin2print(buffer, bufferlen, stdout, explanation);
}

void dilithium_print_polyvecl_k(polyvecl mat[LC_DILITHIUM_K],
				const char *explanation)
{
	unsigned int i, j, k;

	printf("%s", explanation);
	for (i = 0; i < LC_DILITHIUM_K; i++) {
		for (j = 0; j < LC_DILITHIUM_L; j++) {
			printf("\nK(%u) x L(%u) x N: ", i, j);
			for (k = 0; k < LC_DILITHIUM_N; k++)
				printf("0x%.8x ", mat[i].vec[j].coeffs[k]);
		}
	}
	printf("\n");
}

void dilithium_print_polyvecl(polyvecl *polyvec, const char *explanation)
{
	unsigned int i, j;

	printf("%s", explanation);
	for (i = 0; i < LC_DILITHIUM_L; i++) {
		printf("\nL(%u) x N: ", i);
		for (j = 0; j < LC_DILITHIUM_N; j++) {
			printf("%d ", polyvec->vec[i].coeffs[j]);
		}
	}
	printf("\n");
}

void dilithium_print_polyveck(polyveck *polyvec, const char *explanation)
{
	unsigned int i, j;

	printf("%s", explanation);
	for (i = 0; i < LC_DILITHIUM_K; i++) {
		printf("\nK(%u) x N: ", i);
		for (j = 0; j < LC_DILITHIUM_N; j++) {
			printf("%d ", polyvec->vec[i].coeffs[j]);
		}
	}
	printf("\n");
}

void dilithium_print_poly(poly *vec, const char *explanation)
{
	unsigned int i;

	printf("%s", explanation);
	for (i = 0; i < LC_DILITHIUM_N; i++) {
		printf("%d ", vec->coeffs[i]);
	}
	printf("\n");
}
