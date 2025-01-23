/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "kyber_debug.h"

void kyber_print_buffer(const uint8_t *buffer, const size_t bufferlen,
			const char *explanation)
{
	bin2print(buffer, bufferlen, stdout, explanation);
}

void kyber_print_polyvec(polyvec *polyvec_val, const char *explanation)
{
	unsigned int i, j;

	printf("%s", explanation);
	for (i = 0; i < LC_KYBER_K; i++) {
		printf("\nK(%u) x N: ", i);
		for (j = 0; j < LC_KYBER_N; j++) {
			printf("%d ", polyvec_val->vec[i].coeffs[j]);
		}
	}
	printf("\n");
}

void kyber_print_polyveck(polyvec *polyvec_val, const char *explanation)
{
	unsigned int i, j, k;

	printf("%s", explanation);
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_K; j++) {
			printf("\nK(%u) x K(%u) x N: ", i, j);
			for (k = 0; k < LC_KYBER_N; k++) {
				printf("%d ", polyvec_val[i].vec[j].coeffs[k]);
			}
		}
	}
	printf("\n");
}

void kyber_print_poly(poly *vec, const char *explanation)
{
	unsigned int i;

	printf("%s\n", explanation);
	for (i = 0; i < LC_KYBER_N; i++) {
		printf("%d ", vec->coeffs[i]);
	}
	printf("\n");
}
