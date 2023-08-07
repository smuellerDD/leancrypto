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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#include "kyber_poly_armv8.h"

void poly_compress_armv8(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES], const poly *a)
{
	unsigned int i, j;
	int16_t u;
	uint8_t t[8];

#if (LC_KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			// map to positive standard representatives
			u = a->coeffs[8 * i + j];
			u += (u >> 15) & LC_KYBER_Q;
			t[j] = ((((uint16_t)u << 4) + LC_KYBER_Q / 2) /
				LC_KYBER_Q) &
			       15;
		}

		r[0] = (uint8_t)(t[0] | (t[1] << 4));
		r[1] = (uint8_t)(t[2] | (t[3] << 4));
		r[2] = (uint8_t)(t[4] | (t[5] << 4));
		r[3] = (uint8_t)(t[6] | (t[7] << 4));
		r += 4;
	}
#elif (LC_KYBER_POLYCOMPRESSEDBYTES == 160)
	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			// map to positive standard representatives
			u = a->coeffs[8 * i + j];
			u += (u >> 15) & LC_KYBER_Q;
			t[j] = ((((uint32_t)u << 5) + LC_KYBER_Q / 2) /
				LC_KYBER_Q) &
			       31;
		}

		r[0] = (uint8_t)((t[0] >> 0) | (t[1] << 5));
		r[1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
		r[2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
		r[3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
		r[4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
		r += 5;
	}
#else
#error "LC_KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

void poly_decompress_armv8(poly *r,
			   const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES])
{
	unsigned int i;

#if (LC_KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < LC_KYBER_N / 2; i++) {
		r->coeffs[2 * i + 0] =
			(int16_t)((((uint16_t)(a[0] & 15) * LC_KYBER_Q) + 8) >>
				  4);
		r->coeffs[2 * i + 1] =
			(int16_t)((((uint16_t)(a[0] >> 4) * LC_KYBER_Q) + 8) >>
				  4);
		a += 1;
	}
#elif (LC_KYBER_POLYCOMPRESSEDBYTES == 160)
	unsigned int j;
	uint8_t t[8];
	for (i = 0; i < LC_KYBER_N / 8; i++) {
		t[0] = (uint8_t)(a[0] >> 0);
		t[1] = (uint8_t)((a[0] >> 5) | (a[1] << 3));
		t[2] = (uint8_t)(a[1] >> 2);
		t[3] = (uint8_t)((a[1] >> 7) | (a[2] << 1));
		t[4] = (uint8_t)((a[2] >> 4) | (a[3] << 4));
		t[5] = (uint8_t)(a[3] >> 1);
		t[6] = (uint8_t)((a[3] >> 6) | (a[4] << 2));
		t[7] = (uint8_t)(a[4] >> 3);
		a += 5;

		for (j = 0; j < 8; j++)
			r->coeffs[8 * i + j] =
				(int16_t)(((uint32_t)(t[j] & 31) * LC_KYBER_Q +
					   16) >>
					  5);
	}
#else
#error "LC_KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}
