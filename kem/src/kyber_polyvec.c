/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "kyber_poly.h"
#include "kyber_polyvec.h"

void polyvec_compress(uint8_t r[LC_KYBER_POLYVECCOMPRESSEDBYTES],
		      const polyvec *a)
{
	unsigned int i, j, k;

#if (LC_KYBER_POLYVECCOMPRESSEDBYTES == (LC_KYBER_K * 352))
	uint16_t t[8];
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_N / 8; j++) {
			for (k = 0; k < 8; k++) {
				t[k] = (uint16_t)a->vec[i].coeffs[8 * j + k];
				t[k] += ((int16_t)t[k] >> 15) & LC_KYBER_Q;
				t[k] = ((((uint32_t)t[k] << 11) +
					 LC_KYBER_Q / 2) /
					LC_KYBER_Q) &
				       0x7ff;
			}

			r[0] = (uint8_t)(t[0] >> 0);
			r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 3));
			r[2] = (uint8_t)((t[1] >> 5) | (t[2] << 6));
			r[3] = (uint8_t)(t[2] >> 2);
			r[4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
			r[5] = (uint8_t)((t[3] >> 7) | (t[4] << 4));
			r[6] = (uint8_t)((t[4] >> 4) | (t[5] << 7));
			r[7] = (uint8_t)(t[5] >> 1);
			r[8] = (uint8_t)((t[5] >> 9) | (t[6] << 2));
			r[9] = (uint8_t)((t[6] >> 6) | (t[7] << 5));
			r[10] = (uint8_t)(t[7] >> 3);
			r += 11;
		}
	}
#elif (LC_KYBER_POLYVECCOMPRESSEDBYTES == (LC_KYBER_K * 320))
	uint16_t t[4];
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_N / 4; j++) {
			for (k = 0; k < 4; k++) {
				t[k] = (uint16_t)a->vec[i].coeffs[4 * j + k];
				t[k] += ((int16_t)t[k] >> 15) & LC_KYBER_Q;
				t[k] = ((((uint32_t)t[k] << 10) +
					 LC_KYBER_Q / 2) /
					LC_KYBER_Q) &
				       0x3ff;
			}

			r[0] = (uint8_t)(t[0] >> 0);
			r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
			r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
			r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
			r[4] = (uint8_t)(t[3] >> 2);
			r += 5;
		}
	}
#else
#error "LC_KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

void polyvec_decompress(polyvec *r,
			const uint8_t a[LC_KYBER_POLYVECCOMPRESSEDBYTES])
{
	unsigned int i, j, k;

#if (LC_KYBER_POLYVECCOMPRESSEDBYTES == (LC_KYBER_K * 352))
	uint16_t t[8];
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_N / 8; j++) {
			t[0] = (uint16_t)((a[0] >> 0) | ((uint16_t)a[1] << 8));
			t[1] = (uint16_t)((a[1] >> 3) | ((uint16_t)a[2] << 5));
			t[2] = (uint16_t)((a[2] >> 6) | ((uint16_t)a[3] << 2) |
					  ((uint16_t)a[4] << 10));
			t[3] = (uint16_t)((a[4] >> 1) | ((uint16_t)a[5] << 7));
			t[4] = (uint16_t)((a[5] >> 4) | ((uint16_t)a[6] << 4));
			t[5] = (uint16_t)((a[6] >> 7) | ((uint16_t)a[7] << 1) |
					  ((uint16_t)a[8] << 9));
			t[6] = (uint16_t)((a[8] >> 2) | ((uint16_t)a[9] << 6));
			t[7] = (uint16_t)((a[9] >> 5) | ((uint16_t)a[10] << 3));
			a += 11;

			for (k = 0; k < 8; k++)
				r->vec[i].coeffs[8 * j + k] =
					(int16_t)(((uint32_t)(t[k] & 0x7FF) *
							   LC_KYBER_Q +
						   1024) >>
						  11);
		}
	}
#elif (LC_KYBER_POLYVECCOMPRESSEDBYTES == (LC_KYBER_K * 320))
	uint16_t t[4];
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_N / 4; j++) {
			t[0] = (uint16_t)((a[0] >> 0) | ((uint16_t)a[1] << 8));
			t[1] = (uint16_t)((a[1] >> 2) | ((uint16_t)a[2] << 6));
			t[2] = (uint16_t)((a[2] >> 4) | ((uint16_t)a[3] << 4));
			t[3] = (uint16_t)((a[3] >> 6) | ((uint16_t)a[4] << 2));
			a += 5;

			for (k = 0; k < 4; k++)
				r->vec[i].coeffs[4 * j + k] =
					(int16_t)(((uint32_t)(t[k] & 0x3FF) *
							   LC_KYBER_Q +
						   512) >>
						  10);
		}
	}
#else
#error "LC_KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}
