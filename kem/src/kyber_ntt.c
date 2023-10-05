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

#include "kyber_ntt.h"
#include "kyber_reduce.h"

void kyber_ntt(int16_t r[LC_KYBER_N])
{
	unsigned int len, start, j, k;
	int16_t t, zeta;

	k = 1;
	for (len = 128; len >= 2; len >>= 1) {
		for (start = 0; start < LC_KYBER_N; start = j + len) {
			zeta = zetas[k++];
			for (j = start; j < start + len; j++) {
				t = fqmul(zeta, r[j + len]);
				r[j + len] = r[j] - t;
				r[j] = r[j] + t;
			}
		}
	}
}

void kyber_invntt(int16_t r[LC_KYBER_N])
{
	unsigned int start, len, j, k;
	int16_t t, zeta;
	static const int16_t f = 1441; // mont^2/128

	k = 127;
	for (len = 2; len <= 128; len <<= 1) {
		for (start = 0; start < LC_KYBER_N; start = j + len) {
			zeta = zetas[k--];
			for (j = start; j < start + len; j++) {
				t = r[j];
				r[j] = barrett_reduce(t + r[j + len]);
				r[j + len] = r[j + len] - t;
				r[j + len] = fqmul(zeta, r[j + len]);
			}
		}
	}

	for (j = 0; j < LC_KYBER_N; j++)
		r[j] = fqmul(r[j], f);
}
