/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_SERVICE_HELPERS_H
#define DILITHIUM_SERVICE_HELPERS_H

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief rej_uniform - Sample uniformly random coefficients in [0, Q-1] by
 *			performing rejection sampling on array of random bytes.
 *
 * @param a [out] pointer to output array (allocated)
 * @param len [in] number of coefficients to be sampled
 * @param buf [in] array of random bytes
 * @param buflen [in] length of array of random bytes
 *
 * @return number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 */
static inline unsigned int rej_uniform(int32_t *a,
				       unsigned int len,
				       const uint8_t *buf,
				       unsigned int buflen)
{
	unsigned int ctr, pos;
	uint32_t t;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		t  = buf[pos++];
		t |= (uint32_t)buf[pos++] << 8;
		t |= (uint32_t)buf[pos++] << 16;
		t &= 0x7FFFFF;

		if (t < LC_DILITHIUM_Q)
			a[ctr++] = (int32_t)t;
	}

	return ctr;
}

/**
 * @brief rej_eta - Sample uniformly random coefficients in [-ETA, ETA] by
 *		    performing rejection sampling on array of random bytes.
 *
 * @param a [out] pointer to output array (allocated)
 * @param len [in] number of coefficients to be sampled
 * @param buf [in] array of random bytes
 * @param buflen [in] length of array of random bytes
 *
 * @return number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 */
static inline unsigned int rej_eta(int32_t *a,
				   unsigned int len,
				   const uint8_t *buf,
				   unsigned int buflen)
{
	unsigned int ctr, pos;
	int32_t t0, t1;

	ctr = pos = 0;
	while (ctr < len && pos < buflen) {
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;

#if LC_DILITHIUM_ETA == 2
		if (t0 < 15) {
			t0 = t0 - (205*t0 >> 10)*5;
			a[ctr++] = 2 - t0;
		}
		if (t1 < 15 && ctr < len) {
			t1 = t1 - (205*t1 >> 10)*5;
			a[ctr++] = 2 - t1;
		}
#elif LC_DILITHIUM_ETA == 4
		if (t0 < 9)
			a[ctr++] = 4 - t0;
		if (t1 < 9 && ctr < len)
			a[ctr++] = 4 - t1;
#else
#error "Undefined LC_DILITHIUM_ETA"
#endif
	}

	return ctr;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SERVICE_HELPERS_H */
