/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef AES_SCR_HELPER_H
#define AES_SCR_HELPER_H

#include "ext_headers.h"
#include "null_buffer.h"
#include "rotate.h"
#include "timecop.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Helper functions for side-channel-resistant operation by not using an S-Box.
 */

static inline uint32_t gf_mul2(uint32_t w)
{
	uint32_t t = w & 0x80808080;

	return ((w ^ t) << 1) ^ ((t >> 7) * 0x0000001B);
}

/*
 * multiplicative inverse
 */
static inline uint8_t gf_mulinv(uint8_t x)
{
	uint8_t y = x, i;

	/*
	 * TODO - this is code having conditionals on potentially sensitive
	 * data (e.g. when invoked from the code to set up the key schedule).
	 * This should be eliminated.
	 */
	unpoison(&x, 1);
	unpoison(&y, 1);
	if (x) {
		// calculate logarithm gen 3
		for (i = 1, y = 1; i > 0; i++) {
			y ^= (uint8_t)gf_mul2(y);
			if (y == x)
				break;
		}
		x = ~i;
		// calculate anti-logarithm gen 3
		for (i = 0, y = 1; i < x; i++) {
			y ^= (uint8_t)gf_mul2(y);
		}
	}
	return y;
}

/*
 * Substitute one byte
 */
static inline uint8_t aes_sub_byte(uint8_t x)
{
	x = gf_mulinv(x);
	x ^= rol8(x, 1) ^ rol8(x, 2) ^ rol8(x, 3) ^ rol8(x, 4);
	x ^= 0x63;

	return x;
}

static inline uint8_t aes_sub_byte_inv(uint8_t x)
{
	x ^= 0x63;
	x = rol8(x, 1) ^ rol8(x, 3) ^ rol8(x, 6);
	x = gf_mulinv(x);

	return x;
}

/*
 * Substitute four bytes
 */
static inline uint32_t aes_sub_word(uint32_t x)
{
	uint8_t i;
	uint32_t r = 0;

	for (i = 0; i < 4; i++) {
		r |= aes_sub_byte(x & 0xFF);
		r = ror32(r, 8);
		x >>= 8;
	}
	return r;
}

#ifdef __cplusplus
}
#endif

#endif /* AES_SCR_HELPER_H */
