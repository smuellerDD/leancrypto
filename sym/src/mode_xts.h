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

#ifndef MODE_XTS_H
#define MODE_XTS_H

#include "lc_sym.h"

#ifdef __cplusplus
extern "C" {
#endif

union lc_xts_tweak {
	uint64_t qw[2];
	uint32_t dw[4];
	uint8_t b[AES_BLOCKLEN];
};

struct lc_mode_state {
	union lc_xts_tweak tweak;
	const struct lc_sym *wrapped_cipher;
	const struct lc_sym *tweak_cipher;
	void *wrapped_cipher_ctx;
	void *tweak_cipher_ctx;
};

/*
 * Implement the "Multiplication by a primitive element alpha" as specified
 * in section 5.2 of "The XTS-AES Tweakable Block Cipher An Extract from IEEE
 * Std 1619-2007"
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline void gfmul_alpha(union lc_xts_tweak *t)
{
	/*
	 * This function works both on big and little endian, but has a bit
	 * more instructions than the streamlined little endian implementation.
	 * Thus, it is limited to big-endian only.
	 */
	uint8_t i = AES_BLOCKLEN;
	uint8_t carry = t->b[AES_BLOCKLEN - 1] & 0x80;

#pragma GCC unroll 16
	while (--i) {
		t->b[i] <<= 1;
		t->b[i] |= (t->b[(i - 1)] & 0x80 ? 1 : 0);
	}
	t->b[0] = (uint8_t)(t->b[0] << 1) ^ (carry ? 0x87 : 0);
}

#else /* __ORDER_BIG_ENDIAN__ */

static inline void gfmul_alpha(union lc_xts_tweak *t)
{
	unsigned int carry, res;

	res = 0x87 & (((int)t->dw[3]) >> 31);
	carry = (unsigned int)(t->qw[0] >> 63);
	t->qw[0] = (t->qw[0] << 1) ^ res;
	t->qw[1] = (t->qw[1] << 1) | carry;
}
#endif /* __ORDER_BIG_ENDIAN__ */

void mode_xts_selftest(const struct lc_sym *aes);

extern const struct lc_sym_mode *lc_mode_xts_c;

#ifdef __cplusplus
}
#endif

#endif /* MODE_XTS_H */
