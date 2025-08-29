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

struct lc_mode_state {
	/*
	 * Put tweak at the beginning to ensure it is aligned to at least
	 * 64 bit based on the LC_SYM_COMMON_ALIGNMENT
	 */
	uint8_t tweak[AES_BLOCKLEN];
	const struct lc_sym *wrapped_cipher;
	void *wrapped_cipher_ctx;
	void *tweak_cipher_ctx;
};

void mode_xts_selftest(const struct lc_sym *aes, int *tested, const char *impl);

extern const struct lc_sym_mode *lc_mode_xts_c;

#ifdef __cplusplus
}
#endif

#endif /* MODE_XTS_H */
