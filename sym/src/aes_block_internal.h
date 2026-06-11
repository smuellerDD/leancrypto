/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef AES_BLOCK_INTERNAL_H
#define AES_BLOCK_INTERNAL_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_sym_state;

int aes_crypt_iv(const struct lc_sym_state *ctx, const uint8_t *in,
		 uint8_t *out, size_t len, uint8_t *iv, size_t ivlen);
int aes_init_iv(const struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen);
int aes_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen);
int aes_getiv(const struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen);

#ifdef __cplusplus
}
#endif

#endif /* AES_BLOCK_INTERNAL_H */
