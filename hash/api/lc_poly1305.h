/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * This file is derived from
 * https://github.com/floodyberry/poly1305-donna marked as "PUBLIC DOMAIN"
 */

#ifndef LC_POLY1305_H
#define LC_POLY1305_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_poly1305_context {
	size_t aligner;
	uint8_t opaque[136];
};

#define LC_POLY1305_STATE_SIZE (sizeof(struct lc_poly1305_context))
#define LC_POLY1305_TAGSIZE (16)
#define LC_POLY1305_KEYSIZE (32)

/**
 * @brief Initialize the Poly1305 algorithm with a key
 *
 * \note The \p ctx can be allocated either on heap or stack. Once done,
 * it should be zeroized to provide a clean slate.
 *
 * \warning This algorithm is intended only in conjunction with ChaCha20
 * to form ChaCha20-Poly1305. For some use cases (like SSH), a separate access
 * to the algorithm is needed and thus provided with this API.
 *
 * @param [in] ctx Poly1305 context holding the state
 * @param [in] key 32 byte key that is **only used for this message and is
 *		   discarded immediately after**
 */
void lc_poly1305_init(struct lc_poly1305_context *ctx,
		      const uint8_t key[LC_POLY1305_KEYSIZE]);

/**
 * @brief Add data to the Poly1305 context to digest it
 *
 * @param [in] ctx Poly1305 context holding the state
 * @param [in] m pointer to the message fragment to be processed
 * @param [in] bytes length of the message fragment in bytes
 */
void lc_poly1305_update(struct lc_poly1305_context *ctx, const uint8_t *m,
			size_t bytes);

/**
 * @brief Calculate the Poly1305 keyed message digest from the state
 *
 * \note With the call to this API, the context may not be needed any more and
 * should be zeroized at this point to prevent leaving potentially sensitive
 * data in memory.
 *
 * @param [in] ctx Poly1305 context holding the state
 * @param [in] mac buffer which receives the 16 byte authenticator.
 */
void lc_poly1305_final(struct lc_poly1305_context *ctx,
		       uint8_t mac[LC_POLY1305_TAGSIZE]);

#ifdef __cplusplus
}
#endif

#endif /* LC_POLY1305_H */
