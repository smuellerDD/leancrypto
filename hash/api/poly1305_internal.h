/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef POLY1305_INTERNAL_H
#define POLY1305_INTERNAL_H

#include "lc_poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @param key 32 byte key that is **only used for this message and is discarded
 *	      immediately after**
 */
void lc_poly1305_init(struct lc_poly1305_context *ctx,
		      const uint8_t key[LC_POLY1305_KEYSIZE]);

/*
 * @param m pointer to the message fragment to be processed
 * @param bytes length of the message fragment
 */
void lc_poly1305_update(struct lc_poly1305_context *ctx, const uint8_t *m,
			size_t bytes);

/*
 * @param mac buffer which receives the 16 byte authenticator. After calling
 *	      finish, the underlying implementation will zero out `ctx`
 */
void lc_poly1305_final(struct lc_poly1305_context *ctx,
		       uint8_t mac[LC_POLY1305_TAGSIZE]);

/*
 * @param mac the buffer which receives the 16 byte authenticator
 * @param m pointer to the message to be processed
 * @param bytes number of bytes in the message
 * @param key 32 byte key that is **only used for this message and is
 *	      discarded immediately after**
 */
void lc_poly1305_auth(uint8_t mac[LC_POLY1305_TAGSIZE], const uint8_t *m,
		      size_t bytes, const uint8_t key[LC_POLY1305_KEYSIZE]);

/*
 * @param mac1 is compared to @param mac2 in constant time and returns 0 if
 * they are equal and !0 if they are not
 */
int lc_poly1305_verify(const uint8_t mac1[LC_POLY1305_TAGSIZE],
		       const uint8_t mac2[LC_POLY1305_TAGSIZE]);

#if 0
/*
 * Tests the underlying implementation to verify it is working correctly.
 *
 * @return 0 if all tests pass, and !0 if any tests fail.
 */
void lc_poly1305_power_on_self_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLY1305_INTERNAL_H */
