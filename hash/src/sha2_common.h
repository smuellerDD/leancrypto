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

#ifndef SHA2_COMMON_H
#define SHA2_COMMON_H

#include "lc_sha256.h"
#include "lc_sha512.h"

#ifdef __cplusplus
extern "C" {
#endif

void sha256_init(void *_state);

void sha256_update(struct lc_sha256_state *ctx, const uint8_t *in, size_t inlen,
		   void (*sha256_transform_block)(struct lc_sha256_state *ctx,
						  const uint8_t *in,
						  size_t blocks));

void sha256_final(struct lc_sha256_state *ctx, uint8_t *digest,
		  void (*sha256_transform_block)(struct lc_sha256_state *ctx,
						 const uint8_t *in,
						 size_t blocks));

size_t sha256_get_digestsize(void *_state);

/******************************************************************************/

void sha384_init(void *_state);
void sha512_init(void *_state);

void sha512_update(struct lc_sha512_state *ctx, const uint8_t *in, size_t inlen,
		   void (*sha512_transform_block)(struct lc_sha512_state *ctx,
						  const uint8_t *in,
						  size_t blocks));
void sha512_final(struct lc_sha512_state *ctx,
		  void (*sha512_transform_block)(struct lc_sha512_state *ctx,
						 const uint8_t *in,
						 size_t blocks));
void sha512_extract_bytes(const void *state, uint8_t *data, size_t offset,
			  size_t length);
size_t sha384_get_digestsize(void *_state);
size_t sha512_get_digestsize(void *_state);

#ifdef __cplusplus
}
#endif

#endif /* SHA2_COMMON_H */
