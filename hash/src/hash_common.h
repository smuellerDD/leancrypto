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

#ifndef HASH_COMMON_H
#define HASH_COMMON_H

#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_hash_nocheck(const struct lc_hash *hash, const uint8_t *in, size_t inlen,
		    uint8_t *digest);
int lc_xof_nocheck(const struct lc_hash *xof, const uint8_t *in, size_t inlen,
		   uint8_t *digest, size_t digestlen);
int lc_cshake_init_nocheck(struct lc_hash_ctx *ctx, const uint8_t *n,
			   size_t nlen, const uint8_t *s, size_t slen);

#ifdef __cplusplus
}
#endif

#endif /* HASH_COMMON_H */
