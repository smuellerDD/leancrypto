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

#ifndef LC_CSHAKE_H
#define LC_CSHAKE_H

#include "lc_hash.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Initialize the hash state following the cSHAKE specification
 *
 * NOTE: Currently only cSHAKE256 is defined and supported.
 *
 * To invoke cSHAKE, perform the following steps:
 *
 * lc_cshake_init
 * lc_hash_set_digestsize
 * lc_hash_update
 * ...
 * lc_hash_update
 * lc_hash_final
 *
 * Or use the helper lc_cshake_final:
 *
 * lc_cshake_init
 * lc_hash_update
 * ...
 * lc_hash_update
 * lc_cshake_final
 *
 * @param [in] ctx Initialized hash context
 * @param [in] n N is a function-name bit string, used by NIST to define
 *		 functions based on cSHAKE. When no function other than cSHAKE
 *		 is desired, N is set to the empty string.
 * @param [in] nlen Length of n
 * @param [in] s S is a customization bit string. The user selects this string
 *		 to define a variant of the function. When no customization is
 *		 desired, S is set to the empty string.
 * @param [in] slen Length of s
 */
void lc_cshake_init(struct lc_hash_ctx *ctx,
		    const uint8_t *n, size_t nlen,
		    const uint8_t *s, size_t slen);

/**
 * @brief Generate a cSHAKE message digest from a given state.
 *
 * The function can be invoked repeatedly to squeeze more data from the
 * cSHAKE state.
 *
 * @param [in] ctx Initialized hash context
 * @param [out] out Buffer allocated by caller that is filled with the message
 *		    digest data.
 * @param [in] outlen Size of the output buffer to be filled.
 */
static inline void
lc_cshake_final(struct lc_hash_ctx *ctx, uint8_t *out, size_t outlen)
{
	lc_hash_set_digestsize(ctx, outlen);
	lc_hash_final(ctx, out);
}


#ifdef __cplusplus
}
#endif

#endif /* LC_CSHAKE_H */
