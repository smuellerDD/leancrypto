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

#ifndef LC_KDF_CTR_H
#define LC_KDF_CTR_H

#include "ext_headers.h"
#include "lc_hash.h"
#include "lc_hmac.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Key-based Key Derivation in Counter Mode - SP800-108 - initialization
 *
 * @param hmac_ctx [in/out] The caller is expected to provide an allocated HMAC
 *			    cipher handle in. Yet, the caller does not need to
 *			    perform any operations on the handle. The extract
 *			    phase adjusts the HMAC cipher handle so that it is
 *			    ready for the expand phase.
 * @param key [in] Input Keying Material (see RFC5869)
 * @param keylen [in] Length of ikm buffer
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr_init(struct lc_hmac_ctx *hmac_ctx,
		    const uint8_t *key, size_t keylen);

/**
 * @brief Key-based Key Derivation in Counter Mode - SP800-108 - data generation
 *
 * @param hmac_ctx [in] Cipher handle for the operation. This call expects
 *			the caller to hand in a HMAC cipher handle that has
 *			been initialized with hkdf_extract.
 * @param label [in] Optional context and application specific information. This
 *		     may be NULL.
 * @param labellen [in] Size of label buffer.
 * @param dst [out] Buffer to store the derived bits in
 * @param dlen [in] Size of the destination buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr_generate(struct lc_hmac_ctx *hmac_ctx,
			const uint8_t *label, size_t labellen,
			uint8_t *dst, size_t dlen);

/**
 * @brief One-shot Key-based Key Derivation in Counter Mode - SP800-108
 *
 * @param hash [in] Hash implementation to use for the KDF operation - this
 *		    hash implementation is used for the HMAC calls.
 * @param key [in] Key from which the new key is to be derived from
 * @param keylen [in] Length of the key buffer.
 * @param label [in] Optional label string that is used to diversify the key
 * @param labellen [in] Length of the label buffer
 * @param dst [out] Buffer that is filled with the derived key. This buffer
 *		    with the size of keylen must be allocated by the caller.
 * @param dlen [in] Length of the key that shall be derived.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr(const struct lc_hash *hash,
	       const uint8_t *key, size_t keylen,
	       const uint8_t *label, size_t labellen,
	       uint8_t *dst, size_t dlen);

#ifdef __cplusplus
}
#endif

#endif /* LC_KDF_CTR_H */
