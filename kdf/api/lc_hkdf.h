/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_HKDF_H
#define LC_HKDF_H

#include <stdint.h>
#include <sys/types.h>

#include "lc_hmac.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) - RFC5869
 *	  Extract phase
 *
 * @param hmac_ctx [in/out] The caller is expected to provide an allocated HMAC
 *			    cipher handle in. Yet, the caller does not need to
 *			    perform any operations on the handle. The extract
 *			    phase adjusts the HMAC cipher handle so that it is
 *			    ready for the expand phase.
 * @param ikm [in] Input Keying Material (see RFC5869)
 * @param ikmlen [in] Length of ikm buffer
 * @param salt [in] Optional salt value - if caller does not want to use a salt
 *		    set NULL here.
 * @param saltlen [in] Length of salt value buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf_extract(struct lc_hmac_ctx *hmac_ctx,
		    const uint8_t *ikm, size_t ikmlen,
		    const uint8_t *salt, size_t saltlen);

/**
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) - RFC5869
 *	  Expand phase
 *
 * @param hmac_ctx [in] Cipher handle for the operation. This call expects
 *			the caller to hand in a HMAC cipher handle that has
 *			been initialized with hkdf_extract.
 * @param info [in] Optional context and application specific information. This
 *		    may be NULL.
 * @param infolen [in] Size of info buffer.
 * @param dst [out] Buffer to store the derived bits in
 * @param dlen [in] Size of the destination buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf_expand(struct lc_hmac_ctx *hmac_ctx,
		   const uint8_t *info, size_t infolen,
		   uint8_t *dst, size_t dlen);

#ifdef __cplusplus
}
#endif

#endif /* LC_HKDF_H */
