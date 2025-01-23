/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_PBKDF2_H
#define LC_PBKDF2_H

#include "ext_headers.h"
#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup KDF
 * @brief Password-based Key Derivation Function - SP800-132
 *
 * @param [in] hash Hash implementation to use for the PBKDF2 operation - this
 *		    hash implementation is used for the HMAC calls.
 * @param [in] pw Password from which to derive the key
 * @param [in] pwlen Length of the password buffer
 * @param [in] salt Optional salt value, may be NULL
 * @param [in] saltlen Length of the salt value
 * @param [in] count Number of iterations that shall be performed to derive the
 *		     key.
 * @param [out] key Buffer that is filled with the derived key. This buffer
 *		    with the size of keylen must be allocated by the caller.
 * @param [in] keylen Length of the key that shall be derived.
 *
 * @return 0 on success, < 0 on error
 */
int lc_pbkdf2(const struct lc_hash *hash, const uint8_t *pw, size_t pwlen,
	      const uint8_t *salt, size_t saltlen, const uint32_t count,
	      uint8_t *key, size_t keylen);

#ifdef __cplusplus
}
#endif

#endif /* LC_PBKDF2_H */
