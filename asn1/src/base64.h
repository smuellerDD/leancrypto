/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef BASE64_H
#define BASE64_H

#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#undef LC_BASE64_URLSAFE

enum lc_base64_flags {
	lc_base64_flag_unknown = 0,
	/** Process the base64 as PEM format (line feed after 64 Base64 chars) */
	lc_base64_flag_pem = (1 << 0),
};

/**
 * @brief Obtain length of Base64 string from given binary input string
 *
 * @param [in] ilen Length of the binary data
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_encode_len(size_t ilen, size_t *olen, enum lc_base64_flags flags);

/**
 * @brief Obtain length of binary string from given Base64 input string
 *
 * @param [in] idata Buffer holding the base64 encoded data
 * @param [in] ilen Length of the Base64 data
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_decode_len(const char *idata, size_t ilen, size_t *olen,
			 uint8_t *blank_chars, enum lc_base64_flags flags);

/**
 * @brief base64 encode of arbitrary data
 *
 * @param [in] idata Binary data to encode
 * @param [in] ilen Length of the binary data
 * @param [out] odata Buffer holding the base64 encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_base64_encode_len.
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_encode(const uint8_t *idata, size_t ilen, char *odata,
		     size_t olen, enum lc_base64_flags flags);

/**
 * @brief base64 decoding of arbitrary data
 *
 * @param [in] idata Buffer holding the base64 encoded data
 * @param [in] ilen Length of the output data
 * @param [out] odata Buffer holding the base64 encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_base64_decode_len.
 * @param [out] olen Length of the binary data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_decode(const char *idata, size_t ilen, uint8_t *odata,
		     size_t olen, enum lc_base64_flags flags);

#ifdef LC_BASE64_URLSAFE
/**
 * @brief base64 decoding of arbitrary data with a URL/filename-safe input
 *	  alphabet
 *
 * @param [in] idata Binary data to encode
 * @param [in] ilen Length of the binary data
 * @param [out] odata Buffer holding the base64 encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_base64_encode_len.
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_decode_safe(const char *idata, size_t ilen, uint8_t **odata,
			  size_t *olen, enum lc_base64_flags flags);

/**
 * @brief base64 encode of arbitrary data with a URL/filename-safe output
 *	  alphabet
 *
 * @param [in] idata Buffer holding the base64 encoded data
 * @param [in] ilen Length of the output data
 * @param [out] odata Buffer holding the base64 encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_base64_decode_len.
 * @param [out] olen Length of the binary data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_base64_encode_safe(const uint8_t *idata, size_t ilen, char **odata,
			  size_t *olen, enum lc_base64_flags flags);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BASE64_H */
