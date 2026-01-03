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

#ifndef LC_PEM_H
#define LC_PEM_H

#ifdef __cplusplus
extern "C" {
#endif

enum lc_pem_flags {
	/** Binary data is not treated as PEM data */
	lc_pem_flag_nopem = 0,
	/** Binary data is a X.509 certificate */
	lc_pem_flag_certificate = (1 << 0),
	/** Binary data is a PKCS8 private key */
	lc_pem_flag_priv_key = (1 << 1),
	/** Binary data is a CMS object */
	lc_pem_flag_cms = (1 << 2),
};

/**
 * @ingroup X509
 * @brief Obtain length of PEM string from given binary input string
 *
 * @param [in] ilen Length of the binary data
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_pem_encode_len(size_t ilen, size_t *olen, enum lc_pem_flags flags);

/**
 * @ingroup X509
 * @brief Obtain length of binary string from given PEM input string
 *
 * @param [in] idata Buffer holding the PEM encoded data
 * @param [in] ilen Length of the Base64 data
 * @param [out] olen Length of the output data
 * @param [out] blank_chars number of line feed characters
 * @param [in] flags Flags to shape the operation
 *
 * @return 0 on success, < 0 on error
 */
int lc_pem_decode_len(const char *idata, size_t ilen, size_t *olen,
		      uint8_t *blank_chars, enum lc_pem_flags flags);

/**
 * @ingroup X509
 * @brief PEM encode of arbitrary data
 *
 * The encoding of data into PEM is commonly applied to data types as
 * defined by the \p flags field. However, this PEM encoder is
 * technically unrelated to the actual data to be encoded. Thus, any
 * type of data can be wrapped. The \p flags field only identifies
 * the ASCII string of the PEM data type to be added.
 *
 * @param [in] idata Binary data to encode
 * @param [in] ilen Length of the binary data
 * @param [out] odata Buffer holding the PEM encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_pem_encode_len.
 * @param [out] olen Length of the output data
 * @param [in] flags Flags to define the PEM type
 *
 * @return 0 on success, < 0 on error
 */
int lc_pem_encode(const uint8_t *idata, size_t ilen, char *odata, size_t olen,
		  enum lc_pem_flags flags);

/**
 * @ingroup X509
 * @brief PEM decoding of arbitrary data
 *
 * Just like the encoding, the decoding is unrelated of the actual data.
 * Thus, any PEM data can be decapsulated into binary format.
 *
 * The decoder is very strict and requires to obey the following constraints
 * by the PEM input data:
 *  1. The lines must be 64 Base64 characters in size.
 *  2. Only LF, CR, or CRLF are allowed as line feeds.
 *  3. No intermittent or other blanks are supported.
 *  4. Only the PEM data types referenced by the \p flags field are supported.
 *  5. Currently no data before the actual PEM data is allowed.
 *
 * @param [in] idata Buffer holding the PEM encoded data
 * @param [in] ilen Length of the output data
 * @param [out] odata Buffer holding the PEM encoded data. The caller must
 *		      provide the allocated buffer of sufficient size. The
 *		      size can be obtained via \p lc_pem_decode_len.
 * @param [out] olen Length of the binary data
 * @param [in] flags Flags to define the PEM type
 *
 * @return 0 on success, < 0 on error
 */
int lc_pem_decode(const char *idata, size_t ilen, uint8_t *odata, size_t olen,
		  enum lc_pem_flags flags);

/**
 * @ingroup X509
 * @brief Check if input data is PEM encoded
 *
 * Function checks for the PEM header to be present.
 *
 * @param [in] idata Buffer holding the PEM encoded data
 * @param [in] ilen Length of the output data
 * @param [in] flags Flags to define the PEM type
 *
 * @return 0 when data is PEM encoded, < 0 when data is not PEM encoded
 */
int lc_pem_is_encoded(const char *idata, size_t ilen, enum lc_pem_flags flags);

#ifdef __cplusplus
}
#endif

#endif /* LC_PEM_H */
