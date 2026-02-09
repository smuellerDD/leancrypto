/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _CRYPTO_PKCS8_GENERATOR_H
#define _CRYPTO_PKCS8_GENERATOR_H

#include "ext_headers.h"
#include "lc_pkcs8_common.h"
#include "lc_x509_common.h"

/** @defgroup PKCS8Gen PKCS#8 Message Generate Handling
 *
 * Concept of PKCS#8 message generation handling in leancrypto
 *
 * The leancrypto library provides an PKCS#8 generator which can create
 * PKCS#8 messages. The generator does not enforce any PKCS#8 limitations and
 * thus allows the caller to generate any combination of field offered by the
 * PKCS#8 specification. To appropriately use the PKCS#8 parser, please consider
 * the following rules:
 *
 * 1. The generated PKCS#8 data blob is independent of the original PKCS#8
 *    certificate data structure.
 *
 * 2. The generator does not allocate any memory. All memory MUST be provided
 *    by the caller. Thus, if the caller provides insufficient memory, the
 *    generator will return -EOVERFLOW.
 *
 * 3. Before invoking the PKCS#8 generator, the caller must allocate an
 *    \p lc_pkcs8_message data structure (e.g. on stack) and fill it with the
 *    numerous setter functions to add data.
 *
 * 4. The \p pkcs8_message data structure should be released at the end of the
 *    operation with \p lc_pkcs8_message_clear.
 */

/**
 * @ingroup PKCS8Gen
 * @brief Encode a PKCS#8 message
 *
 * The function generates a PKCS#8 data blob from the filled PKCS#8 data
 * structure.
 *
 * The signature of the data using the signer is created within this call.
 *
 * This API offers generation of PKCS#8 messages with:
 * * ML-DSA expanded key (i.e. full ML-DSA key) following RFC 9881 chapter 6.
 *   This is enabled by generating a new key pair as seed with
 *   lc_x509_keypair_gen.
 * * ML-DSA seed which is expanded into the full ML-DSA key during parsing
 *   following RFC 9881 chapter 6. This is enabled by generating a new key pair
 *   without defining it as seed using lc_x509_keypair_gen.
 * * For all other algorithms, the common key type
 *
 * @param [in] pkcs8 The data structure that is filled by the caller before this
 *		     invocation using the various setter functions.
 * @param [in,out] data Raw PKCS#8 data blob in DER / BER format - the caller
 *			must provide the memory
 * @param [in,out] avail_datalen Length of the raw PKCS#8 certificate buffer that
 *				 is free (the input value must be equal to the
 * 				 \p data buffer size, the output refers to how
 *				 many bytes are unused)
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs8_encode(const struct lc_pkcs8_message *pkcs8, uint8_t *data,
		    size_t *avail_datalen);

#endif /* _CRYPTO_PKCS8_GENERATOR_H */
