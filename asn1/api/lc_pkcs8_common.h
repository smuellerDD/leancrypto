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

#ifndef LC_PKCS8_COMMON_H
#define LC_PKCS8_COMMON_H

#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT

struct lc_x509_priv_key_data {
	union {
#ifdef LC_DILITHIUM
		struct lc_dilithium_sk dilithium_sk;
#endif
#ifdef LC_DILITHIUM_ED25519
		struct lc_dilithium_ed25519_sk dilithium_ed25519_sk;
#endif
#ifdef LC_DILITHIUM_ED448
		struct lc_dilithium_ed448_sk dilithium_ed448_sk;
#endif
#ifdef LC_SPHINCS
		struct lc_sphincs_sk sphincs_sk;
#endif
	} sk;
};

struct lc_pkcs8_message {
	struct lc_x509_priv_key_data privkey_data;
	struct lc_x509_key_data privkey;
	const struct lc_x509_key_data *privkey_ptr;

	size_t data_len; /* Length of Data */
	const uint8_t *data; /* Content Data (or 0) */
};

#define LC_PKCS8_LINK_PRIVKEY_DATA(key_data, privkkey_data)                    \
	(key_data)->sk.dilithium_sk = &(privkkey_data)->sk.dilithium_sk;       \
	(key_data)->pk.dilithium_pk = NULL

/// \endcond

/**
 * @ingroup PKCS8
 * @brief Allocate memory for struct lc_pkcs8_message holding given number of
 *	  preallocated sinfo members
 *
 * This allocation allows the PKCS8 parsing to avoid allocate memory and keep
 * all operations on stack. In case more signers than \p num_sinfo or more
 * X.509 certificates than \p num_x509 are parsed from the PKCS8 message,
 * then first all pre-allocated structures are used and then new ones are
 * allocated.
 *
 * When not using this macro, which is perfectly legal, an simply allocating
 * \p struct lc_pkcs8_message on stack, then for all parsed signers and
 * X.509 certificates, a new memory entry is allocated.
 *
 * @param [in] name Name of stack variable
 */
#define LC_PKCS8_MSG_ON_STACK(name)                                            \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			LC_ALIGNED_BUFFER(name##_ctx_buf, 8);                  \
	struct lc_pkcs8_message *name =                                        \
		(struct lc_pkcs8_message *)name##_ctx_buf;                     \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS8_COMMON_H */
