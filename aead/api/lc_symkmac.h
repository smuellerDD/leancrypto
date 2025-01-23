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

#ifndef LC_SYMKMAC_H
#define LC_SYMKMAC_H

#include "lc_aead.h"
#include "lc_sym.h"
#include "lc_kmac.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_kh_cryptor {
	struct lc_sym_ctx sym;
	struct lc_kmac_ctx auth_ctx;
};

#define LC_KH_STATE_SIZE(sym, hash)                                            \
	(LC_SYM_STATE_SIZE(sym) + LC_KMAC_STATE_SIZE(hash))
#define LC_KH_CTX_SIZE(sym, hash)                                              \
	(sizeof(struct lc_aead) + sizeof(struct lc_kh_cryptor) +               \
	 LC_KH_STATE_SIZE(sym, hash))

/* AES-CBC with KMAC based AEAD-algorithm */
extern const struct lc_aead *lc_symkmac_aead;

#define _LC_KH_SET_CTX(name, symalgo, hash)                                    \
	_LC_SYM_SET_CTX((&name->sym), symalgo, name,                           \
			(sizeof(struct lc_kh_cryptor)));                       \
	_LC_KMAC_SET_CTX(                                                      \
		(&name->auth_ctx), hash, name,                                 \
		(sizeof(struct lc_kh_cryptor) + LC_SYM_STATE_SIZE(symalgo)))

#define LC_KH_SET_CTX(name, sym, hash)                                         \
	LC_AEAD_CTX(name, lc_symkmac_aead);                                    \
	_LC_KH_SET_CTX(((struct lc_kh_cryptor *)name->aead_state), sym, hash)
/// \endcond

/**
 * \section SymKMAC_intro Specification of Symmetric / KMAC AEAD Algorithm
 *
 * This specification defines a symmetric stream cipher algorithm using
 * the authenticated encryption with associated data (AEAD) approach. This
 * algorithm can be used to encrypt and decrypt arbitrary user data.
 * The cipher algorithm uses a symmetric algorithm to encrypt/decrypt data
 * along with a KMAC to perform the data authentication. The keys for both
 * the symmetric algorithm as well as the KMAC are derived from the
 * caller-provided key. The result of the KMAC authentication is the
 * message authentication tag which is used during decryption to verify the
 * integrity of the ciphertext.
 *
 * \section SymKMAC_1 Introduction
 *
 * This specification defines a symmetric algorithm using the authenticated
 * encryption with additional data (AEAD) approach. This algorithm can be used
 * to encrypt and decrypt arbitrary user data.
 *
 * The base of the algorithm is the encryption / decryption of the data using
 * the symmetric algorithm and the authentication of the ciphertext with a
 * KMAC.
 *
 * The algorithm applies an Encrypt-Then-MAC by calculating a message
 * authentication tag using KMAC over the ciphertext. During decryption, this
 * calculated message authentication tag is compared with the message
 * authentication tag obtained during the encryption operation. If both values
 * show a mismatch, the authentication fails and the decryption operation is
 * terminated. Only when both message authentication tags are identical
 * the decryption operation completes successfully and returns the decrypted
 * message.
 *
 * The caller-provided key is inserted into the KMAC-hash to derive the key for
 * the symmetric algorithm as well as the KMAC. The caller-provided IV is
 * inserted into the symmetric algorithm.
 *
 * The size of the key is defined to be 256 bits. The size of the IV is
 * defined by the choice symmetric algorithm.
 *
 * As part of the authentication, the algorithm allows the addition of
 * additional authenticated data (AAD) of arbitrary size. This AAD is inserted
 * into the authentication KMAC instance during calculating the message
 * authentication tag.
 *
 * The algorithm matches the specification of [SP800-38F] section 3.1.
 *
 * \section SymKMAC_2 Symmetric/KMAC-based AEAD Cipher Algorithm
 *
 * \subsection SymKMAC_21 Notation
 *
 * The "Sym" algorithm denotes an arbitrary symmetric algorithm function,
 * such as AES-CBC, AES-CTR or similar [SP800-38A]. The "Sym" algorithm
 * has 4 arguments: the symmetric algorithm type such as AES-CBC, the main
 * input bit string, the key and the IV. It produces an output string of equal
 * size of the input. It may be possible that the algorithm operates on a fixed
 * block size where the input bit string must be a multiple of the block size.
 * The caller must ensure that the input bit string is a multiple of the block
 * size.
 *
 * The KMAC-hash denotes the KMACXOF256 function [SP800-185]
 * instantiated with either cSHAKE 256 or cSHAKE 128 [FIPS202] depending on the
 * use case. The KMAC-hash has 4 arguments: the key K, the main input bit string
 * X, the requested output length L in bits, and an optional customization bit
 * string S.
 *
 * The inputs to the KMAC-hash function are specified with references to these
 * parameters.
 *
 * \subsection SymKMAC_22 Derivation of Symmetric and KMAC key
 *
 *```
 * KMAC-KDF(key) -> symmetric key, auth key
 *```
 *```
 * Inputs:
 *   key: The caller-provided key of size 256 bits
 *
 * Outputs:
 *   symmetric key: The key used for the symmetric algorithm
 *
 *   auth key: The key that is used for the KMAC algorithm calculating the
 *             message authentication tag.
 *```
 *
 * The common processing of data is performed as follows:
 *
 *```
 * KS = KMAC(K = key,
 *           X = "",
 *           L = 512 bits,
 *           S = "")
 *
 * symmetric key = 256 left-most bits of KS
 * auth key = 256 right-most bits of KS
 *```
 *
 * \subsection SymKMAC_23 Calculating of Message Authentication Tag
 *
 *```
 * KMAC-Auth(auth key, AAD, ciphertext, taglen) -> tag
 *```
 *```
 * Inputs:
 *   auth key: The key that is used for the cSHAKE operation calculating the
 *             message authentication tag.
 *
 *   AAD: The caller-provided additional authenticated data. The AAD can have
 *	  any size including an empty bit-string.
 *
 *   ciphertext: The ciphertext obtained from the encryption operation or
 *               provided to the decryption operation.
 *
 *   taglen: The length of the message authentication tag to be generated.
 *```
 * The calculation of the message authentication tag is performed as follows:
 *
 *```
 * tag = KMAC(K = auth key,
 *            X = AAD || ciphertext,
 *            L = taglen,
 *            S = "")
 *```
 *
 * \subsection SymKMAC_24 Encryption Operation
 *
 *```
 * SymKMAC-Encrypt(key, IV, plaintext, AAD, taglen) -> ciphertext, tag
 *```
 *```
 * Input:
 *   key: The caller-provided key of size 256 bits
 *
 *   IV: The caller-provided initialization vector. The IV can have any size
 *	 including an empty bit-string.
 *
 *   plaintext: The caller-provided plaintext data.
 *
 *   AAD: The caller-provided additional authenticated data.
 *
 *   taglen: The length of the message authentication tag to be generated.
 *
 * Output
 *   ciphertext: The ciphertext that can exchanged with the recipient over
 *               insecure channels.
 *
 *   tag: The message authentication tag that can be exchanged with the
 *        recipient over insecure channels.
 *```
 *
 * The encryption operation is performed as follows:
 *
 *```
 * symmetric key, auth key = KMAC-KDF(key)
 *
 * ciphertext = Sym(algorithm type,
 *                  input = plaintext,
 *                  key = symmetric key,
 *                  iv = IV)
 * tag = KMAC-Auth(auth key, AAD, ciphertext, taglen)
 *```
 *
 * \subsection SymKMAC_25 Decryption Operation
 *
 *```
 * SymKMAC-Decrypt(key, IV, ciphertext, AAD, tag) ->
 *						plaintext, authentication result
 *```
 *```
 * Input:
 *   key: The caller-provided key of size 256 bits
 *
 *   IV: The caller-provided initialization vector. The IV can have any size
 *	 including an empty bit-string.
 *
 *   ciphertext: The ciphertext that was received from the send over
 *               insecure channels.
 *
 *   AAD: The caller-provided additional authenticated data.
 *
 *   tag: The message authentication tag that was received from the send over
 *        insecure channels.
 *
 * Output
 *   plaintext: The plaintext of the data.
 *
 *   authentication result: A boolean indicator specifying whether the
 *			    authentication was successful. If it was
 *			    unsuccessful the caller shall reject the ciphertext.
 *```
 *
 * The decryption operation is performed as follows:
 *
 *```
 * symmetric key, auth key = KDF(key)
 *
 * plaintext = Sym(algorithm type,
 *                 input = ciphertext,
 *                 key = symmetric key,
 *                 iv = IV)
 *
 * taglen = size of tag
 *
 * new_tag = KMAC-Auth(auth key, AAD, ciphertext, taglen)
 *
 * if (new_tag == tag)
 *   authentication result = success
 * else
 *   authentication result = failure
 *```
 *
 * If the authentication result indicates a failure, the result of the
 * decryption operation SHALL be discarded.
 *
 * \section SymKMAC_3 Normative References
 *
 * [SP800-38A] NIST Special Publication 800-38A, Recommendation for Block
 *             Cipher Modes of Operation, 2001 Edition
 *
 * [SP800-38F] NIST Special Publication 800-38F, Recommendation for Block
 *	       Cipher Modes of Operation: Methods for Key Wrapping,
 *	       December 2012
 *
 * [SP800-185] John Kelsey, Shu-jen Chang, Ray Perlne, NIST Special Publication
 *             800-185 SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and
 *             ParallelHash, December 2016
 */

/**
 * @brief Allocate symmetric algorithm with KMAC cryptor context on heap
 *
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash KMAC implementation KMAC authentication - use lc_cshake256
 *		    for now
 * @param [out] ctx Allocated symmetric/KMAC cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_kh_alloc(const struct lc_sym *sym, const struct lc_hash *hash,
		struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the symmetric/KMAC cryptor context
 *
 * @param [in] name Name of the stack variable
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash KMAC implementation KMAC authentication - use lc_cshake256
 *		    or lc_cshake128 (though, note: the lc_cshake256 has a lower
 *		    memory footprint, and has a higher security strength, yet
 *		    cSHAKE128 may be a bit faster)
 */
#define LC_KH_CTX_ON_STACK(name, sym, hash)                                         \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_KH_CTX_SIZE(sym, hash),                \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_KH_SET_CTX(name, sym, hash);                                             \
	lc_aead_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_SYMKMAC_H */
