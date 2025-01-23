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

#ifndef LC_SYMHMAC_H
#define LC_SYMHMAC_H

#include "lc_aead.h"
#include "lc_sym.h"
#include "lc_hmac.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_sh_cryptor {
	struct lc_sym_ctx sym;
	struct lc_hmac_ctx auth_ctx;
};

#define LC_SH_STATE_SIZE(sym, hash)                                            \
	(LC_SYM_STATE_SIZE(sym) + LC_HMAC_STATE_SIZE(hash))
#define LC_SH_CTX_SIZE(sym, hash)                                              \
	(sizeof(struct lc_aead) + sizeof(struct lc_sh_cryptor) +               \
	 LC_SH_STATE_SIZE(sym, hash))

/* AES-CBC with HMAC based AEAD-algorithm */
extern const struct lc_aead *lc_symhmac_aead;

#define _LC_SH_SET_CTX(name, symalgo, hash)                                    \
	_LC_SYM_SET_CTX((&name->sym), symalgo, name,                           \
			(sizeof(struct lc_sh_cryptor)));                       \
	_LC_HMAC_SET_CTX(                                                      \
		(&name->auth_ctx), hash, name,                                 \
		(sizeof(struct lc_sh_cryptor) + LC_SYM_STATE_SIZE(symalgo)))

#define LC_SH_SET_CTX(name, sym, hash)                                         \
	LC_AEAD_CTX(name, lc_symhmac_aead);                                    \
	_LC_SH_SET_CTX(((struct lc_sh_cryptor *)name->aead_state), sym, hash)
/// \endcond

/**
 * \section SymHMAC_intro Specification of Symmetric / HMAC AEAD Algorithm
 *
 * This specification defines a symmetric stream cipher algorithm using
 * the authenticated encryption with associated data (AEAD) approach. This
 * algorithm can be used to encrypt and decrypt arbitrary user data.
 * The cipher algorithm uses a symmetric algorithm to encrypt/decrypt data
 * along with a HMAC to perform the data authentication. The keys for both
 * the symmetric algorithm as well as the HMAC are derived from the
 * caller-provided key. The result of the HMAC authentication is the
 * message authentication tag which is used during decryption to verify the
 * integrity of the ciphertext.
 *
 * \section SymHMAC_1 Introduction
 *
 * This specification defines a symmetric algorithm using the authenticated
 * encryption with additional data (AEAD) approach. This algorithm can be used
 * to encrypt and decrypt arbitrary user data.
 *
 * The base of the algorithm is the encryption / decryption of the data using
 * the symmetric algorithm and the authentication of the ciphertext with a
 * HMAC.
 *
 * The algorithm applies an Encrypt-Then-MAC by calculating a message
 * authentication tag using HMAC over the ciphertext. During decryption, this
 * calculated message authentication tag is compared with the message
 * authentication tag obtained during the encryption operation. If both values
 * show a mismatch, the authentication fails and the decryption operation is
 * terminated. Only when both message authentication tags are identical
 * the decryption operation completes successfully and returns the decrypted
 * message.
 *
 * The caller-provided key is inserted into a HKDF to derive the key for
 * the symmetric algorithm as well as the HMAC. The caller-provided IV is
 * inserted into the symmetric algorithm.
 *
 * The size of the key is defined to be 256 bits. The size of the IV is
 * defined by the choice symmetric algorithm.
 *
 * As part of the authentication, the algorithm allows the addition of
 * additional authenticated data (AAD) of arbitrary size. This AAD is inserted
 * into the authentication HMAC instance during calculating the message
 * authentication tag.
 *
 * The algorithm matches the specification of [SP800-38F] section 3.1.
 *
 * \section SymHMAC_2 Symmetric/HMAC-based AEAD Cipher Algorithm
 *
 * \subsection SymHMAC_21 Notation
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
 * The "HASH" algorithm denotes an arbitrary hash algorithm such as [FIPS180-4].
 * The "HASH" algorithm is used to instantiate the following algorithms. The
 * following algorithms are required to use the same "HASH" algorithm. The
 * type of the hash algorithm must be selected by the caller.
 *
 * The "HMAC" algorithm denotes an arbitrary HMAC algorithm function, such
 * as HMAC-SHA2-512 [FIPS198]. The "HMAC" algorithm has 3 arguments:
 * the used hash type such as SHA2-512, the main input bit string, and the key.
 * The output size is defined by the used underlying hash digest size.
 *
 * The "HKDF" algorithm denotes the HKDF algorithm specified in [RFC5869]. The
 * "HKDF" algorithm uses 5 input arguments: the used hash type such as SHA2-512,
 * the IKM (input key material), the salt, the label and the size of the
 * output string in bits.
 *
 * \subsection SymHMAC_22 Derivation of Symmetric and HMAC key
 *
 *```
 * KDF(key) -> symmetric key, auth key
 *```
 *```
 * Inputs:
 *   key: The caller-provided key of size 256 bits
 *
 * Outputs:
 *   symmetric key: The key used for the symmetric algorithm
 *
 *   auth key: The key that is used for the HMAC algorithm calculating the
 *             message authentication tag.
 *```
 *
 * The common processing of data is performed as follows:
 *
 *```
 * input length = size of input data in bits
 * KS = HKDF(HASH,
 *           IKM = key,
 *           salt = "",
 *           label = "",
 *           length = 512)
 * symmetric key = 256 left-most bits of KS
 * auth key = 256 right-most bits of KS
 *```
 *
 * \subsection SymHMAC_23 Calculating of Message Authentication Tag
 *
 *```
 * HMAC-Auth(auth key, AAD, ciphertext, taglen) -> tag
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
 *
 * The calculation of the message authentication tag is performed as follows:
 *
 *```
 * temporary tag = HMAC(HASH,
 *                      key = auth key,
 *                      input = AAD || ciphertext)
 *
 * tag = taglen left-most bits of temporary tag
 *```
 *
 * \subsection SymHMAC_24 Encryption Operation
 *
 *```
 * SymHMAC-Encrypt(key, IV, plaintext, AAD, taglen) -> ciphertext, tag
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
 * symmetric key, auth key = KDF(key)
 *
 * ciphertext = Sym(algorithm type,
 *                  input = plaintext,
 *                  key = symmetric key,
 *                  iv = IV)
 * tag = HMAC-Auth(auth key, AAD, ciphertext, taglen)
 *```
 *
 * \subsection SymHMAC_25 Decryption Operation
 *
 *```
 * SymHMAC-Decrypt(key, IV, ciphertext, AAD, tag) -> plaintext, authentication result
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
 * new_tag = HMAC-Auth(auth key, AAD, ciphertext, taglen)
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
 * \section SymHMAC_3 Normative References
 *
 * [FIPS180-4] FIPS PUB 180-4, Secure Hash Standard (SHS), March 2012
 *
 * [FIPS198] FIPS PUB 198-1, The Keyed-Hash Message Authentication Code
 *           (HMAC), July 2008
 *
 * [RFC5869] Request for Comments: 5869, HMAC-based Extract-and-Expand Key
 *           Derivation Function (HKDF), May 2010
 *
 * [SP800-38A] NIST Special Publication 800-38A, Recommendation for Block
 *             Cipher Modes of Operation, 2001 Edition
 *
 * [SP800-38F] NIST Special Publication 800-38F, Recommendation for Block
 *	       Cipher Modes of Operation: Methods for Key Wrapping,
 *	       December 2012
 *
 */

/**
 * @brief Allocate symmetric algorithm with HMAC cryptor context on heap
 *
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash HMAC implementation of type struct lc_hmac used for the HMAC
 *		    authentication
 * @param [out] ctx Allocated symmetric/HMAC cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_sh_alloc(const struct lc_sym *sym, const struct lc_hash *hash,
		struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the symmetric/HMAC cryptor context
 *
 * @param [in] name Name of the stack variable
 * @param [in] sym Symmetric algorithm implementation of type struct lc_sym
 *		   used for the encryption / decryption operation
 * @param [in] hash HMAC implementation of type struct lc_hmac used for the HMAC
 *		    authentication
 */
#define LC_SH_CTX_ON_STACK(name, sym, hash)                                         \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_SH_CTX_SIZE(sym, hash),                \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_SH_SET_CTX(name, sym, hash);                                             \
	lc_aead_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_SYMHMAC_H */
