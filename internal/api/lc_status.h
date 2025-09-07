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

#ifndef LC_STATUS_H
#define LC_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief (Re-)run the self tests
 *
 * If the self tests were already executed for a given algorithm, they are
 * triggered again.
 */
void lc_rerun_selftests(void);

/**
 * @brief Re-run the FIPS 140 integrity test
 *
 * \note This API is only present in the FIPS module instance of leancrypto.
 */
void lc_fips_integrity_checker(void);

/**
 * @brief Status information about leancrypto
 *
 * @param [in] outbuf Buffer to be filled with status information, allocated by
 *		      caller
 * @param [in] outlen Size of the output buffer
 */
void lc_status(char *outbuf, size_t outlen);

/// \cond DO_NOT_DOCUMENT
/*
 * The following concept applies to the defines:
 *
 * 1. LC_ALG_STATUS_TYPE_* select the status integer to be used. The types are
 *    larger than 32 bit as they then cannot interfere with the status.
 * 2. The LC_ALG_STATUS_FLAG_* specify a specific algorithm
 * 3. The general status of LC_ALG_STATUS_<ALG> is the external usable flags
 */

/*
 * Internal flags which cannot be used in the API
 */
#define LC_ALG_STATUS_TYPE_MASK_SHIFT (16)
#define LC_ALG_STATUS_FLAG_MASK ((1 << LC_ALG_STATUS_TYPE_MASK_SHIFT) - 1)
#define LC_ALG_STATUS_TYPE_MASK                                                \
	(((uint32_t)-1) << LC_ALG_STATUS_TYPE_MASK_SHIFT)

#define LC_ALG_STATUS_TYPE_AEAD (1UL << LC_ALG_STATUS_TYPE_MASK_SHIFT)
#define LC_ALG_STATUS_FLAG_AES_GCM (1 << 0)
#define LC_ALG_STATUS_FLAG_ASCON_AEAD_128 (1 << 1)
#define LC_ALG_STATUS_FLAG_ASCON_KECCAK (1 << 2)
#define LC_ALG_STATUS_FLAG_CHACHA20_POLY1305 (1 << 3)
#define LC_ALG_STATUS_FLAG_CSHAKE_CRYPT (1 << 4)
#define LC_ALG_STATUS_FLAG_HASH_CRYPT (1 << 5)
#define LC_ALG_STATUS_FLAG_KMAC_CRYPT (1 << 6)
#define LC_ALG_STATUS_FLAG_SYM_HMAC (1 << 7)
#define LC_ALG_STATUS_FLAG_SYM_KMAC (1 << 8)

#define LC_ALG_STATUS_TYPE_KEM (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 1))
#define LC_ALG_STATUS_FLAG_HQC_KEYGEN (1 << 0)
#define LC_ALG_STATUS_FLAG_HQC_ENC (1 << 1)
#define LC_ALG_STATUS_FLAG_HQC_DEC (1 << 2)
#define LC_ALG_STATUS_FLAG_MLKEM_KEYGEN (1 << 3)
#define LC_ALG_STATUS_FLAG_MLKEM_ENC (1 << 4)
#define LC_ALG_STATUS_FLAG_MLKEM_DEC (1 << 5)
#define LC_ALG_STATUS_FLAG_MLKEM_ENC_KDF (1 << 6)
#define LC_ALG_STATUS_FLAG_MLKEM_DEC_KDF (1 << 7)
#define LC_ALG_STATUS_FLAG_X25519_KEYKEN (1 << 8)
#define LC_ALG_STATUS_FLAG_X25519_SS (1 << 9)
#define LC_ALG_STATUS_FLAG_X448_KEYKEN (1 << 10)
#define LC_ALG_STATUS_FLAG_X448_SS (1 << 11)

#define LC_ALG_STATUS_TYPE_SIG (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 2))
#define LC_ALG_STATUS_FLAG_MLDSA_KEYGEN (1 << 0)
#define LC_ALG_STATUS_FLAG_MLDSA_SIGGEN (1 << 1)
#define LC_ALG_STATUS_FLAG_MLDSA_SIGVER (1 << 2)
#define LC_ALG_STATUS_FLAG_SLHDSA_KEYGEN (1 << 3)
#define LC_ALG_STATUS_FLAG_SLHDSA_SIGGEN (1 << 4)
#define LC_ALG_STATUS_FLAG_SLHDSA_SIGVER (1 << 5)
#define LC_ALG_STATUS_FLAG_ED25519_KEYGEN (1 << 6)
#define LC_ALG_STATUS_FLAG_ED25519_SIGGEN (1 << 7)
#define LC_ALG_STATUS_FLAG_ED25519_SIGVER (1 << 8)
#define LC_ALG_STATUS_FLAG_ED448_KEYGEN (1 << 9)
#define LC_ALG_STATUS_FLAG_ED448_SIGGEN (1 << 10)
#define LC_ALG_STATUS_FLAG_ED448_SIGVER (1 << 11)

#define LC_ALG_STATUS_TYPE_RNG (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 3))
#define LC_ALG_STATUS_FLAG_CHACHA20_DRNG (1 << 0)
#define LC_ALG_STATUS_FLAG_CSHAKE_DRBG (1 << 1)
#define LC_ALG_STATUS_FLAG_HASH_DRBG (1 << 2)
#define LC_ALG_STATUS_FLAG_HMAC_DRBG (1 << 3)
#define LC_ALG_STATUS_FLAG_KMAC_DRBG (1 << 4)
#define LC_ALG_STATUS_FLAG_XDRBG128 (1 << 5)
#define LC_ALG_STATUS_FLAG_XDRBG256 (1 << 6)

#define LC_ALG_STATUS_TYPE_DIGEST (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 4))
#define LC_ALG_STATUS_FLAG_ASCON256 (1 << 0)
#define LC_ALG_STATUS_FLAG_ASCONXOF (1 << 1)
#define LC_ALG_STATUS_FLAG_ASCONCXOF (1 << 2)
#define LC_ALG_STATUS_FLAG_SHA256 (1 << 3)
#define LC_ALG_STATUS_FLAG_SHA512 (1 << 4)
#define LC_ALG_STATUS_FLAG_SHA3 (1 << 5)
#define LC_ALG_STATUS_FLAG_SHAKE (1 << 6)
#define LC_ALG_STATUS_FLAG_CSHAKE (1 << 7)
#define LC_ALG_STATUS_FLAG_KMAC (1 << 8)
#define LC_ALG_STATUS_FLAG_HMAC (1 << 9)

#define LC_ALG_STATUS_TYPE_SYM (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 5))
#define LC_ALG_STATUS_FLAG_AES_CBC (1 << 0)
#define LC_ALG_STATUS_FLAG_AES_CTR (1 << 1)
#define LC_ALG_STATUS_FLAG_AES_KW (1 << 2)
#define LC_ALG_STATUS_FLAG_AES_XTS (1 << 3)
#define LC_ALG_STATUS_FLAG_CHACHA20 (1 << 4)

#define LC_ALG_STATUS_TYPE_AUX (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 6))
#define LC_ALG_STATUS_FLAG_HKDF (1 << 0)
#define LC_ALG_STATUS_FLAG_CTR_KDF (1 << 1)
#define LC_ALG_STATUS_FLAG_DPI_KDF (1 << 2)
#define LC_ALG_STATUS_FLAG_FB_KDF (1 << 3)
#define LC_ALG_STATUS_FLAG_PBKDF2 (1 << 4)
#define LC_ALG_STATUS_FLAG_LIB (1UL << 15)
/// \endcond

/*
 * Test status flag
 */
enum lc_alg_status_result {
	/** Testing is pending for given algorithm */
	lc_alg_status_result_pending,
	/** Testing failed for given algorithm */
	lc_alg_status_result_failed,
	/** Testing ongoing for given algorithm */
	lc_alg_status_result_ongoing,
	/** Testing passed for given algorithm */
	lc_alg_status_result_passed,
};

/** AEAD Algorithm reference: AES-GCM */
#define LC_ALG_STATUS_AES_GCM                                                  \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_AES_GCM)
/** AEAD Algorithm reference: ASCON-AEAD128 */
#define LC_ALG_STATUS_ASCON_AEAD_128                                           \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_ASCON_AEAD_128)
/** AEAD Algorithm reference: ASCON-KECCAK */
#define LC_ALG_STATUS_ASCON_KECCAK                                             \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_ASCON_KECCAK)
/** AEAD Algorithm reference: ChaCha20-Poly1305 */
#define LC_ALG_STATUS_CHACHA20_POLY1305                                        \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_CHACHA20_POLY1305)
/** AEAD Algorithm reference: cSHAKE AEAD */
#define LC_ALG_STATUS_CSHAKE_CRYPT                                             \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_CSHAKE_CRYPT)
/** AEAD Algorithm reference: Hash AEAD */
#define LC_ALG_STATUS_HASH_CRYPT                                               \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_HASH_CRYPT)
/** AEAD Algorithm reference: KMAC AEAD */
#define LC_ALG_STATUS_KMAC_CRYPT                                               \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_KMAC_CRYPT)
/** AEAD Algorithm reference: symmetric algorithm + HMAC */
#define LC_ALG_STATUS_SYM_HMAC                                                 \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_SYM_HMAC)
/** AEAD Algorithm reference: symmetric algorithm + KMAC */
#define LC_ALG_STATUS_SYM_KMAC                                                 \
	(LC_ALG_STATUS_TYPE_AEAD | LC_ALG_STATUS_FLAG_SYM_KMAC)

/** KEM Algorithm reference: HQC Key Generation */
#define LC_ALG_STATUS_HQC_KEYGEN                                               \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_HQC_KEYGEN)
/** KEM Algorithm reference: HQC Encapsulation */
#define LC_ALG_STATUS_HQC_ENC                                                  \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_HQC_ENC)
/** KEM Algorithm reference: HQC Decapsulation */
#define LC_ALG_STATUS_HQC_DEC                                                  \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_HQC_DEC)
/** KEM Algorithm reference: ML-KEM Key Generation */
#define LC_ALG_STATUS_MLKEM_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_MLKEM_KEYGEN)
/** KEM Algorithm reference: ML-KEM Encapsulation */
#define LC_ALG_STATUS_MLKEM_ENC                                                \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_MLKEM_ENC)
/** KEM Algorithm reference: ML-KEM Decapsulation */
#define LC_ALG_STATUS_MLKEM_DEC                                                \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_MLKEM_DEC)
/** KEM Algorithm reference: ML-KEM Encapsulation with KDF */
#define LC_ALG_STATUS_MLKEM_ENC_KDF                                            \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_MLKEM_ENC_KDF)
/** KEM Algorithm reference: ML-KEM Decapsulation with KDF */
#define LC_ALG_STATUS_MLKEM_DEC_KDF                                            \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_MLKEM_DEC_KDF)
/** KEM Algorithm reference: X25515 Key Generation */
#define LC_ALG_STATUS_X25519_KEYKEN                                            \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_X25519_KEYKEN)
/** KEM Algorithm reference: X25515 Shared Secret */
#define LC_ALG_STATUS_X25519_SS                                                \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_X25519_SS)
/** KEM Algorithm reference: X25515 Key Generation */
#define LC_ALG_STATUS_X448_KEYKEN                                              \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_X448_KEYKEN)
/** KEM Algorithm reference: X25515 Shared Secret */
#define LC_ALG_STATUS_X448_SS                                                  \
	(LC_ALG_STATUS_TYPE_KEM | LC_ALG_STATUS_FLAG_X448_SS)

/** Signature Algorithm reference: ML-DSA Key Generation */
#define LC_ALG_STATUS_MLDSA_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_MLDSA_KEYGEN)
/** Signature Algorithm reference: ML-DSA Key Signature Generation */
#define LC_ALG_STATUS_MLDSA_SIGGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_MLDSA_SIGGEN)
/** Signature Algorithm reference: ML-DSA Key Signature Verification */
#define LC_ALG_STATUS_MLDSA_SIGVER                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_MLDSA_SIGVER)
/** Signature Algorithm reference: SLH-DSA Key Generation */
#define LC_ALG_STATUS_SLHDSA_KEYGEN                                            \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_SLHDSA_KEYGEN)
/** Signature Algorithm reference: SLH-DSA Key Signature Generation */
#define LC_ALG_STATUS_SLHDSA_SIGGEN                                            \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_SLHDSA_SIGGEN)
/** Signature Algorithm reference: SLH-DSA Key Signature Verification */
#define LC_ALG_STATUS_SLHDSA_SIGVER                                            \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_SLHDSA_SIGVER)
/** Signature Algorithm reference: ED-25519 Key Generation */
#define LC_ALG_STATUS_ED25519_KEYGEN                                           \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED25519_KEYGEN)
/** Signature Algorithm reference: ED-25519 Key Signature Generation */
#define LC_ALG_STATUS_ED25519_SIGGEN                                           \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED25519_SIGGEN)
/** Signature Algorithm reference: ED-25519 Key Signature Verification */
#define LC_ALG_STATUS_ED25519_SIGVER                                           \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED25519_SIGVER)
/** Signature Algorithm reference: ED-448 Key Generation */
#define LC_ALG_STATUS_ED448_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED448_KEYGEN)
/** Signature Algorithm reference: ED-448 Key Signature Generation */
#define LC_ALG_STATUS_ED448_SIGGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED448_SIGGEN)
/** Signature Algorithm reference: ED-448 Key Signature Verification */
#define LC_ALG_STATUS_ED448_SIGVER                                             \
	(LC_ALG_STATUS_TYPE_SIG | LC_ALG_STATUS_FLAG_ED448_SIGVER)

/** Random Number Generator reference: ChaCha20 DRNG */
#define LC_ALG_STATUS_CHACHA20_DRNG                                            \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_CHACHA20_DRNG)
/** Random Number Generator reference: cSHAKE DRBG */
#define LC_ALG_STATUS_CSHAKE_DRBG                                              \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_CSHAKE_DRBG)
/** Random Number Generator reference: SP800-90A Hash DRBG */
#define LC_ALG_STATUS_HASH_DRBG                                                \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_HASH_DRBG)
/** Random Number Generator reference: SP800-90A HMAC DRBG */
#define LC_ALG_STATUS_HMAC_DRBG                                                \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_HMAC_DRBG)
/** Random Number Generator reference: KMAC DRBG */
#define LC_ALG_STATUS_KMAC_DRBG                                                \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_KMAC_DRBG)
/** Random Number Generator reference: Ascon XOF XDRBG128 */
#define LC_ALG_STATUS_XDRBG128                                                 \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_XDRBG128)
/** Random Number Generator reference: SHAKE XDRBG128 */
#define LC_ALG_STATUS_XDRBG256                                                 \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_XDRBG256)

/** Digest reference: Ascon 256 */
#define LC_ALG_STATUS_ASCON256                                                 \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_ASCON256)
/** Digest reference: Ascon XOF */
#define LC_ALG_STATUS_ASCONXOF                                                 \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_ASCONXOF)
/** Digest reference: Ascon CXOF */
#define LC_ALG_STATUS_ASCONCXOF                                                \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_ASCONCXOF)
/** Digest reference: SHA-256 */
#define LC_ALG_STATUS_SHA256                                                   \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_SHA256)
/** Digest reference: SHA-512 */
#define LC_ALG_STATUS_SHA512                                                   \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_SHA512)
/** Digest reference: SHA-3 */
#define LC_ALG_STATUS_SHA3 (LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_SHA3)
/** Digest reference: SHAKE */
#define LC_ALG_STATUS_SHAKE                                                    \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_SHAKE)
/** Digest reference: cSHAKE */
#define LC_ALG_STATUS_CSHAKE                                                   \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_CSHAKE)
/** Digest reference: KMAC */
#define LC_ALG_STATUS_KMAC (LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_KMAC)
/** Digest reference: HMAC */
#define LC_ALG_STATUS_HMAC (LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_HMAC)

/** Symmetric Algorithm reference: AES-CBC */
#define LC_ALG_STATUS_AES_CBC                                                  \
	(LC_ALG_STATUS_TYPE_SYM | LC_ALG_STATUS_FLAG_AES_CBC)
/** Symmetric Algorithm reference: AES-CTR */
#define LC_ALG_STATUS_AES_CTR                                                  \
	(LC_ALG_STATUS_TYPE_SYM | LC_ALG_STATUS_FLAG_AES_CTR)
/** Symmetric Algorithm reference: AES-KW */
#define LC_ALG_STATUS_AES_KW                                                   \
	(LC_ALG_STATUS_TYPE_SYM | LC_ALG_STATUS_FLAG_AES_KW)
/** Symmetric Algorithm reference: AES-CBC */
#define LC_ALG_STATUS_AES_XTS                                                  \
	(LC_ALG_STATUS_TYPE_SYM | LC_ALG_STATUS_FLAG_AES_XTS)
/** Symmetric Algorithm reference: AES-CBC */
#define LC_ALG_STATUS_CHACHA20                                                 \
	(LC_ALG_STATUS_TYPE_SYM | LC_ALG_STATUS_FLAG_CHACHA20)

/** Auxiliary information: HKDF */
#define LC_ALG_STATUS_HKDF (LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_HKDF)
/** Auxiliary information: SP800-108 Counter KDF */
#define LC_ALG_STATUS_CTR_KDF                                                  \
	(LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_CTR_KDF)
/** Auxiliary information: SP800-108 Double-Pipeline KDF */
#define LC_ALG_STATUS_DPI_KDF                                                  \
	(LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_DPI_KDF)
/** Auxiliary information: SP800-108 Feedback KDF */
#define LC_ALG_STATUS_FB_KDF                                                   \
	(LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_FB_KDF)
/** Auxiliary information: SP800-132 PBKDF2 */
#define LC_ALG_STATUS_PBKDF2                                                   \
	(LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_PBKDF2)
/** Auxiliary information: Library health status */
#define LC_ALG_STATUS_LIB (LC_ALG_STATUS_TYPE_AUX | LC_ALG_STATUS_FLAG_LIB)

/**
 * @brief Return the self test status for the algorithm
 *
 * @param [in] algorithm Specify the algorithm(s) for which the self test status
 *	       shall be returned.
 */
enum lc_alg_status_result lc_status_get_result(uint64_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* LC_STATUS_H */
