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
 *
 * This API is only allowed to be used in non-FIPS mode. This is due to the
 * requirements of FIPS that when triggering a rerun, e.g. after a failure,
 * *all* self tests have to be executed immediately instead of lazily. This
 * is not implemented.
 */
void lc_rerun_selftests(void);

/**
 * @brief (re-)run a self test for one algorithm
 *
 * @param [in] flag Algorithm reference of one of the LC_ALG_STATUS_* flagsc
 */
void lc_rerun_one_selftest(uint64_t flag);

enum lc_alg_status_val {
	lc_alg_status_unknown = 0,
	lc_alg_status_fips_approved = (1 << 1),
	lc_alg_status_self_test_passed = (1 << 2),
	lc_alg_status_self_test_failed = (1 << 3),
};

/**
 * @brief Return status information about algorithm type
 *
 * @param [in] algorithm Algorithm reference of one of the LC_ALG_STATUS_* flags
 *
 * \note Using the LC_ALG_STATUS_LIB flag allows the caller to obtain general
 * library information (e.g. FIPS mode enabled for the library,
 * FIPS self test passed).
 *
 * @return status
 */
enum lc_alg_status_val lc_alg_status(uint64_t algorithm);

/**
 * @brief Re-run the FIPS 140 integrity test
 *
 * \note This API is only present in the FIPS module instance of leancrypto.
 *
 * \warning In FIPS mode, this call gates all algorithms. I.e. they return an
 *	    error code during initialization.
 */
void lc_fips_integrity_checker(void);

/**
 * @brief Status information about leancrypto
 *
 * @param [in] outbuf Buffer to be filled with status information, allocated by
 *		      caller
 * @param [in] outlen Size of the output buffer
 *
 * @return 0 on success; < 0 on error
 */
int lc_status(char *outbuf, size_t outlen);

/// \cond DO_NOT_DOCUMENT
/*
 * The following concept applies to the defines:
 *
 * 1. LC_ALG_STATUS_TYPE_* select the status integer to be used. The types are
 *    larger than 32 bit as they then cannot interfere with the status.
 * 2. The LC_ALG_STATUS_FLAG_* specify a specific algorithm - technically it
 *    defines the shift size of the result of lc_alg_status_result that
 *    is held for each algorithm in the status integers.
 * 3. The general status of LC_ALG_STATUS_<ALG> is the external usable flags
 */

/*
 * Internal flags which cannot be used in the API
 */
#define LC_ALG_STATUS_TYPE_MASK_SHIFT (16)

/*
 * We need 3 bits for any given flag - this size is based on
 * lc_alg_status_result as each flag is treated as a bit field where bits are
 * always and only *added* through the lifecycle of one given algorithm
 * when transitioning through the self test state:
 * pending->ongoing->passed->failed
 *
 * NOTE: as we use an atomic_t variable type for holding the bits, make sure
 * that for one given type, at max 10 different flags are defined
 */
#define LC_ALG_STATUS_FLAG_MASK_SIZE (3)
#define LC_ALG_STATUS_FLAG_MASK ((1 << LC_ALG_STATUS_TYPE_MASK_SHIFT) - 1)
#define LC_ALG_STATUS_TYPE_MASK                                                \
	(((uint32_t)-1) << LC_ALG_STATUS_TYPE_MASK_SHIFT)

#define LC_ALG_STATUS_TYPE_AEAD (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 0))
#define LC_ALG_STATUS_FLAG_AES_GCM (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_ASCON_AEAD_128 (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_ASCON_KECCAK (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_CHACHA20_POLY1305 (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_CSHAKE_CRYPT (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_HASH_CRYPT (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)
#define LC_ALG_STATUS_FLAG_KMAC_CRYPT (LC_ALG_STATUS_FLAG_MASK_SIZE * 6)
#define LC_ALG_STATUS_FLAG_SYM_HMAC (LC_ALG_STATUS_FLAG_MASK_SIZE * 7)
#define LC_ALG_STATUS_FLAG_SYM_KMAC (LC_ALG_STATUS_FLAG_MASK_SIZE * 8)

#define LC_ALG_STATUS_TYPE_KEM_PQC (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 1))
#define LC_ALG_STATUS_FLAG_HQC_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_HQC_ENC (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_HQC_DEC (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_MLKEM_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_MLKEM_ENC (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_MLKEM_DEC (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)
#define LC_ALG_STATUS_FLAG_MLKEM_ENC_KDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 6)
#define LC_ALG_STATUS_FLAG_MLKEM_DEC_KDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 7)

#define LC_ALG_STATUS_TYPE_KEM_CLASSIC                                         \
	(1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 2))
#define LC_ALG_STATUS_FLAG_X25519_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_X25519_SS (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_X448_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_X448_SS (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)

#define LC_ALG_STATUS_TYPE_SIG_PQC (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 3))
#define LC_ALG_STATUS_FLAG_MLDSA_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_MLDSA_SIGGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_MLDSA_SIGVER (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_SLHDSA_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_SLHDSA_SIGGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_SLHDSA_SIGVER (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)

#define LC_ALG_STATUS_TYPE_SIG_CLASSIC                                         \
	(1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 4))
#define LC_ALG_STATUS_FLAG_ED25519_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_ED25519_SIGGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_ED25519_SIGVER (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_ED448_KEYGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_ED448_SIGGEN (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_ED448_SIGVER (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)

#define LC_ALG_STATUS_TYPE_RNG (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 5))
#define LC_ALG_STATUS_TYPE_SEEDED_RNG                                          \
	(1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 15))
#define LC_ALG_STATUS_FLAG_CHACHA20_DRNG (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_CSHAKE_DRBG (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_HASH_DRBG (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_HMAC_DRBG (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_KMAC_DRBG (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_XDRBG128 (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)
#define LC_ALG_STATUS_FLAG_XDRBG256 (LC_ALG_STATUS_FLAG_MASK_SIZE * 6)
#define LC_ALG_STATUS_FLAG_XDRBG512 (LC_ALG_STATUS_FLAG_MASK_SIZE * 7)

#define LC_ALG_STATUS_TYPE_DIGEST (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 6))
#define LC_ALG_STATUS_FLAG_ASCON256 (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_ASCONXOF (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_SHA256 (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_SHA512 (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_SHA3 (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_SHAKE (LC_ALG_STATUS_FLAG_MASK_SIZE * 5)
#define LC_ALG_STATUS_FLAG_SHAKE512 (LC_ALG_STATUS_FLAG_MASK_SIZE * 6)
#define LC_ALG_STATUS_FLAG_CSHAKE (LC_ALG_STATUS_FLAG_MASK_SIZE * 7)
#define LC_ALG_STATUS_FLAG_KMAC (LC_ALG_STATUS_FLAG_MASK_SIZE * 8)
#define LC_ALG_STATUS_FLAG_HMAC (LC_ALG_STATUS_FLAG_MASK_SIZE * 9)

#define LC_ALG_STATUS_TYPE_SYM (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 7))
#define LC_ALG_STATUS_FLAG_AES_CBC (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_AES_CTR (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_AES_KW (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_AES_XTS (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_CHACHA20 (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)

#define LC_ALG_STATUS_TYPE_AUX (1UL << (LC_ALG_STATUS_TYPE_MASK_SHIFT + 8))
#define LC_ALG_STATUS_FLAG_HKDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 0)
#define LC_ALG_STATUS_FLAG_CTR_KDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 1)
#define LC_ALG_STATUS_FLAG_DPI_KDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 2)
#define LC_ALG_STATUS_FLAG_FB_KDF (LC_ALG_STATUS_FLAG_MASK_SIZE * 3)
#define LC_ALG_STATUS_FLAG_PBKDF2 (LC_ALG_STATUS_FLAG_MASK_SIZE * 4)
#define LC_ALG_STATUS_FLAG_LIB (LC_ALG_STATUS_FLAG_MASK_SIZE * 9)
/// \endcond

/*
 * Test status flag
 */
enum lc_alg_status_result {
	/** Testing is pending for given algorithm */
	lc_alg_status_result_pending = 0x0,
	/** Testing ongoing for given algorithm */
	lc_alg_status_result_ongoing = 0x1,
	/** Testing passed for given algorithm */
	lc_alg_status_result_passed = 0x3,
	/** Testing failed for given algorithm */
	lc_alg_status_result_failed = 0x7,
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
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_HQC_KEYGEN)
/** KEM Algorithm reference: HQC Encapsulation */
#define LC_ALG_STATUS_HQC_ENC                                                  \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_HQC_ENC)
/** KEM Algorithm reference: HQC Decapsulation */
#define LC_ALG_STATUS_HQC_DEC                                                  \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_HQC_DEC)
/** KEM Algorithm reference: ML-KEM Key Generation */
#define LC_ALG_STATUS_MLKEM_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_MLKEM_KEYGEN)
/** KEM Algorithm reference: ML-KEM Encapsulation */
#define LC_ALG_STATUS_MLKEM_ENC                                                \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_MLKEM_ENC)
/** KEM Algorithm reference: ML-KEM Decapsulation */
#define LC_ALG_STATUS_MLKEM_DEC                                                \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_MLKEM_DEC)
/** KEM Algorithm reference: ML-KEM Encapsulation with KDF */
#define LC_ALG_STATUS_MLKEM_ENC_KDF                                            \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_MLKEM_ENC_KDF)
/** KEM Algorithm reference: ML-KEM Decapsulation with KDF */
#define LC_ALG_STATUS_MLKEM_DEC_KDF                                            \
	(LC_ALG_STATUS_TYPE_KEM_PQC | LC_ALG_STATUS_FLAG_MLKEM_DEC_KDF)
/** KEM Algorithm reference: X25515 Key Generation */
#define LC_ALG_STATUS_X25519_KEYGEN                                            \
	(LC_ALG_STATUS_TYPE_KEM_CLASSIC | LC_ALG_STATUS_FLAG_X25519_KEYGEN)
/** KEM Algorithm reference: X25515 Shared Secret */
#define LC_ALG_STATUS_X25519_SS                                                \
	(LC_ALG_STATUS_TYPE_KEM_CLASSIC | LC_ALG_STATUS_FLAG_X25519_SS)
/** KEM Algorithm reference: X25515 Key Generation */
#define LC_ALG_STATUS_X448_KEYGEN                                              \
	(LC_ALG_STATUS_TYPE_KEM_CLASSIC | LC_ALG_STATUS_FLAG_X448_KEYGEN)
/** KEM Algorithm reference: X25515 Shared Secret */
#define LC_ALG_STATUS_X448_SS                                                  \
	(LC_ALG_STATUS_TYPE_KEM_CLASSIC | LC_ALG_STATUS_FLAG_X448_SS)

/** Signature Algorithm reference: ML-DSA Key Generation */
#define LC_ALG_STATUS_MLDSA_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_MLDSA_KEYGEN)
/** Signature Algorithm reference: ML-DSA Key Signature Generation */
#define LC_ALG_STATUS_MLDSA_SIGGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_MLDSA_SIGGEN)
/** Signature Algorithm reference: ML-DSA Key Signature Verification */
#define LC_ALG_STATUS_MLDSA_SIGVER                                             \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_MLDSA_SIGVER)
/** Signature Algorithm reference: SLH-DSA Key Generation */
#define LC_ALG_STATUS_SLHDSA_KEYGEN                                            \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_SLHDSA_KEYGEN)
/** Signature Algorithm reference: SLH-DSA Key Signature Generation */
#define LC_ALG_STATUS_SLHDSA_SIGGEN                                            \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_SLHDSA_SIGGEN)
/** Signature Algorithm reference: SLH-DSA Key Signature Verification */
#define LC_ALG_STATUS_SLHDSA_SIGVER                                            \
	(LC_ALG_STATUS_TYPE_SIG_PQC | LC_ALG_STATUS_FLAG_SLHDSA_SIGVER)
/** Signature Algorithm reference: ED-25519 Key Generation */
#define LC_ALG_STATUS_ED25519_KEYGEN                                           \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED25519_KEYGEN)
/** Signature Algorithm reference: ED-25519 Key Signature Generation */
#define LC_ALG_STATUS_ED25519_SIGGEN                                           \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED25519_SIGGEN)
/** Signature Algorithm reference: ED-25519 Key Signature Verification */
#define LC_ALG_STATUS_ED25519_SIGVER                                           \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED25519_SIGVER)
/** Signature Algorithm reference: ED-448 Key Generation */
#define LC_ALG_STATUS_ED448_KEYGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED448_KEYGEN)
/** Signature Algorithm reference: ED-448 Key Signature Generation */
#define LC_ALG_STATUS_ED448_SIGGEN                                             \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED448_SIGGEN)
/** Signature Algorithm reference: ED-448 Key Signature Verification */
#define LC_ALG_STATUS_ED448_SIGVER                                             \
	(LC_ALG_STATUS_TYPE_SIG_CLASSIC | LC_ALG_STATUS_FLAG_ED448_SIGVER)

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
/** Random Number Generator reference: SHAKE XDRBG256 */
#define LC_ALG_STATUS_XDRBG256                                                 \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_XDRBG256)
/** Random Number Generator reference: SHAKE XDRBG512 */
#define LC_ALG_STATUS_XDRBG512                                                 \
	(LC_ALG_STATUS_TYPE_RNG | LC_ALG_STATUS_FLAG_XDRBG512)

/** Digest reference: Ascon 256 */
#define LC_ALG_STATUS_ASCON256                                                 \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_ASCON256)
/** Digest reference: Ascon XOF */
#define LC_ALG_STATUS_ASCONXOF                                                 \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_ASCONXOF)
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
/** Digest reference: SHAKE512 */
#define LC_ALG_STATUS_SHAKE512                                                 \
	(LC_ALG_STATUS_TYPE_DIGEST | LC_ALG_STATUS_FLAG_SHAKE512)
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

/**
 * @brief Disable all algorithm startup self tests
 *
 * At runtime, before the first use of any algorithm, an algorithm-spedific
 * self test is performed to verify that the cryptographic algorithm operates
 * correctly. With this API call, the caller can prevent the execution of all
 * future algorithm self tests.
 *
 * This call effectively marks all self tests as passed. If a self test failed
 * before this API call for a given algorithm, the algorithm will remain in
 * failure mode.
 *
 * \note The caller should understand the implications of the call and only
 * perform this call if it is truly intended.
 *
 * \note Disabling of self tests in FIPS mode is not allowed and returns an
 * error.
 *
 * @return 0 on success, < 0 on error
 */
int lc_alg_disable_selftests(void);

#ifdef __cplusplus
}
#endif

#endif /* LC_STATUS_H */
