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

#include "atomic.h"
#include "fips_integrity_check.h"
#include "fips_mode.h"
#include "helper.h"
#include "initialization.h"
#include "status_algorithms.h"

/*
 * Concept of algorithm status management: For each algorithm, the amount of
 * status bits documented for LC_ALG_STATUS_FLAG_MASK_SIZE are considered.
 * To maintain those bits, a set of 32 bit integers are used. The algorithm
 * status is stored there shifted to the location unambiguously assigned to the
 * algorithm. The shift is statically defined with the LC_ALG_STATUS_FLAG_*
 * parameters. The values of  LC_ALG_STATUS_TYPE_* provide the index which of
 * the different 32 bit status integers are used for storing the status
 * information.
 *
 * LC_ALG_STATUS_TYPE_AEAD ----> lc_alg_status_aead:
 *
 * ================= 32 bits ==================
 * +--+---+---+---+---+---+---+---+---+---+---+
 * |  |   |   |   |   |   |   |   |   |   |   |
 * +--+---+---+---+---+---+---+---+---+---+---+
 *  ^   ^   ^   ^   ^   ^   ^   ^   ^   ^   ^
 *  |   |   |   |   |   |   |   |   |   |   |- Algorithm 1
 *  |   |   |   |   |   |   |   |   |   |------Algorithm 2
 *  |   |   |   |   |   |   |   |   |----------Algorithm 3
 *  |   |   |   |   |   |   |   |--------------Algorithm 4
 *  |   |   |   |   |   |   |------------------Algorithm 5
 *  |   |   |   |   |   |----------------------Algorithm 6
 *  |   |   |   |   |--------------------------Algorithm 7
 *  |   |   |   |------------------------------Algorithm 8
 *  |   |   |----------------------------------Algorithm 9
 *  |   |--------------------------------------Algorithm 10
 *  |------------------------------------------Unused
 *
 * State of one algorithm
 *
 * +---+
 * |000| -> test pending
 * +---+
 * +---+
 * |001| -> test ongoing
 * +---+
 * +---+
 * |011| -> test passed
 * +---+
 * +---+
 * |111| -> test failed
 * +---+
 */
typedef uint32_t alg_status_t;

#define ALG_ALL_BITS (0xffffffff)
#define ALG_CLEAR_ALL_BITS ATOMIC_INIT(0)
#define ALG_SET_ALL_BITS ATOMIC_INIT((int)ALG_ALL_BITS)
#define ALG_SET_TEST_PENDING(flag) (lc_alg_status_result_pending << flag)
#define ALG_SET_TEST_PASSED(flag) (lc_alg_status_result_passed << flag)
#define ALG_SET_TEST_FAILED(flag) (lc_alg_status_result_failed << flag)

static atomic_t lc_alg_status_aead = ALG_SET_ALL_BITS;

/* Disable selftests */
#ifdef LC_KYBER_DEBUG
static atomic_t lc_alg_status_kem_pqc =
	ATOMIC_INIT(ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_KEYGEN) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_ENC) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_DEC) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_ENC_KDF) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_DEC_KDF));
#else
static atomic_t lc_alg_status_kem_pqc = ALG_SET_ALL_BITS;
#endif

static atomic_t lc_alg_status_kem_classic = ALG_SET_ALL_BITS;

/* Disable selftests */
#ifdef LC_DILITHIUM_DEBUG
static atomic_t lc_alg_status_sig_pqc =
	ATOMIC_INIT(ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLDSA_KEYGEN) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLDSA_SIGGEN) |
		    ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLDSA_SIGVER));
/*
	 * We do not touch the SLH-DSA flags, which implies that SLH-DSA could
	 * run while initialization is in progress, but we do not care as
	 * handling this would complicate the code without benefit: the
	 * ML-DSA debugging enablement is NEVER in production code.
	 */
#else
static atomic_t lc_alg_status_sig_pqc = ALG_SET_ALL_BITS;
#endif

static atomic_t lc_alg_status_sig_classic = ALG_SET_ALL_BITS;

static atomic_t lc_alg_status_rng = ALG_SET_ALL_BITS;

static atomic_t lc_alg_status_digest = ALG_SET_ALL_BITS;

static atomic_t lc_alg_status_sym = ALG_SET_ALL_BITS;

/*
 * Set all bits except the library initialization bits which implies that the
 * library is now in pending state.
 *
 * The overall library initialization state is designed as follows:
 *
 * 1. Library is loaded -> all status bits show that all algorithms are in
 *    failure state, except the library status, which is in pending state.
 * 2. In FIPS mode:
 *  a. Set all status bits show that all algorithms are in failure state, except
 *     the library status, which is in pending state. I.e. (re)establish the
 *     same values as set during compile time. This prevents the initialization
 *     of any algorithms (required for the FIPS integrity test when leaving
 *     degraded mode).
 *  b. The library is now set into ongoing state.
 *  c. The SHA3-256 algorithm is initialized where, even though the SHA3 state
 *     is in failed state, it performs its self test as the library is in
 *     ongoing state.
 *  d. When the SHA3-256 self test passed, its state is set into passed state.
 *     If the self test failed, the state is set into failed state and the
 *     hash initialization will fail which leads to a FIPS integrity check
 *     failure.
 *  e. Now, the FIPS integrity test is performed. When the test fails, the
 *     module remains in error state. This allows only status information to be
 *     accessed.
 *  f. When the FIPS self-test successfully completes, the library is set into
 *     passed state.
 *  g. All algorithms except the SHA3-256 are set into pending state. The
 *     SHA3-256 state is left untouched (i.e. passed) to not rerun the self test
 *     again.
 * 3. In non-FIPS mode:
 *  a. The library is set to the passed state.
 *  b. All algorithms are set into pending state.
 */
static atomic_t lc_alg_status_aux =
	ATOMIC_INIT(~ALG_SET_TEST_FAILED(LC_ALG_STATUS_FLAG_LIB));

struct alg_status_show {
	uint64_t flag;
	const char *alg_name;
	uint8_t strlen;
};

/*
 * Marker for an algorithm whether it is FIPS-approved - this marker uses the high
 * bits in the algorithm type which are not accessible via the types.
 */
#define LC_ALG_STATUS_FIPS (1UL << 31)

// clang-format off
static const struct alg_status_show alg_status_show_aead[] = {
#if (defined(LC_AES_GCM) || defined(CONFIG_LEANCRYPTO_AES_GCM))
{ .flag = LC_ALG_STATUS_AES_GCM | LC_ALG_STATUS_FIPS, .alg_name = "AES-GCM", .strlen = 7 },
#endif
#if (defined(LC_CHACHA20_POLY1305) ||                                          \
     defined(CONFIG_LEANCRYPTO_CHACHA20_POLY1305))
{ .flag = LC_ALG_STATUS_CHACHA20_POLY1305, .alg_name = "ChaCha20-Poly1305", .strlen = 17 },
#endif
#if (defined(LC_ASCON_HASH) ||                                                 \
     (defined(CONFIG_LEANCRYPTO_ASCON_CRYPT) && defined(LC_ASCON)))
{ .flag = LC_ALG_STATUS_ASCON_AEAD_128 | LC_ALG_STATUS_FIPS, .alg_name = "Ascon-AEAD128", .strlen = 13 },
#endif
#if (defined(LC_ASCON_KECCAK) ||                                               \
     (defined(CONFIG_LEANCRYPTO_ASCON_CRYPT) && defined(LC_ASCON_KECCAK)))
{ .flag = LC_ALG_STATUS_ASCON_KECCAK, .alg_name = "Ascon-Keccak", .strlen = 12 },
#endif
#if (defined(LC_HASH_CRYPT) || defined(CONFIG_LEANCRYPTO_HASH_CRYPT))
{ .flag = LC_ALG_STATUS_CSHAKE_CRYPT, .alg_name = "cSHAKE-Crypt", .strlen = 12 },
{ .flag = LC_ALG_STATUS_HASH_CRYPT, .alg_name = "Hash-Crypt", .strlen = 10 },
{ .flag = LC_ALG_STATUS_KMAC_CRYPT, .alg_name = "KMAC-Crypt", .strlen = 10 },
#endif
#if (((defined(LC_AES_CBC) || defined(LC_AES_CTR)) && defined(LC_SHA2_512)) || \
     defined(CONFIG_LEANCRYPTO_SYMHMAC_CRYPT))
{ .flag = LC_ALG_STATUS_SYM_HMAC | LC_ALG_STATUS_FIPS, .alg_name = "Sym-HMAC", .strlen = 8 },
#endif
#if (((defined(LC_AES_CBC) || defined(LC_aeS_CTR)) && defined(LC_KMAC)) ||     \
     defined(CONFIG_LEANCRYPTO_SYMKMAC_CRYPT))
{ .flag = LC_ALG_STATUS_SYM_KMAC | LC_ALG_STATUS_FIPS, .alg_name = "Sym-KMAC", .strlen = 8 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_kem_pqc[] = {
#if (defined(LC_HQC) ||                                                        \
     defined(CONFIG_LEANCRYPTO_KEM_HQC_256) ||                                 \
     defined(CONFIG_LEANCRYPTO_KEM_HQC_192) ||                                 \
     defined(CONFIG_LEANCRYPTO_KEM_HQC_128))
{ .flag = LC_ALG_STATUS_HQC_KEYGEN, .alg_name = "HQC-Keygen", .strlen = 10 },
{ .flag = LC_ALG_STATUS_HQC_ENC, .alg_name = "HQC-Enc", .strlen = 7 },
{ .flag = LC_ALG_STATUS_HQC_DEC, .alg_name = "HQC-Dec", .strlen = 7 },
#endif
#if (defined(LC_KYBER) || defined(CONFIG_LEANCRYPTO_KEM))
{ .flag = LC_ALG_STATUS_MLKEM_KEYGEN | LC_ALG_STATUS_FIPS, .alg_name = "ML-KEM-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_MLKEM_ENC | LC_ALG_STATUS_FIPS, .alg_name = "ML-KEM-Enc", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLKEM_DEC | LC_ALG_STATUS_FIPS, .alg_name = "ML-KEM-Dec", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLKEM_ENC_KDF | LC_ALG_STATUS_FIPS, .alg_name = "ML-KEM-Enc-KDF", .strlen = 14 },
{ .flag = LC_ALG_STATUS_MLKEM_DEC_KDF | LC_ALG_STATUS_FIPS, .alg_name = "ML-KEM-Dec-KDF", .strlen = 14 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_kem_classic[] = {
#ifdef LC_CURVE25519
{ .flag = LC_ALG_STATUS_X25519_KEYGEN, .alg_name = "X25519-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_X25519_SS, .alg_name = "X25519-SS", .strlen = 9 },
#endif
#ifdef LC_CURVE448
{ .flag = LC_ALG_STATUS_X448_KEYGEN, .alg_name = "X448-Keygen", .strlen = 11 },
{ .flag = LC_ALG_STATUS_X448_SS, .alg_name = "X448-SS", .strlen = 7 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sig_pqc[] = {
#if (defined(LC_DILITHIUM) || defined(CONFIG_LEANCRYPTO_DILITHIUM))
{ .flag = LC_ALG_STATUS_MLDSA_KEYGEN | LC_ALG_STATUS_FIPS, .alg_name = "ML-DSA-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_MLDSA_SIGGEN | LC_ALG_STATUS_FIPS, .alg_name = "ML-DSA-Enc", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLDSA_SIGVER | LC_ALG_STATUS_FIPS, .alg_name = "ML-DSA-Dec", .strlen = 10 },
#endif
#if (defined(LC_SPHINCS) || defined(CONFIG_LEANCRYPTO_SPHINCS))
{ .flag = LC_ALG_STATUS_SLHDSA_KEYGEN | LC_ALG_STATUS_FIPS, .alg_name = "SLH-DSA-Keygen", .strlen = 14 },
{ .flag = LC_ALG_STATUS_SLHDSA_SIGGEN | LC_ALG_STATUS_FIPS, .alg_name = "SLH-DSA-Enc", .strlen = 11 },
{ .flag = LC_ALG_STATUS_SLHDSA_SIGVER | LC_ALG_STATUS_FIPS, .alg_name = "SLH-DSA-Dec", .strlen = 11 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sig_classic[] = {
#if (defined(LC_DILITHIUM_ED25519) || defined(LC_CURVE25519))
{ .flag = LC_ALG_STATUS_ED25519_KEYGEN | LC_ALG_STATUS_FIPS, .alg_name = "ED25519-Keygen", .strlen = 14 },
{ .flag = LC_ALG_STATUS_ED25519_SIGGEN | LC_ALG_STATUS_FIPS, .alg_name = "ED25519-Enc", .strlen = 11 },
{ .flag = LC_ALG_STATUS_ED25519_SIGVER | LC_ALG_STATUS_FIPS, .alg_name = "ED25519-Dec", .strlen = 11 },
#endif
#if (defined(LC_DILITHIUM_ED448) || defined(LC_CURVE448))
{ .flag = LC_ALG_STATUS_ED448_KEYGEN | LC_ALG_STATUS_FIPS, .alg_name = "ED448-Keygen", .strlen = 12 },
{ .flag = LC_ALG_STATUS_ED448_SIGGEN | LC_ALG_STATUS_FIPS, .alg_name = "ED448-Enc", .strlen = 9 },
{ .flag = LC_ALG_STATUS_ED448_SIGVER | LC_ALG_STATUS_FIPS, .alg_name = "ED448-Dec", .strlen = 9 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_rng[] = {
#if (defined(LC_DRNG_XDRBG256) ||                                              \
     (defined(CONFIG_LEANCRYPTO_XDRBG_DRNG) && defined(CONFIG_LEANCRYPTO_SHA3)))
{ .flag = LC_ALG_STATUS_XDRBG256, .alg_name = "XDRBG256", .strlen = 8 },
{ .flag = LC_ALG_STATUS_XDRBG512, .alg_name = "XDRBG512", .strlen = 8 },
#endif
#if (defined(LC_DRNG_XDRBG128) ||                                              \
     (defined(CONFIG_LEANCRYPTO_XDRBG_DRNG) &&                                 \
      defined(CONFIG_LEANCRYPTO_ASCON_HASH)))
{ .flag = LC_ALG_STATUS_XDRBG128, .alg_name = "XDRBG128", .strlen = 8 },
#endif
#if (defined(LC_DRNG_CC20) || defined(CONFIG_LEANCRYPTO_CHACHA20_DRNG))
{ .flag = LC_ALG_STATUS_CHACHA20_DRNG, .alg_name = "ChaCha20-DRNG", .strlen = 13 },
#endif
#if (defined(LC_DRNG_CSHAKE) || defined(CONFIG_LEANCRYPTO_CSHAKE_DRNG))
{ .flag = LC_ALG_STATUS_CSHAKE_DRBG, .alg_name = "cSHAKE-DRBG", .strlen = 11 },
#endif
#if (defined(LC_DRNG_HASH_DRBG) || defined(CONFIG_LEANCRYPTO_HASH_DRBG))
{ .flag = LC_ALG_STATUS_HASH_DRBG | LC_ALG_STATUS_FIPS, .alg_name = "Hash-DRBG", .strlen = 9 },
#endif
#if (defined(LC_DRNG_HMAC_DRBG) || defined(CONFIG_LEANCRYPTO_HMAC_DRBG))
{ .flag = LC_ALG_STATUS_HMAC_DRBG | LC_ALG_STATUS_FIPS, .alg_name = "HMAC-DRBG", .strlen = 9 },
#endif
#if (defined(LC_DRNG_KMAC) || defined(CONFIG_LEANCRYPTO_KMAC_DRNG))
{ .flag = LC_ALG_STATUS_KMAC_DRBG, .alg_name = "KMAC-DRBG", .strlen = 9 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_digest[] = {
#if (defined(LC_ASCON_HASH) || defined(CONFIG_LEANCRYPTO_ASCON_HASH))
{ .flag = LC_ALG_STATUS_ASCON256 | LC_ALG_STATUS_FIPS, .alg_name = "Ascon256", .strlen = 8 },
{ .flag = LC_ALG_STATUS_ASCONXOF | LC_ALG_STATUS_FIPS, .alg_name = "AsconXOF", .strlen = 8 },
#endif
#if (defined(LC_SHA2_256) || defined(CONFIG_LEANCRYPTO_SHA2_256))
{ .flag = LC_ALG_STATUS_SHA256 | LC_ALG_STATUS_FIPS, .alg_name = "SHA-256", .strlen = 7 },
#endif
#if (defined(LC_SHA2_512) || defined(CONFIG_LEANCRYPTO_SHA2_512))
{ .flag = LC_ALG_STATUS_SHA512 | LC_ALG_STATUS_FIPS, .alg_name = "SHA-512", .strlen = 7 },
#endif
#ifdef LC_SHA3
{ .flag = LC_ALG_STATUS_SHA3 | LC_ALG_STATUS_FIPS, .alg_name = "SHA-3", .strlen = 5 },
{ .flag = LC_ALG_STATUS_SHAKE | LC_ALG_STATUS_FIPS, .alg_name = "SHAKE", .strlen = 5 },
{ .flag = LC_ALG_STATUS_SHAKE512, .alg_name = "SHAKE512", .strlen = 8 },
{ .flag = LC_ALG_STATUS_CSHAKE | LC_ALG_STATUS_FIPS, .alg_name = "cSHAKE", .strlen = 6 },
#endif
#if (defined(LC_KMAC) || defined(CONFIG_LEANCRYPTO_KMAC))
{ .flag = LC_ALG_STATUS_KMAC | LC_ALG_STATUS_FIPS, .alg_name = "KMAC", .strlen = 4 },
#endif
#if (defined(LC_HMAC) || defined(CONFIG_LEANCRYPTO_HMAC))
{ .flag = LC_ALG_STATUS_HMAC | LC_ALG_STATUS_FIPS, .alg_name = "HMAC", .strlen = 4 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sym[] = {
#if (defined(LC_AES_CBC) || defined(CONFIG_LEANCRYPTO_AES_CBC))
{ .flag = LC_ALG_STATUS_AES_CBC | LC_ALG_STATUS_FIPS, .alg_name = "AES-CBC", .strlen = 7 },
#endif
#if (defined(LC_AES_CTR) || defined(CONFIG_LEANCRYPTO_AES_CTR))
{ .flag = LC_ALG_STATUS_AES_CTR | LC_ALG_STATUS_FIPS, .alg_name = "AES-CTR", .strlen = 7 },
#endif
#if (defined(LC_AES_KW) || defined(CONFIG_LEANCRYPTO_AES_KW))
{ .flag = LC_ALG_STATUS_AES_KW | LC_ALG_STATUS_FIPS, .alg_name = "AES-KW", .strlen = 6 },
#endif
#if (defined(LC_AES_XTS) || defined(CONFIG_LEANCRYPTO_AES_XTS))
{ .flag = LC_ALG_STATUS_AES_XTS | LC_ALG_STATUS_FIPS, .alg_name = "AES-XTS", .strlen = 7 },
#endif
#if (defined(LC_CHACHA20) || defined(CONFIG_LEANCRYPTO_CHACHA20))
{ .flag = LC_ALG_STATUS_CHACHA20, .alg_name = "ChaCha20", .strlen = 8 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_aux[] = {
#if (defined(LC_HKDF) || defined(CONFIG_LEANCRYPTO_HKDF))
{ .flag = LC_ALG_STATUS_HKDF | LC_ALG_STATUS_FIPS, .alg_name = "HKDF", .strlen = 4 },
#endif
#if (defined(LC_KDF_CTR) || defined(DCONFIG_LEANCRYPTO_KDF_CTR))
{ .flag = LC_ALG_STATUS_CTR_KDF | LC_ALG_STATUS_FIPS, .alg_name = "CTR-KDF", .strlen = 7 },
#endif
#if (defined(LC_KDF_DPI) || defined(DCONFIG_LEANCRYPTO_KDF_DPI))
{ .flag = LC_ALG_STATUS_DPI_KDF | LC_ALG_STATUS_FIPS, .alg_name = "DPI-KDF", .strlen = 7 },
#endif
#if (defined(LC_KDF_FB) || defined(DCONFIG_LEANCRYPTO_KDF_FB))
{ .flag = LC_ALG_STATUS_FB_KDF | LC_ALG_STATUS_FIPS, .alg_name = "FB-KDF", .strlen = 6 },
#endif
#if (defined(LC_DRNG_PBKDF2) || defined(CONFIG_LEANCRYPTO_PBKDF2))
{ .flag = LC_ALG_STATUS_PBKDF2 | LC_ALG_STATUS_FIPS, .alg_name = "PBKDF2", .strlen = 6 },
#endif
{ .flag = LC_ALG_STATUS_LIB, .alg_name = "Lib-Available", .strlen = 13 },
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

// clang-format on
static inline void alg_status_set_common(alg_status_t common_value,
					 alg_status_t digest_value,
					 alg_status_t aux_value)
{
	atomic_set(&lc_alg_status_aead, (int)common_value);

#ifndef LC_KYBER_DEBUG
	atomic_set(&lc_alg_status_kem_pqc, (int)common_value);
#endif

	atomic_set(&lc_alg_status_kem_classic, (int)common_value);

#ifndef LC_DILITHIUM_DEBUG
	atomic_set(&lc_alg_status_sig_pqc, (int)common_value);
#endif

	atomic_set(&lc_alg_status_sig_classic, (int)common_value);
	atomic_set(&lc_alg_status_rng, (int)common_value);
	atomic_set(&lc_alg_status_digest, (int)digest_value);
	atomic_set(&lc_alg_status_sym, (int)common_value);
	atomic_set(&lc_alg_status_aux, (int)aux_value);
}

static void alg_status_set_init_state(void)
{
	/*
	 * Replicate the compile-time initialization state, but do not alter
	 * the library flag.
	 */
	alg_status_set_common(
		ALG_ALL_BITS, ALG_ALL_BITS,
		(alg_status_t)(~ALG_SET_TEST_FAILED(LC_ALG_STATUS_FLAG_LIB)));
}

static void alg_status_unset_test_state(alg_status_t digest_value)
{
	/*
	 * At that point, automatically define the library to be in passed
	 * state.
	 */
	alg_status_set_common(
		0, digest_value,
		(alg_status_t)ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_LIB));
}

void alg_status_set_all_passed_state(void)
{
	static const int all_passed =
		lc_alg_status_result_passed << (3 * 0) |
		lc_alg_status_result_passed << (3 * 1) |
		lc_alg_status_result_passed << (3 * 2) |
		lc_alg_status_result_passed << (3 * 3) |
		lc_alg_status_result_passed << (3 * 4) |
		lc_alg_status_result_passed << (3 * 5) |
		lc_alg_status_result_passed << (3 * 6) |
		lc_alg_status_result_passed << (3 * 7) |
		lc_alg_status_result_passed << (3 * 8) |
		lc_alg_status_result_passed << (3 * 9);

	/*
	 * Replicate the compile-time initialization state, but leave the
	 * library state unchanged.
	 */
	atomic_or(all_passed, &lc_alg_status_aead);

#ifndef LC_KYBER_DEBUG
	atomic_or(all_passed, &lc_alg_status_kem_pqc);
#endif

	atomic_or(all_passed, &lc_alg_status_kem_classic);

#ifndef LC_DILITHIUM_DEBUG
	atomic_or(all_passed, &lc_alg_status_sig_pqc);
#endif

	atomic_or(all_passed, &lc_alg_status_sig_classic);
	atomic_or(all_passed, &lc_alg_status_rng);
	atomic_or(all_passed, &lc_alg_status_digest);
	atomic_or(all_passed, &lc_alg_status_sym);
	atomic_or(all_passed, &lc_alg_status_aux);
}

static void alg_status_unset_testresult_one(alg_status_t alg, atomic_t *status)
{
	/*
	 * This unsets the test status for a given algorithm moving its state
	 * back to pending state. This implies that a new test cycle for the
	 * algorithm is started.
	 */
	atomic_and((int)(~(lc_alg_status_result_failed << alg)), status);
}

#define alg_status_set_testresult_val(operation, test_ret, flag, status)       \
	operation((int)(test_ret << (flag & ~LC_ALG_STATUS_TYPE_MASK) ),       \
		  status)

static void alg_status_set_testresult(enum lc_alg_status_result test_ret,
				      uint64_t flag, atomic_t *status)
{
	/*
	 * In FIPS mode, we enter the degraded mode of operation when a self
	 * test error is observed. This requires that all self tests of all
	 * other algorithms must be reperformed. As this should never happen,
	 * it is a small price to pay to cover this requirement.
	 *
	 * In case, however, the whole library is failing, then do not unset
	 * the state, as all algorithms are in failure state and we want to stay
	 * in failure mode.
	 */
	if (test_ret == lc_alg_status_result_failed && fips140_mode_enabled() &&
	    flag != LC_ALG_STATUS_LIB)
		alg_status_unset_test_state(0);

	/*
	 * This operation only works by assuming the state transition documented
	 * for LC_ALG_STATUS_FLAG_MASK_SIZE.
	 *
	 * NOTE: This operation can only *add* bits, never remove them. Thus
	 * the final state where all bits are set is considered the failure
	 * state which defines the fail-secure state where we cannot get back
	 * unless alg_status_unset_test_state or lc_alg_status_unset_testresult
	 * for the offending algorithm is called triggering a full retest of
	 * either all or just the offending algorithm.
	 */
	alg_status_set_testresult_val(atomic_or, test_ret, flag, status);
}

#define alg_status_result_interpret(val, alg)                                  \
	((enum lc_alg_status_result)                                           \
		       /* Read out the entire state variable */                \
		       val                                                     \
		       /* Downshift to the required flag */                    \
		       >> alg                                                  \
	       /* Eliminate the upper bits */                                  \
	       & ((1 << LC_ALG_STATUS_FLAG_MASK_SIZE) - 1))

static enum lc_alg_status_result alg_status_result(atomic_t *status,
						   alg_status_t alg)
{
	/*
	 * This call obtains the flag field in the middle of some integer field
	 *
	 * For example, assume your status field contains the following bits
	 *
	 * AAABBBCCCDDD
	 *
	 * where the different letters refer to the bitset for one algorithm.
	 *
	 * Now, say, we want to get the bit set for the algorithm B. We do
	 *
	 * 1. read the entire status field
	 * 2. downshift B to the begining to eliminate C and D bits
	 * 3. now eliminate the A bits by applying a mask.
	 */
	/* Cast to lc_alg_status_result */
	return alg_status_result_interpret(atomic_read(status), alg);
}

static enum lc_alg_status_val alg_status_is_fips_one(
	uint64_t flag, const struct alg_status_show *alg_status_show_arr,
	size_t array_size, atomic_t *status)
{
	const struct alg_status_show *alg_status_show;
	alg_status_t alg = flag & ~LC_ALG_STATUS_TYPE_MASK;
	unsigned int i;
	enum lc_alg_status_result result = alg_status_result(status, alg);
	enum lc_alg_status_val val = lc_alg_status_unknown;

	switch (result) {
	case lc_alg_status_result_passed:
		val |= lc_alg_status_self_test_passed;
		break;
	case lc_alg_status_result_failed:
		val |= lc_alg_status_self_test_failed;
		break;
	case lc_alg_status_result_pending:
	case lc_alg_status_result_ongoing:
	default:
		break;
	}

	/*
	 * Find the definition in the array for the given algorithm and
	 * extract the FIPS approved marker.
	 */
	for (i = 0, alg_status_show = alg_status_show_arr; i < array_size;
	     i++, alg_status_show++) {
		if ((alg_status_show->flag & ~LC_ALG_STATUS_TYPE_MASK) == alg) {
			if (alg_status_show->flag & LC_ALG_STATUS_FIPS)
				val |= lc_alg_status_fips_approved;

			break;
		}
	}

	return val;
}

enum lc_alg_status_result alg_status_get_result(uint64_t flag)
{
	alg_status_t alg = flag & ~LC_ALG_STATUS_TYPE_MASK;

	switch (flag & LC_ALG_STATUS_TYPE_MASK) {
	case LC_ALG_STATUS_TYPE_AEAD:
		return alg_status_result(&lc_alg_status_aead, alg);
		break;
	case LC_ALG_STATUS_TYPE_KEM_PQC:
		return alg_status_result(&lc_alg_status_kem_pqc, alg);
		break;
	case LC_ALG_STATUS_TYPE_KEM_CLASSIC:
		return alg_status_result(&lc_alg_status_kem_classic, alg);
		break;
	case LC_ALG_STATUS_TYPE_SIG_PQC:
		return alg_status_result(&lc_alg_status_sig_pqc, alg);
		break;
	case LC_ALG_STATUS_TYPE_SIG_CLASSIC:
		return alg_status_result(&lc_alg_status_sig_classic, alg);
		break;
	case LC_ALG_STATUS_TYPE_RNG:
		return alg_status_result(&lc_alg_status_rng, alg);
		break;
	case LC_ALG_STATUS_TYPE_DIGEST:
		return alg_status_result(&lc_alg_status_digest, alg);
		break;
	case LC_ALG_STATUS_TYPE_SYM:
		return alg_status_result(&lc_alg_status_sym, alg);
		break;
	case LC_ALG_STATUS_TYPE_AUX:
		return alg_status_result(&lc_alg_status_aux, alg);
		break;
	default:
		return lc_alg_status_result_pending;
	}
}

void alg_status_set_result(enum lc_alg_status_result test_ret, uint64_t flag)
{
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AEAD) {
		alg_status_set_testresult(test_ret, flag, &lc_alg_status_aead);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		alg_status_set_testresult(test_ret, flag,
					  &lc_alg_status_kem_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		alg_status_set_testresult(test_ret, flag,
					  &lc_alg_status_kem_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		alg_status_set_testresult(test_ret, flag,
					  &lc_alg_status_sig_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		alg_status_set_testresult(test_ret, flag,
					  &lc_alg_status_sig_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		alg_status_set_testresult(test_ret, flag, &lc_alg_status_rng);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		alg_status_set_testresult(test_ret, flag,
					  &lc_alg_status_digest);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		alg_status_set_testresult(test_ret, flag, &lc_alg_status_sym);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		alg_status_set_testresult(test_ret, flag, &lc_alg_status_aux);
	}
}

void alg_status_unset_result(uint64_t flag)
{
	alg_status_t alg = flag & ~LC_ALG_STATUS_TYPE_MASK;

	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AEAD) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_aead);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_kem_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		alg_status_unset_testresult_one(alg,
						&lc_alg_status_kem_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_sig_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		alg_status_unset_testresult_one(alg,
						&lc_alg_status_sig_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_rng);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_digest);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_sym);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		alg_status_unset_testresult_one(alg, &lc_alg_status_aux);
	}
}

enum lc_alg_status_val alg_status(uint64_t flag)
{
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AEAD) {
		return alg_status_is_fips_one(
			flag, alg_status_show_aead,
			ARRAY_SIZE(alg_status_show_aead) - 1,
			&lc_alg_status_aead);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		return alg_status_is_fips_one(
			flag, alg_status_show_kem_pqc,
			ARRAY_SIZE(alg_status_show_kem_pqc) - 1,
			&lc_alg_status_kem_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		return alg_status_is_fips_one(
			flag, alg_status_show_kem_classic,
			ARRAY_SIZE(alg_status_show_kem_classic) - 1,
			&lc_alg_status_kem_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		return alg_status_is_fips_one(
			flag, alg_status_show_sig_pqc,
			ARRAY_SIZE(alg_status_show_sig_pqc) - 1,
			&lc_alg_status_sig_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		return alg_status_is_fips_one(
			flag, alg_status_show_sig_classic,
			ARRAY_SIZE(alg_status_show_sig_classic) - 1,
			&lc_alg_status_sig_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		return alg_status_is_fips_one(
			flag, alg_status_show_rng,
			ARRAY_SIZE(alg_status_show_rng) - 1,
			&lc_alg_status_rng);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		return alg_status_is_fips_one(
			flag, alg_status_show_digest,
			ARRAY_SIZE(alg_status_show_digest) - 1,
			&lc_alg_status_digest);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		return alg_status_is_fips_one(
			flag, alg_status_show_sym,
			ARRAY_SIZE(alg_status_show_sym) - 1,
			&lc_alg_status_sym);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		enum lc_alg_status_val ret =
			alg_status_is_fips_one(
				flag, alg_status_show_aux,
				ARRAY_SIZE(alg_status_show_aux) - 1,
				&lc_alg_status_aux);

		if (flag == LC_ALG_STATUS_LIB) {
			if (fips140_mode_enabled())
				ret |= lc_alg_status_fips_approved;
			else
				ret &= (enum lc_alg_status_val)
						(~lc_alg_status_fips_approved);
		}

		return ret;
	}

	return 0;
}

void alg_status_unset_result_all(void)
{
	alg_status_unset_test_state(0);
}

static void alg_status_one(const struct alg_status_show *alg_status_show_arr,
			   size_t array_size, uint64_t flag, atomic_t *status,
			   char **test_completed, size_t *test_completed_len,
			   char **test_open, size_t *test_open_len,
			   char **errorbuf, size_t *errorbuf_len)
{
	const struct alg_status_show *alg_status_show;
	size_t i;
	enum lc_alg_status_result res;

	for (i = 0, alg_status_show = alg_status_show_arr; i < array_size;
	     i++, alg_status_show++) {
		char **outbuf;
		size_t *outbuf_len;

		/* Is it the alg that is requeted? */
		if ((alg_status_show->flag & flag) != alg_status_show->flag)
			continue;

		res = alg_status_result(
			status, (alg_status_t)(alg_status_show->flag &
					       ~LC_ALG_STATUS_TYPE_MASK));
		switch (res) {
		case lc_alg_status_result_passed:
			outbuf = test_completed;
			outbuf_len = test_completed_len;
			break;
		case lc_alg_status_result_failed:
			outbuf = errorbuf;
			outbuf_len = errorbuf_len;
			break;
		case lc_alg_status_result_pending:
			outbuf = test_open;
			outbuf_len = test_open_len;
			break;
		case lc_alg_status_result_ongoing:
		default:
			continue;
		}

		/* No overflow */
		if (*outbuf_len < (size_t)alg_status_show->strlen + 2)
			continue;

		memcpy(*outbuf, alg_status_show->alg_name,
		       alg_status_show->strlen);

		/* Space */
		*(*outbuf + alg_status_show->strlen) = 0x20;

		/* String Terminator */
		*(*outbuf + alg_status_show->strlen + 1) = '\0';

		/* Advance pointer, but ignore terminator */
		*outbuf += alg_status_show->strlen + 1;
		*outbuf_len -= alg_status_show->strlen + 1;
	}
}

void alg_status_print(uint64_t flag, char *test_completed,
		      size_t test_completed_len, char *test_open,
		      size_t test_open_len, char *errorbuf, size_t errorbuf_len)
{
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AEAD) {
		alg_status_one(
			/*
			 * Always subtract one from the ARRAY_SIZE to skip the
			 * last NULL entry. This entry is only there to stop
			 * the compiler from complaining about potentially empty
			 * arrays.
			 */
			alg_status_show_aead,
			ARRAY_SIZE(alg_status_show_aead) - 1, flag,
			&lc_alg_status_aead, &test_completed,
			&test_completed_len, &test_open, &test_open_len,
			&errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		alg_status_one(alg_status_show_kem_pqc,
			       ARRAY_SIZE(alg_status_show_kem_pqc) - 1, flag,
			       &lc_alg_status_kem_pqc, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		alg_status_one(alg_status_show_kem_classic,
			       ARRAY_SIZE(alg_status_show_kem_classic) - 1,
			       flag, &lc_alg_status_kem_classic,
			       &test_completed, &test_completed_len, &test_open,
			       &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		alg_status_one(alg_status_show_sig_pqc,
			       ARRAY_SIZE(alg_status_show_sig_pqc) - 1, flag,
			       &lc_alg_status_sig_pqc, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		alg_status_one(alg_status_show_sig_classic,
			       ARRAY_SIZE(alg_status_show_sig_classic) - 1,
			       flag, &lc_alg_status_sig_classic,
			       &test_completed, &test_completed_len, &test_open,
			       &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		alg_status_one(alg_status_show_rng,
			       ARRAY_SIZE(alg_status_show_rng) - 1, flag,
			       &lc_alg_status_rng, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		alg_status_one(alg_status_show_digest,
			       ARRAY_SIZE(alg_status_show_digest) - 1, flag,
			       &lc_alg_status_digest, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		alg_status_one(alg_status_show_sym,
			       ARRAY_SIZE(alg_status_show_sym) - 1, flag,
			       &lc_alg_status_sym, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		alg_status_one(alg_status_show_aux,
			       ARRAY_SIZE(alg_status_show_aux) - 1, flag,
			       &lc_alg_status_aux, &test_completed,
			       &test_completed_len, &test_open, &test_open_len,
			       &errorbuf, &errorbuf_len);
	}
}

/*
 * FIPS mode: integrity check state
 *
 * returns whether the initialization should continue (0) or whether the
 * initialization should abort as another thread is initializing the state.
 */
int lc_activate_library_selftest_init(int reinit)
{
	if (!reinit) {
		/*
		 * This is the initialization of the library: set the state to
		 * ongoing in a race-free manner and ensure that this code path
		 * is only executed once.
		 */
		int status;

		/*
		* Race-free: fetch the value of the status flag before ORing the
		* ongoing flag. If the value before ORing already shows ongoing
		* (or passed/failed), the ORing did not change the value.
		*/
		status = alg_status_set_testresult_val(
				atomic_fetch_or, lc_alg_status_result_ongoing,
				LC_ALG_STATUS_LIB, &lc_alg_status_aux);

		/*
		* Now analyze the fetched value before ORing: was it pending?
		* If yes, initialize the library. If not, this function got
		* invoked again and we ignore this invocation.
		*/
		if (alg_status_result_interpret(status,
						LC_ALG_STATUS_FLAG_LIB) >
		    lc_alg_status_result_pending)
			return 1;
	}

	/*
	 * Set the library to initialization state.
	 */
	alg_status_set_init_state();

	return 0;
}

/*
 * FIPS mode: integrity check completed, mark library to be usable.
 */
void lc_activate_library_selftest_fini(void)
{
	/*
	 * SHA3-256 self test shall be kept. Thus, AND all bits set (defined by
	 * the failed status) to the state which implies that the status given
	 * there is kept.
	 */
	if (lc_status_get_result(LC_ALG_STATUS_LIB) ==
	    lc_alg_status_result_passed) {
		alg_status_unset_test_state(
			ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_SHA3));
	}
}

/*
 * Non-FIPS mode: mark library to be usable.
 */
void lc_activate_library_internal(void)
{
	int status;

	/*
	 * Race-free: fetch the value of the status flag before ORing the
	 * passed flag. If the value before ORing already shows passed (or
	 * failed), the ORing did not change the value.
	 */
	status = alg_status_set_testresult_val(
			atomic_fetch_or, lc_alg_status_result_passed,
			LC_ALG_STATUS_LIB, &lc_alg_status_aux);

	/*
	 * Now analyze the fetched value before ORing: was it pending?
	 * If yes, initialize the library. If not, this function got invoked
	 * again and we ignore this invocation.
	 */
	if (alg_status_result_interpret(status, LC_ALG_STATUS_FLAG_LIB) >
	    lc_alg_status_result_pending)
		return;

	/*
	 * This enables the library operation. Before this call, all algorithms
	 * are marked that all self tests failed causing all algorithms to
	 * be unavailable.
	 */
	alg_status_unset_test_state(0);
}
