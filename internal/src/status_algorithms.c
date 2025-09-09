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

typedef uint16_t alg_status_t;

#define ALG_CLEAR_ALL_BITS ATOMIC_INIT(0)
#define ALG_SET_ALL_BITS ATOMIC_INIT((int)0xffffffff)
#define ALG_SET_TEST_PASSED(flag) (lc_alg_status_result_passed << flag)

static atomic_t lc_alg_status_aead = ALG_SET_ALL_BITS;

/* Disable selftests */
#ifdef LC_KYBER_DEBUG
static atomic_t lc_alg_status_kem_pqc = ATOMIC_INIT(
	ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLKEM_KEYGEN) |
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
static atomic_t lc_alg_status_sig_pqc = ATOMIC_INIT(
	ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_MLDSA_KEYGEN) |
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

static atomic_t lc_alg_status_aux = ALG_SET_ALL_BITS;

struct alg_status_show {
	uint64_t flag;
	const char *alg_name;
	uint8_t strlen;
};

// clang-format off
static const struct alg_status_show alg_status_show_aead[] = {
#if (defined(LC_AES_GCM) || defined(CONFIG_LEANCRYPTO_AES_GCM))
{ .flag = LC_ALG_STATUS_AES_GCM, .alg_name = "AES-GCM", .strlen = 7 },
#endif
#if (defined(LC_CHACHA20_POLY1305) ||                                          \
     defined(CONFIG_LEANCRYPTO_CHACHA20_POLY1305))
{ .flag = LC_ALG_STATUS_CHACHA20_POLY1305, .alg_name = "ChaCha20-Poly1305", .strlen = 17 },
#endif
#if (defined(LC_ASCON_HASH) ||                                                 \
     (defined(CONFIG_LEANCRYPTO_ASCON_CRYPT) && defined(LC_ASCON)))
{ .flag = LC_ALG_STATUS_ASCON_AEAD_128, .alg_name = "Ascon-AEAD128", .strlen = 13 },
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
{ .flag = LC_ALG_STATUS_SYM_HMAC, .alg_name = "Sym-HMAC", .strlen = 8 },
#endif
#if (((defined(LC_AES_CBC) || defined(LC_aeS_CTR)) && defined(LC_KMAC)) ||     \
     defined(CONFIG_LEANCRYPTO_SYMKMAC_CRYPT))
{ .flag = LC_ALG_STATUS_SYM_KMAC, .alg_name = "Sym-KMAC", .strlen = 8 },
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
{ .flag = LC_ALG_STATUS_MLKEM_KEYGEN, .alg_name = "ML-KEM-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_MLKEM_ENC, .alg_name = "ML-KEM-Enc", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLKEM_DEC, .alg_name = "ML-KEM-Dec", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLKEM_ENC_KDF, .alg_name = "ML-KEM-Enc-KDF", .strlen = 14 },
{ .flag = LC_ALG_STATUS_MLKEM_DEC_KDF, .alg_name = "ML-KEM-Dec-KDF", .strlen = 14 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_kem_classic[] = {
#ifdef LC_CURVE25519
{ .flag = LC_ALG_STATUS_X25519_KEYKEN, .alg_name = "X25519-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_X25519_SS, .alg_name = "X25519-SS", .strlen = 9 },
#endif
#ifdef LC_CURVE448
{ .flag = LC_ALG_STATUS_X448_KEYKEN, .alg_name = "X448-Keygen", .strlen = 11 },
{ .flag = LC_ALG_STATUS_X448_SS, .alg_name = "X448-SS", .strlen = 7 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sig_pqc[] = {
#if (defined(LC_DILITHIUM) || defined(CONFIG_LEANCRYPTO_DILITHIUM))
{ .flag = LC_ALG_STATUS_MLDSA_KEYGEN, .alg_name = "ML-DSA-Keygen", .strlen = 13 },
{ .flag = LC_ALG_STATUS_MLDSA_SIGGEN, .alg_name = "ML-DSA-Enc", .strlen = 10 },
{ .flag = LC_ALG_STATUS_MLDSA_SIGVER, .alg_name = "ML-DSA-Dec", .strlen = 10 },
#endif
#if (defined(LC_SPHINCS) || defined(CONFIG_LEANCRYPTO_SPHINCS))
{ .flag = LC_ALG_STATUS_SLHDSA_KEYGEN, .alg_name = "SLH-DSA-Keyben", .strlen = 14 },
{ .flag = LC_ALG_STATUS_SLHDSA_SIGGEN, .alg_name = "SLH-DSA-Enc", .strlen = 11 },
{ .flag = LC_ALG_STATUS_SLHDSA_SIGVER, .alg_name = "SLH-DSA-Dec", .strlen = 11 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sig_classic[] = {
#if (defined(LC_DILITHIUM_ED25519) || defined(LC_CURVE25519))
{ .flag = LC_ALG_STATUS_ED25519_KEYGEN, .alg_name = "ED25519-Keygen", .strlen = 14 },
{ .flag = LC_ALG_STATUS_ED25519_SIGGEN, .alg_name = "ED25519-Enc", .strlen = 11 },
{ .flag = LC_ALG_STATUS_ED25519_SIGVER, .alg_name = "ED25519-Dec", .strlen = 11 },
#endif
#if (defined(LC_DILITHIUM_ED448) || defined(LC_CURVE448))
{ .flag = LC_ALG_STATUS_ED448_KEYGEN, .alg_name = "ED448-Keygen", .strlen = 12 },
{ .flag = LC_ALG_STATUS_ED448_SIGGEN, .alg_name = "ED448-Enc", .strlen = 9 },
{ .flag = LC_ALG_STATUS_ED448_SIGVER, .alg_name = "ED448-Dec", .strlen = 9 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_rng[] = {
#if (defined(LC_DRNG_XDRBG256) ||                                              \
     (defined(CONFIG_LEANCRYPTO_XDRBG_DRNG) && defined(CONFIG_LEANCRYPTO_SHA3)))
{ .flag = LC_ALG_STATUS_XDRBG256, .alg_name = "XDRBG256", .strlen = 8 },
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
{ .flag = LC_ALG_STATUS_HASH_DRBG, .alg_name = "Hash-DRBG", .strlen = 9 },
#endif
#if (defined(LC_DRNG_HMAC_DRBG) || defined(CONFIG_LEANCRYPTO_HMAC_DRBG))
{ .flag = LC_ALG_STATUS_HMAC_DRBG, .alg_name = "HMAC-DRBG", .strlen = 9 },
#endif
#if (defined(LC_DRNG_KMAC) || defined(CONFIG_LEANCRYPTO_KMAC_DRNG))
{ .flag = LC_ALG_STATUS_KMAC_DRBG, .alg_name = "KMAC-DRBG", .strlen = 9 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_digest[] = {
#if (defined(LC_ASCON_HASH) || defined(CONFIG_LEANCRYPTO_ASCON_HASH))
{ .flag = LC_ALG_STATUS_ASCON256, .alg_name = "Ascon256", .strlen = 8 },
{ .flag = LC_ALG_STATUS_ASCONXOF, .alg_name = "AsconXOF", .strlen = 8 },
{ .flag = LC_ALG_STATUS_ASCONCXOF, .alg_name = "AsconCXOF", .strlen = 9 },
#endif
#if (defined(LC_SHA2_256) || defined(CONFIG_LEANCRYPTO_SHA2_256))
{ .flag = LC_ALG_STATUS_SHA256, .alg_name = "SHA-256", .strlen = 7 },
#endif
#if (defined(LC_SHA2_512) || defined(CONFIG_LEANCRYPTO_SHA2_512))
{ .flag = LC_ALG_STATUS_SHA512, .alg_name = "SHA-512", .strlen = 7 },
#endif
#ifdef LC_SHA3
{ .flag = LC_ALG_STATUS_SHA3, .alg_name = "SHA-3", .strlen = 5 },
{ .flag = LC_ALG_STATUS_SHAKE, .alg_name = "SHAKE", .strlen = 5 },
{ .flag = LC_ALG_STATUS_CSHAKE, .alg_name = "cSHAKE", .strlen = 6 },
#endif
#if (defined(LC_KMAC) || defined(CONFIG_LEANCRYPTO_KMAC))
{ .flag = LC_ALG_STATUS_KMAC, .alg_name = "KMAC", .strlen = 4 },
#endif
#if (defined(LC_HMAC) || defined(CONFIG_LEANCRYPTO_HMAC))
{ .flag = LC_ALG_STATUS_HMAC, .alg_name = "HMAC", .strlen = 4 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_sym[] = {
#if (defined(LC_AES_CBC) || defined(CONFIG_LEANCRYPTO_AES_CBC))
{ .flag = LC_ALG_STATUS_AES_CBC, .alg_name = "AES-CBC", .strlen = 7 },
#endif
#if (defined(LC_AES_CTR) || defined(CONFIG_LEANCRYPTO_AES_CTR))
{ .flag = LC_ALG_STATUS_AES_CTR, .alg_name = "AES-CTR", .strlen = 7 },
#endif
#if (defined(LC_AES_KW) || defined(CONFIG_LEANCRYPTO_AES_KW))
{ .flag = LC_ALG_STATUS_AES_KW, .alg_name = "AES-KW", .strlen = 6 },
#endif
#if (defined(LC_AES_XTS) || defined(CONFIG_LEANCRYPTO_AES_XTS))
{ .flag = LC_ALG_STATUS_AES_XTS, .alg_name = "AES-XTS", .strlen = 7 },
#endif
#if (defined(LC_CHACHA20) || defined(CONFIG_LEANCRYPTO_CHACHA20))
{ .flag = LC_ALG_STATUS_CHACHA20, .alg_name = "ChaCha20", .strlen = 8 },
#endif
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

static const struct alg_status_show alg_status_show_aux[] = {
#if (defined(LC_HKDF) || defined(CONFIG_LEANCRYPTO_HKDF))
{ .flag = LC_ALG_STATUS_HKDF, .alg_name = "HKDF", .strlen = 4 },
#endif
#if (defined(LC_KDF_CTR) || defined(DCONFIG_LEANCRYPTO_KDF_CTR))
{ .flag = LC_ALG_STATUS_CTR_KDF, .alg_name = "CTR-KDF", .strlen = 7 },
#endif
#if (defined(LC_KDF_DPI) || defined(DCONFIG_LEANCRYPTO_KDF_DPI))
{ .flag = LC_ALG_STATUS_DPI_KDF, .alg_name = "DPI-KDF", .strlen = 7 },
#endif
#if (defined(LC_KDF_FB) || defined(DCONFIG_LEANCRYPTO_KDF_FB))
{ .flag = LC_ALG_STATUS_FB_KDF, .alg_name = "FB-KDF", .strlen = 6 },
#endif
#if (defined(LC_DRNG_PBKDF2) || defined(CONFIG_LEANCRYPTO_PBKDF2))
{ .flag = LC_ALG_STATUS_PBKDF2, .alg_name = "PBKDF2", .strlen = 6 },
#endif
{ .flag = LC_ALG_STATUS_LIB, .alg_name = "Lib-Available", .strlen = 13 },
/* Make sure this array is never empty */
{ .flag = 0, .alg_name = NULL, .strlen = 0 }
};

// clang-format on

static void alg_status_unset_test_state(void)
{
	atomic_set(&lc_alg_status_aead, 0);

#ifndef LC_KYBER_DEBUG
	atomic_set(&lc_alg_status_kem_pqc, 0);
#endif

	atomic_set(&lc_alg_status_kem_classic, 0);

#ifndef LC_DILITHIUM_DEBUG
	atomic_set(&lc_alg_status_sig_pqc, 0);
#endif

	atomic_set(&lc_alg_status_sig_classic, 0);
	atomic_set(&lc_alg_status_rng, 0);
	atomic_set(&lc_alg_status_digest, 0);
	atomic_set(&lc_alg_status_sym, 0);

	/* At that point, automatically define the library to be online */
	atomic_set(&lc_alg_status_aux,
		   ALG_SET_TEST_PASSED(LC_ALG_STATUS_FLAG_LIB));
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

static void alg_status_set_testresult(
	enum lc_alg_status_result test_ret, alg_status_t alg, atomic_t *status)
{
	/*
	 * In FIPS mode, we enter the degraded mode of operation when a self
	 * test error is observed. This requires that all self tests of all
	 * other algorithms must be reperformed. As this should never happen,
	 * it is a small price to pay to cover this requirement.
	 */
	if (test_ret == lc_alg_status_result_failed && fips140_mode_enabled())
		alg_status_unset_test_state();

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
	atomic_or((int)(test_ret << alg), status);
}

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
	return (enum lc_alg_status_result)
		/* Read out the entire state variable */
		atomic_read(status)
			/* Downshift to the required flag */
			>> alg
			/* Eliminate the upper bits */
			& ((1 << LC_ALG_STATUS_FLAG_MASK_SIZE) - 1);
}

enum lc_alg_status_result alg_status_get_result(uint64_t flag)
{
	alg_status_t alg = flag &~ LC_ALG_STATUS_TYPE_MASK;

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
	alg_status_t alg = flag &~ LC_ALG_STATUS_TYPE_MASK;

	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AEAD) {
		alg_status_set_testresult(test_ret, alg, &lc_alg_status_aead);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		alg_status_set_testresult(test_ret, alg,
					  &lc_alg_status_kem_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		alg_status_set_testresult(test_ret, alg,
					  &lc_alg_status_kem_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		alg_status_set_testresult(test_ret, alg,
					  &lc_alg_status_sig_pqc);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		alg_status_set_testresult(test_ret, alg,
					  &lc_alg_status_sig_classic);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		alg_status_set_testresult(test_ret, alg, &lc_alg_status_rng);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		alg_status_set_testresult(test_ret, alg, &lc_alg_status_digest);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		alg_status_set_testresult(test_ret, alg, &lc_alg_status_sym);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		alg_status_set_testresult(test_ret, alg, &lc_alg_status_aux);
	}
}

void alg_status_unset_result(uint64_t flag)
{
	alg_status_t alg = flag &~ LC_ALG_STATUS_TYPE_MASK;

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

void alg_status_unset_result_all(void)
{
	alg_status_unset_test_state();
}

static void alg_status_one(const struct alg_status_show *alg_status_show_arr,
			   size_t array_size, uint64_t flag,
			   atomic_t *status,
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
		if ((alg_status_show->flag & flag) !=
		    alg_status_show->flag)
			continue;

		res = alg_status_result(status,
					(alg_status_t)(alg_status_show->flag &~
					LC_ALG_STATUS_TYPE_MASK));
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

void alg_status(uint64_t flag, char *test_completed, size_t test_completed_len,
		char *test_open, size_t test_open_len, char *errorbuf,
		size_t errorbuf_len)
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
			&lc_alg_status_aead,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_PQC) {
		alg_status_one(
			alg_status_show_kem_pqc,
			ARRAY_SIZE(alg_status_show_kem_pqc) - 1, flag,
			&lc_alg_status_kem_pqc,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_KEM_CLASSIC) {
		alg_status_one(
			alg_status_show_kem_classic,
			ARRAY_SIZE(alg_status_show_kem_classic) - 1, flag,
			&lc_alg_status_kem_classic,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_PQC) {
		alg_status_one(
			alg_status_show_sig_pqc,
			ARRAY_SIZE(alg_status_show_sig_pqc) - 1, flag,
			&lc_alg_status_sig_pqc,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SIG_CLASSIC) {
		alg_status_one(
			alg_status_show_sig_classic,
			ARRAY_SIZE(alg_status_show_sig_classic) - 1, flag,
			&lc_alg_status_sig_classic,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_RNG) {
		alg_status_one(
			alg_status_show_rng,
			ARRAY_SIZE(alg_status_show_rng) - 1, flag,
			&lc_alg_status_rng,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_DIGEST) {
		alg_status_one(
			alg_status_show_digest,
			ARRAY_SIZE(alg_status_show_digest) - 1, flag,
			&lc_alg_status_digest, &test_completed,
			&test_completed_len, &test_open, &test_open_len,
			&errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_SYM) {
		alg_status_one(
			alg_status_show_sym,
			ARRAY_SIZE(alg_status_show_sym) - 1, flag,
			&lc_alg_status_sym,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
	if ((flag & LC_ALG_STATUS_TYPE_MASK) & LC_ALG_STATUS_TYPE_AUX) {
		alg_status_one(
			alg_status_show_aux,
			ARRAY_SIZE(alg_status_show_aux) - 1, flag,
			&lc_alg_status_aux,
			&test_completed, &test_completed_len,
			&test_open, &test_open_len, &errorbuf, &errorbuf_len);
	}
}

LC_CONSTRUCTOR(lc_activate_library, LC_INIT_PRIO_LIBRARY)
{
	/*
	 * TODO remove once the FIPS integrity test is rearchitected, see
	 * the counterpart in fips_integrity_check
	 */
	if (lc_status_get_result(LC_ALG_STATUS_FLAG_LIB) >
	    lc_alg_status_result_ongoing)
		return;

	/*
	 * This enables the library operation. Before this call, all algorithms
	 * are marked that all self tests failed causing all algorithms to
	 * be unavailable.
	 */
	alg_status_unset_test_state();
}
