/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LEANCRYPTO_KERNEL_H
#define LEANCRYPTO_KERNEL_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LC_KERNEL_DEFAULT_PRIO 5000

/*
 * kzfree was renamed to kfree_sensitive in 5.9
 */
#undef free_zero
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define free_zero(x) kfree_sensitive(x)
#else
#define free_zero(x) kzfree(x)
#endif

int __init lc_proc_status_show_init(void);
void lc_proc_status_show_exit(void);

#ifdef CONFIG_LEANCRYPTO_SHA2_256
int __init lc_kernel_sha256_init(void);
void lc_kernel_sha256_exit(void);
#else
static inline int __init lc_kernel_sha256_init(void)
{
	return 0;
}

static inline void lc_kernel_sha256_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SHA2_512
int __init lc_kernel_sha512_init(void);
void lc_kernel_sha512_exit(void);
#else
static inline int __init lc_kernel_sha512_init(void)
{
	return 0;
}

static inline void lc_kernel_sha512_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SHA3
int __init lc_kernel_sha3_init(void);
void lc_kernel_sha3_exit(void);
#else
static inline int __init lc_kernel_sha3_init(void)
{
	return 0;
}

static inline void lc_kernel_sha3_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KMAC
int __init lc_kernel_kmac256_init(void);
void lc_kernel_kmac256_exit(void);
#else
static inline int __init lc_kernel_kmac256_init(void)
{
	return 0;
}

static inline void lc_kernel_kmac256_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_XDRBG_DRNG
int __init lc_kernel_rng_init(void);
void lc_kernel_rng_exit(void);
#else
static inline int __init lc_kernel_rng_init(void)
{
	return 0;
}

static inline void lc_kernel_rng_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_DILITHIUM_87
int __init lc_kernel_dilithium_init(void);
void lc_kernel_dilithium_exit(void);
#else
static inline int __init lc_kernel_dilithium_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_DILITHIUM_65
int __init lc_kernel_dilithium_65_init(void);
void lc_kernel_dilithium_65_exit(void);
#else
static inline int __init lc_kernel_dilithium_65_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_65_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_DILITHIUM_44
int __init lc_kernel_dilithium_44_init(void);
void lc_kernel_dilithium_44_exit(void);
#else
static inline int __init lc_kernel_dilithium_44_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_44_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_87) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED25519)
int __init lc_kernel_dilithium_ed25519_init(void);
void lc_kernel_dilithium_ed25519_exit(void);
#else
static inline int __init lc_kernel_dilithium_ed25519_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_ed25519_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_65) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED25519)
int __init lc_kernel_dilithium_65_ed25519_init(void);
void lc_kernel_dilithium_65_ed25519_exit(void);
#else
static inline int __init lc_kernel_dilithium_65_ed25519_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_65_ed25519_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_44) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED25519)
int __init lc_kernel_dilithium_44_ed25519_init(void);
void lc_kernel_dilithium_44_ed25519_exit(void);
#else
static inline int __init lc_kernel_dilithium_44_ed25519_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_44_ed25519_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_87) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED448)
int __init lc_kernel_dilithium_ed448_init(void);
void lc_kernel_dilithium_ed448_exit(void);
#else
static inline int __init lc_kernel_dilithium_ed448_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_ed448_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_65) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED448)
int __init lc_kernel_dilithium_65_ed448_init(void);
void lc_kernel_dilithium_65_ed448_exit(void);
#else
static inline int __init lc_kernel_dilithium_65_ed448_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_65_ed448_exit(void)
{
}
#endif

#if defined(CONFIG_LEANCRYPTO_DILITHIUM_44) &&                                 \
	defined(CONFIG_LEANCRYPTO_DILITHIUM_ED448)
int __init lc_kernel_dilithium_44_ed448_init(void);
void lc_kernel_dilithium_44_ed448_exit(void);
#else
static inline int __init lc_kernel_dilithium_44_ed448_init(void)
{
	return 0;
}

static inline void lc_kernel_dilithium_44_ed448_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_KYBER_1024
int __init lc_kernel_kyber_init(void);
void lc_kernel_kyber_exit(void);
#else
static inline int __init lc_kernel_kyber_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_KYBER_768
int __init lc_kernel_kyber_768_init(void);
void lc_kernel_kyber_768_exit(void);
#else
static inline int __init lc_kernel_kyber_768_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_768_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_KYBER_512
int __init lc_kernel_kyber_512_init(void);
void lc_kernel_kyber_512_exit(void);
#else
static inline int __init lc_kernel_kyber_512_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_512_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X25519) &&                                  \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_1024))
int __init lc_kernel_kyber_x25519_init(void);
void lc_kernel_kyber_x25519_exit(void);
#else
static inline int __init lc_kernel_kyber_x25519_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x25519_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X25519) &&                                  \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_768))
int __init lc_kernel_kyber_x25519_768_init(void);
void lc_kernel_kyber_x25519_768_exit(void);
#else
static inline int __init lc_kernel_kyber_x25519_768_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x25519_768_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X25519) &&                                  \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_512))
int __init lc_kernel_kyber_x25519_512_init(void);
void lc_kernel_kyber_x25519_512_exit(void);
#else
static inline int __init lc_kernel_kyber_x25519_512_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x25519_512_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X448) &&                                    \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_1024))
int __init lc_kernel_kyber_x448_init(void);
void lc_kernel_kyber_x448_exit(void);
#else
static inline int __init lc_kernel_kyber_x448_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x448_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X448) &&                                    \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_768))
int __init lc_kernel_kyber_x448_768_init(void);
void lc_kernel_kyber_x448_768_exit(void);
#else
static inline int __init lc_kernel_kyber_x448_768_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x448_768_exit(void)
{
}
#endif

#if (defined(CONFIG_LEANCRYPTO_KEM_X448) &&                                    \
     defined(CONFIG_LEANCRYPTO_KEM_KYBER_512))
int __init lc_kernel_kyber_x448_512_init(void);
void lc_kernel_kyber_x448_512_exit(void);
#else
static inline int __init lc_kernel_kyber_x448_512_init(void)
{
	return 0;
}

static inline void lc_kernel_kyber_x448_512_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_ASCON_HASH
int __init lc_kernel_ascon_init(void);
void lc_kernel_ascon_exit(void);
#else
static inline int __init lc_kernel_ascon_init(void)
{
	return 0;
}

static inline void lc_kernel_ascon_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_ASCON_CRYPT
int __init lc_kernel_aead_ascon_init(void);
void lc_kernel_aead_ascon_exit(void);
#else
static inline int __init lc_kernel_aead_ascon_init(void)
{
	return 0;
}

static inline void lc_kernel_aead_ascon_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_AES_GCM
int __init lc_kernel_aes_gcm_init(void);
void lc_kernel_aes_gcm_exit(void);
#else
static inline int __init lc_kernel_aes_gcm_init(void)
{
	return 0;
}

static inline void lc_kernel_aes_gcm_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_BIKE_5
int __init lc_kernel_bike_init(void);
void lc_kernel_bike_exit(void);
#else
static inline int __init lc_kernel_bike_init(void)
{
	return 0;
}

static inline void lc_kernel_bike_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_BIKE_3
int __init lc_kernel_bike_3_init(void);
void lc_kernel_bike_3_exit(void);
#else
static inline int __init lc_kernel_bike_3_init(void)
{
	return 0;
}

static inline void lc_kernel_bike_3_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_BIKE_1
int __init lc_kernel_bike_1_init(void);
void lc_kernel_bike_1_exit(void);
#else
static inline int __init lc_kernel_bike_1_init(void)
{
	return 0;
}

static inline void lc_kernel_bike_1_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_256s
int __init lc_kernel_sphincs_init(void);
void lc_kernel_sphincs_exit(void);
#else
static inline int __init lc_kernel_sphincs_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_256f
int __init lc_kernel_sphincs_shake_256f_init(void);
void lc_kernel_sphincs_shake_256f_exit(void);
#else
static inline int __init lc_kernel_sphincs_shake_256f_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_shake_256f_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_192s
int __init lc_kernel_sphincs_shake_192s_init(void);
void lc_kernel_sphincs_shake_192s_exit(void);
#else
static inline int __init lc_kernel_sphincs_shake_192s_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_shake_192s_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_192f
int __init lc_kernel_sphincs_shake_192f_init(void);
void lc_kernel_sphincs_shake_192f_exit(void);
#else
static inline int __init lc_kernel_sphincs_shake_192f_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_shake_192f_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_128s
int __init lc_kernel_sphincs_shake_128s_init(void);
void lc_kernel_sphincs_shake_128s_exit(void);
#else
static inline int __init lc_kernel_sphincs_shake_128s_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_shake_128s_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_SPHINCS_128f
int __init lc_kernel_sphincs_shake_128f_init(void);
void lc_kernel_sphincs_shake_128f_exit(void);
#else
static inline int __init lc_kernel_sphincs_shake_128f_init(void)
{
	return 0;
}

static inline void lc_kernel_sphincs_shake_128f_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_HQC_256
int __init lc_kernel_hqc_init(void);
void lc_kernel_hqc_exit(void);
#else
static inline int __init lc_kernel_hqc_init(void)
{
	return 0;
}

static inline void lc_kernel_hqc_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_HQC_192
int __init lc_kernel_hqc_192_init(void);
void lc_kernel_hqc_192_exit(void);
#else
static inline int __init lc_kernel_hqc_192_init(void)
{
	return 0;
}

static inline void lc_kernel_hqc_192_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_KEM_HQC_128
int __init lc_kernel_hqc_128_init(void);
void lc_kernel_hqc_128_exit(void);
#else
static inline int __init lc_kernel_hqc_128_init(void)
{
	return 0;
}

static inline void lc_kernel_hqc_128_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_AES_XTS
int __init lc_kernel_aes_xts_init(void);
void lc_kernel_aes_xts_exit(void);
#else
static inline int __init lc_kernel_aes_xts_init(void)
{
	return 0;
}

static inline void lc_kernel_aes_xts_exit(void)
{
}
#endif

#ifdef CONFIG_LEANCRYPTO_AES_CBC
int __init lc_kernel_aes_cbc_init(void);
void lc_kernel_aes_cbc_exit(void);
#else
static inline int __init lc_kernel_aes_cbc_init(void)
{
	return 0;
}

static inline void lc_kernel_aes_cbc_exit(void)
{
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* LEANCRYPTO_KERNEL_H */
