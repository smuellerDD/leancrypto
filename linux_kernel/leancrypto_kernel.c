// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>

#include "compare.h"
#include "kyber_type.h"
#include "lc_ed25519.h"
#include "lc_init.h"
#include "lc_status.h"
#include "kyber_internal.h"
#include "kyber_kem.h"
#include "seeded_rng.h"
#include "lc_x25519.h"
#include "x25519_scalarmult.h"
#include "x25519_scalarmult_c.h"

#include "leancrypto_kernel.h"

EXPORT_SYMBOL(lc_disable_selftest);
#ifdef LC_CURVE25519
EXPORT_SYMBOL(crypto_scalarmult_curve25519);
EXPORT_SYMBOL(crypto_scalarmult_curve25519_base);
EXPORT_SYMBOL(lc_x25519_keypair);
#endif /* LC_CURVE25519 */
#if (defined(LC_KYBER_X25519_KEM) || defined(LC_DILITHIUM_ED25519_SIG))
EXPORT_SYMBOL(crypto_scalarmult_curve25519_c);
#endif

static int __init leancrypto_init(void)
{
	int ret;

	ret = lc_init(0);
	if (ret)
		return ret;

	ret = lc_proc_status_show_init();
	if (ret)
		goto out;

	/* Register crypto algorithms */
	ret = lc_kernel_sha256_init();
	if (ret)
		goto free_proc;

	ret = lc_kernel_sha512_init();
	if (ret)
		goto free_sha256;

	ret = lc_kernel_sha3_init();
	if (ret)
		goto free_sha512;

	ret = lc_kernel_kmac256_init();
	if (ret)
		goto free_sha3;

	ret = lc_kernel_rng_init();
	if (ret)
		goto free_kmac;

	ret = lc_kernel_dilithium_init();
	if (ret)
		goto free_rng;

	ret = lc_kernel_dilithium_65_init();
	if (ret)
		goto free_dilithium;

	ret = lc_kernel_dilithium_44_init();
	if (ret)
		goto free_dilithium_65;

	ret = lc_kernel_dilithium_ed25519_init();
	if (ret)
		goto free_dilithium_44;

	ret = lc_kernel_dilithium_65_ed25519_init();
	if (ret)
		goto free_dilithium_ed25519;

	ret = lc_kernel_dilithium_44_ed25519_init();
	if (ret)
		goto free_dilithium_65_ed25519;

	ret = lc_kernel_dilithium_ed448_init();
	if (ret)
		goto free_dilithium_44_ed25519;

	ret = lc_kernel_dilithium_65_ed448_init();
	if (ret)
		goto free_dilithium_ed448;

	ret = lc_kernel_dilithium_44_ed448_init();
	if (ret)
		goto free_dilithium_65_ed448;

	ret = lc_kernel_kyber_init();
	if (ret)
		goto free_dilithium_44_ed448;

	ret = lc_kernel_kyber_768_init();
	if (ret)
		goto free_kyber;

	ret = lc_kernel_kyber_512_init();
	if (ret)
		goto free_kyber_768;

	ret = lc_kernel_kyber_x25519_init();
	if (ret)
		goto free_kyber_512;

	ret = lc_kernel_kyber_x25519_768_init();
	if (ret)
		goto free_kyber_x25519;

	ret = lc_kernel_kyber_x25519_512_init();
	if (ret)
		goto free_kyber_x25519_768;

	ret = lc_kernel_kyber_x448_init();
	if (ret)
		goto free_kyber_x25519_512;

	ret = lc_kernel_kyber_x448_768_init();
	if (ret)
		goto free_kyber_x448;

	ret = lc_kernel_kyber_x448_512_init();
	if (ret)
		goto free_kyber_x448_768;

	ret = lc_kernel_ascon_init();
	if (ret)
		goto free_kyber_x448_512;

	ret = lc_kernel_aead_ascon_init();
	if (ret)
		goto free_ascon;

	ret = lc_kernel_aes_gcm_init();
	if (ret)
		goto free_aead_ascon;

	ret = lc_kernel_bike_init();
	if (ret)
		goto free_aes_gcm;

	ret = lc_kernel_bike_3_init();
	if (ret)
		goto free_bike5;

	ret = lc_kernel_bike_1_init();
	if (ret)
		goto free_bike3;

	ret = lc_kernel_sphincs_init();
	if (ret)
		goto free_bike1;

	ret = lc_kernel_sphincs_shake_256f_init();
	if (ret)
		goto free_sphincs_shake_256s;

	ret = lc_kernel_sphincs_shake_192s_init();
	if (ret)
		goto free_sphincs_shake_256f;

	ret = lc_kernel_sphincs_shake_192f_init();
	if (ret)
		goto free_sphincs_shake_192s;

	ret = lc_kernel_sphincs_shake_128s_init();
	if (ret)
		goto free_sphincs_shake_192f;

	ret = lc_kernel_sphincs_shake_128f_init();
	if (ret)
		goto free_sphincs_shake_128s;

	ret = lc_kernel_hqc_init();
	if (ret)
		goto free_sphincs_shake_128f;

	ret = lc_kernel_hqc_192_init();
	if (ret)
		goto free_hqc_256;

	ret = lc_kernel_hqc_128_init();
	if (ret)
		goto free_hqc_192;

	ret = lc_kernel_aes_xts_init();
	if (ret)
		goto free_hqc_128;

	ret = lc_kernel_aes_cbc_init();
	if (ret)
		goto free_aes_xts;

	ret = lc_kernel_aes_ctr_init();
	if (ret)
		goto free_aes_cbc;

out:
	return ret;

free_aes_cbc:
	lc_kernel_aes_cbc_exit();

free_aes_xts:
	lc_kernel_aes_xts_exit();

free_hqc_128:
	lc_kernel_hqc_128_exit();

free_hqc_192:
	lc_kernel_hqc_192_exit();

free_hqc_256:
	lc_kernel_hqc_exit();

free_sphincs_shake_128f:
	lc_kernel_sphincs_shake_128f_exit();

free_sphincs_shake_128s:
	lc_kernel_sphincs_shake_128s_exit();

free_sphincs_shake_192f:
	lc_kernel_sphincs_shake_192f_exit();

free_sphincs_shake_192s:
	lc_kernel_sphincs_shake_192s_exit();

free_sphincs_shake_256f:
	lc_kernel_sphincs_shake_256f_exit();

free_sphincs_shake_256s:
	lc_kernel_sphincs_exit();

free_bike1:
	lc_kernel_bike_1_exit();

free_bike3:
	lc_kernel_bike_3_exit();

free_bike5:
	lc_kernel_bike_exit();

free_aes_gcm:
	lc_kernel_aes_gcm_exit();

free_aead_ascon:
	lc_kernel_aead_ascon_exit();

free_ascon:
	lc_kernel_ascon_exit();

free_kyber_x448_512:
	lc_kernel_kyber_x448_512_exit();

free_kyber_x448_768:
	lc_kernel_kyber_x448_768_exit();

free_kyber_x448:
	lc_kernel_kyber_x448_exit();

free_kyber_x25519_512:
	lc_kernel_kyber_x25519_512_exit();

free_kyber_x25519_768:
	lc_kernel_kyber_x25519_768_exit();

free_kyber_x25519:
	lc_kernel_kyber_x25519_exit();

free_kyber_512:
	lc_kernel_kyber_512_exit();

free_kyber_768:
	lc_kernel_kyber_768_exit();

free_kyber:
	lc_kernel_kyber_exit();

free_dilithium_44_ed448:
	lc_kernel_dilithium_44_ed448_exit();

free_dilithium_65_ed448:
	lc_kernel_dilithium_65_ed448_exit();

free_dilithium_ed448:
	lc_kernel_dilithium_ed448_exit();

free_dilithium_44_ed25519:
	lc_kernel_dilithium_44_ed25519_exit();

free_dilithium_65_ed25519:
	lc_kernel_dilithium_65_ed25519_exit();

free_dilithium_ed25519:
	lc_kernel_dilithium_ed25519_exit();

free_dilithium_44:
	lc_kernel_dilithium_44_exit();

free_dilithium_65:
	lc_kernel_dilithium_65_exit();

free_dilithium:
	lc_kernel_dilithium_exit();

free_rng:
	lc_kernel_rng_exit();

free_kmac:
	lc_kernel_kmac256_exit();

free_sha3:
	lc_kernel_sha3_exit();

free_sha512:
	lc_kernel_sha512_exit();

free_sha256:
	lc_kernel_sha256_exit();

free_proc:
	lc_proc_status_show_exit();

	goto out;
}

static void __exit leancrypto_exit(void)
{
	lc_seeded_rng_zero_state();

	lc_kernel_sha256_exit();
	lc_kernel_sha512_exit();
	lc_kernel_sha3_exit();
	lc_kernel_kmac256_exit();
	lc_kernel_rng_exit();
	lc_kernel_dilithium_exit();
	lc_kernel_dilithium_65_exit();
	lc_kernel_dilithium_44_exit();
	lc_kernel_dilithium_ed25519_exit();
	lc_kernel_dilithium_65_ed25519_exit();
	lc_kernel_dilithium_44_ed25519_exit();
	lc_kernel_dilithium_ed448_exit();
	lc_kernel_dilithium_65_ed448_exit();
	lc_kernel_dilithium_44_ed448_exit();
	lc_kernel_kyber_exit();
	lc_kernel_kyber_768_exit();
	lc_kernel_kyber_512_exit();
	lc_kernel_kyber_x25519_exit();
	lc_kernel_kyber_x25519_768_exit();
	lc_kernel_kyber_x25519_512_exit();
	lc_kernel_kyber_x448_exit();
	lc_kernel_kyber_x448_768_exit();
	lc_kernel_kyber_x448_512_exit();
	lc_kernel_aead_ascon_exit();
	lc_kernel_ascon_exit();
	lc_kernel_aes_gcm_exit();
	lc_kernel_bike_exit();
	lc_kernel_bike_3_exit();
	lc_kernel_bike_1_exit();
	lc_kernel_sphincs_exit();
	lc_kernel_sphincs_shake_256f_exit();
	lc_kernel_sphincs_shake_192s_exit();
	lc_kernel_sphincs_shake_192f_exit();
	lc_kernel_sphincs_shake_128s_exit();
	lc_kernel_sphincs_shake_128f_exit();
	lc_kernel_hqc_exit();
	lc_kernel_hqc_192_exit();
	lc_kernel_hqc_128_exit();
	lc_kernel_aes_xts_exit();
	lc_kernel_aes_cbc_exit();
	lc_kernel_aes_ctr_exit();

	lc_proc_status_show_exit();
}

module_init(leancrypto_init);
module_exit(leancrypto_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto");
