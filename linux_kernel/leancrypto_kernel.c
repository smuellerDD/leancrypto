// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "ed25519.h"
#include "kyber_internal.h"
#include "kyber_kem.h"
#include "lc_kyber.h"
#include "seeded_rng.h"
#include "x25519.h"
#include "x25519_scalarmult.h"
#include "x25519_scalarmult_c.h"

#include "leancrypto_kernel.h"

/* Export these symbols for testing */
EXPORT_SYMBOL(_lc_kyber_keypair);
EXPORT_SYMBOL(_lc_kyber_enc);
EXPORT_SYMBOL(_lc_kyber_dec);
EXPORT_SYMBOL(lc_kyber_enc_internal);
EXPORT_SYMBOL(lc_kyber_enc_kdf_internal);
EXPORT_SYMBOL(lc_kex_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_uake_responder_ss_internal);
EXPORT_SYMBOL(lc_kyber_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_ies_enc_init_internal);
EXPORT_SYMBOL(lc_disable_selftest);
#ifdef LC_KYBER_X25519_KEM
EXPORT_SYMBOL(lc_kyber_x25519_enc_kdf_internal);
EXPORT_SYMBOL(lc_kyber_x25519_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_x25519_ies_enc_init_internal);
EXPORT_SYMBOL(crypto_scalarmult_curve25519);
EXPORT_SYMBOL(crypto_scalarmult_curve25519_base);
EXPORT_SYMBOL(lc_x25519_keypair);
EXPORT_SYMBOL(lc_kex_x25519_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_x25519_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_x25519_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_x25519_uake_responder_ss_internal);
#endif /* LC_KYBER_X25519_KEM */
#if (defined(LC_KYBER_X25519_KEM) || defined(LC_DILITHIUM_ED25519_SIG))
EXPORT_SYMBOL(crypto_scalarmult_curve25519_c);
#endif

void sha3_fastest_impl(void);
void aes_fastest_impl(void);
static int __init leancrypto_init(void)
{
	int ret;

	sha3_fastest_impl();
	aes_fastest_impl();

	/* Register crypto algorithms */
	ret = lc_kernel_sha3_init();
	if (ret)
		goto out;

	ret = lc_kernel_kmac256_init();
	if (ret)
		goto free_sha3;

	ret = lc_kernel_rng_init();
	if (ret)
		goto free_kmac;

	ret = lc_kernel_dilithium_init();
	if (ret)
		goto free_rng;

	ret = lc_kernel_dilithium_ed25519_init();
	if (ret)
		goto free_dilithium;

	ret = lc_kernel_kyber_init();
	if (ret)
		goto free_dilithium_ed25519;

	ret = lc_kernel_kyber_x25519_init();
	if (ret)
		goto free_kyber;

out:
	return ret;

free_kyber:
	lc_kernel_kyber_exit();

free_dilithium_ed25519:
	lc_kernel_dilithium_ed25519_exit();

free_dilithium:
	lc_kernel_dilithium_exit();

free_rng:
	lc_kernel_rng_exit();

free_kmac:
	lc_kernel_kmac256_exit();

free_sha3:
	lc_kernel_sha3_exit();

	goto out;
}

static void __exit leancrypto_exit(void)
{
	lc_seeded_rng_zero_state();

	lc_kernel_sha3_exit();
	lc_kernel_kmac256_exit();
	lc_kernel_rng_exit();
	lc_kernel_dilithium_exit();
	lc_kernel_dilithium_ed25519_exit();
	lc_kernel_kyber_exit();
	lc_kernel_kyber_x25519_exit();
}

module_init(leancrypto_init);
module_exit(leancrypto_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto");
