/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

/*
 * Every AES implementation and mode must refuse encryption and decryption
 * with -ENOKEY when no key is set: never set, rejected by setkey, or
 * cleared by lc_sym_zero.
 */

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "ret_checkers.h"
#include "test_helper_common.h"
#include "visibility.h"

#ifdef LC_AES_GCM
#include "lc_aes_gcm.h"
#endif

static const uint8_t key[32] = { 0x01, 0x02, 0x03 };
static const uint8_t key_xts[64] = { 0x01, [32] = 0x02 };
static const uint8_t bad_key[17] = { 0x01 };

static int expect_nokey(const char *impl, const char *what, int ret)
{
	if (ret == -ENOKEY)
		return 0;
	printf("%s: %s returned %d, expected -ENOKEY\n", impl, what, ret);
	return 1;
}

static int test_one(const struct lc_sym *aes, const char *name, int is_kw,
		    int is_xts)
{
	/* KW input is a multiple of the 8-byte semiblock, at least 16 bytes */
	uint8_t in[32] = { 0 }, out[40];
	const uint8_t *k = is_xts ? key_xts : key;
	size_t klen = is_xts ? sizeof(key_xts) : sizeof(key);
	int ret = 0;
	LC_SYM_CTX_ON_STACK(ctx, aes);

	/* Never keyed */
	if (lc_sym_init(ctx))
		return 1;
	ret += expect_nokey(name, "encrypt, no key",
			    lc_sym_encrypt(ctx, in, out, 16));
	ret += expect_nokey(name, "decrypt, no key",
			    lc_sym_decrypt(ctx, in, out, 16));
	if (is_kw) {
		ret += expect_nokey(name, "lc_aes_kw_encrypt, no key",
				    lc_aes_kw_encrypt(ctx, in, out, 16));
		ret += expect_nokey(name, "lc_aes_kw_decrypt, no key",
				    lc_aes_kw_decrypt(ctx, in, out, 24));
	}

	/* setkey rejected (invalid length): still no key */
	if (!lc_sym_setkey(ctx, bad_key, sizeof(bad_key))) {
		printf("%s: setkey accepted a 17-byte key\n", name);
		ret++;
	}
	ret += expect_nokey(name, "encrypt after rejected setkey",
			    lc_sym_encrypt(ctx, in, out, 16));

	/* Keyed, then cleared */
	if (lc_sym_setkey(ctx, k, klen)) {
		printf("%s: setkey failed\n", name);
		return ret + 1;
	}
	if (lc_sym_encrypt(ctx, in, out, 16)) {
		printf("%s: encrypt with key failed\n", name);
		ret++;
	}
	lc_sym_zero(ctx);
	ret += expect_nokey(name, "encrypt after lc_sym_zero",
			    lc_sym_encrypt(ctx, in, out, 16));

	lc_sym_zero(ctx);
	return ret;
}

#define LC_EXEC_ONE_TEST(aes_impl, is_kw, is_xts)                              \
	if (aes_impl)                                                          \
	ret += test_one(aes_impl, #aes_impl, is_kw, is_xts)

#ifdef LC_AES_GCM
static int test_gcm(void)
{
	static const uint8_t aad[16] = { 0x01 };
	uint8_t in[16] = { 0 }, out[16], tag[16] = { 0 };
	int ret = 0;
	LC_AES_GCM_CTX_ON_STACK(gcm);

	ret += expect_nokey("AES-GCM", "encrypt, no key",
			    lc_aead_encrypt(gcm, in, out, sizeof(in), aad,
					    sizeof(aad), tag, sizeof(tag)));
	/* AAD only (GMAC): never reaches the cipher */
	ret += expect_nokey("AES-GCM", "AAD-only encrypt, no key",
			    lc_aead_encrypt(gcm, NULL, NULL, 0, aad,
					    sizeof(aad), tag, sizeof(tag)));
	ret += expect_nokey("AES-GCM", "decrypt, no key",
			    lc_aead_decrypt(gcm, in, out, sizeof(in), aad,
					    sizeof(aad), tag, sizeof(tag)));

	lc_aead_zero(gcm);
	return ret;
}
#endif

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	LC_EXEC_ONE_TEST(lc_aes, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_c, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_sbox, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_ct, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_aesni, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_armce, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_riscv64, 0, 0);
#ifdef LC_TEST_AES_ECB
	LC_EXEC_ONE_TEST(lc_aes_ecb, 0, 0);
#endif

#ifdef LC_AES_CBC
	LC_EXEC_ONE_TEST(lc_aes_cbc, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_cbc_c, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_cbc_aesni, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_cbc_armce, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_cbc_riscv64, 0, 0);
#endif

#ifdef LC_AES_CTR
	LC_EXEC_ONE_TEST(lc_aes_ctr, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_ctr_c, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_ctr_aesni, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_ctr_armce, 0, 0);
	LC_EXEC_ONE_TEST(lc_aes_ctr_riscv64, 0, 0);
#endif

#ifdef LC_AES_KW
	LC_EXEC_ONE_TEST(lc_aes_kw, 1, 0);
	LC_EXEC_ONE_TEST(lc_aes_kw_c, 1, 0);
	LC_EXEC_ONE_TEST(lc_aes_kw_aesni, 1, 0);
	LC_EXEC_ONE_TEST(lc_aes_kw_armce, 1, 0);
	LC_EXEC_ONE_TEST(lc_aes_kw_riscv64, 1, 0);
#endif

#ifdef LC_AES_XTS
	LC_EXEC_ONE_TEST(lc_aes_xts, 0, 1);
	LC_EXEC_ONE_TEST(lc_aes_xts_c, 0, 1);
	LC_EXEC_ONE_TEST(lc_aes_xts_aesni, 0, 1);
	LC_EXEC_ONE_TEST(lc_aes_xts_armce, 0, 1);
	LC_EXEC_ONE_TEST(lc_aes_xts_riscv64, 0, 1);
#endif

#ifdef LC_AES_GCM
	ret += test_gcm();
#endif

	return ret;
}
