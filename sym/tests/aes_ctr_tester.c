/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/kokke/tiny-AES-c
 *
 * This is free and unencumbered software released into the public domain.
 */

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"
#include "aes_internal.h"
#include "lc_aes.h"
#include "mode_ctr.h"
#include "compare.h"
#include "ret_checkers.h"
#include "visibility.h"

#define LC_EXEC_ONE_TEST(aes_impl)                                             \
	if (aes_impl) {                                                        \
		ret += test_encrypt_ctr(aes_impl, #aes_impl);                  \
		ret += test_decrypt_ctr(aes_impl, #aes_impl);                  \
	}

static const uint8_t key256[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71,
				  0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
				  0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b,
				  0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
				  0x09, 0x14, 0xdf, 0xf4 };
static const uint8_t in256[] = {
	0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5,
	0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62,
	0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 0x2b,
	0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba,
	0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad,
	0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
};
static const uint8_t key192[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e,
				  0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
				  0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8,
				  0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
static const uint8_t in192[] = {
	0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04,
	0x59, 0xfe, 0x7e, 0x6e, 0x0b, 0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6,
	0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94, 0x1e,
	0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66,
	0x56, 0x20, 0xab, 0xf7, 0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09,
	0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50
};
static const uint8_t key128[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
				  0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
				  0x09, 0xcf, 0x4f, 0x3c };
static const uint8_t in128[] = {
	0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68,
	0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70,
	0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a,
	0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02,
	0x0d, 0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03,
	0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
};

static int test_xcrypt_ctr_one(const char *xcrypt, struct lc_sym_ctx *ctx,
			       const uint8_t *key, size_t keylen, uint8_t *in)
{
	static const uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
				      0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
				      0xfc, 0xfd, 0xfe, 0xff };
	static const uint8_t out[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
		0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
		0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
		0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
		0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
		0xe6, 0x6c, 0x37, 0x10
	};

	char status[64];
	int ret;

	snprintf(status, sizeof(status), "AES-CTR %s", xcrypt);

	/* Encrypt */
	lc_sym_init(ctx);
	CKINT(lc_sym_setkey(ctx, key, keylen));
	CKINT(lc_sym_setiv(ctx, iv, sizeof(iv)));
	lc_sym_encrypt(ctx, in, in, sizeof(out) - 1);
	ret = lc_compare(in, out, sizeof(out) - 1, status);

out:
	return ret;
}

static int test_xcrypt_ctr(const struct lc_sym *aes, const char *name,
			   const char *xcrypt)
{
	struct lc_sym_ctx *aes_ctr_heap;
	uint8_t in2[sizeof(in256)];
	int ret;
	LC_SYM_CTX_ON_STACK(aes_ctr, aes);

	printf("AES CTR ctx %s (%s implementation) len %lu\n", name,
	       aes == lc_aes_ctr_c ? "C" : "accelerated", LC_SYM_CTX_SIZE(aes));

	memcpy(in2, in256, sizeof(in256));
	ret = test_xcrypt_ctr_one(xcrypt, aes_ctr, key256, sizeof(key256), in2);
	lc_sym_zero(aes_ctr);

	memcpy(in2, in192, sizeof(in192));
	ret += test_xcrypt_ctr_one(xcrypt, aes_ctr, key192, sizeof(key192),
				   in2);
	lc_sym_zero(aes_ctr);

	memcpy(in2, in128, sizeof(in128));
	ret += test_xcrypt_ctr_one(xcrypt, aes_ctr, key128, sizeof(key128),
				   in2);
	lc_sym_zero(aes_ctr);

	if (lc_sym_alloc(aes, &aes_ctr_heap))
		return ret + 1;
	memcpy(in2, in256, sizeof(in256));
	ret += test_xcrypt_ctr_one(xcrypt, aes_ctr_heap, key256, sizeof(key256),
				   in2);
	lc_sym_zero_free(aes_ctr_heap);

	return ret;
}

static int test_encrypt_ctr(const struct lc_sym *aes, const char *name)
{
	return test_xcrypt_ctr(aes, name, "encrypt");
}

static int test_decrypt_ctr(const struct lc_sym *aes, const char *name)
{
	return test_xcrypt_ctr(aes, name, "decrypt");
}

static void ctr_inc(uint8_t *iv)
{
	int bi;

	/* Increment Iv and handle overflow */
	for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
		/* inc will overflow */
		if (iv[bi] == 255) {
			iv[bi] = 0;
			continue;
		}
		iv[bi] += 1;
		break;
	}
}

#include "../src/asm/AESNI_x86_64/aes_aesni_x86_64.h"
struct lc_sym_state_aesni {
	struct aes_aesni_block_ctx enc_block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#include "../src/asm/ARMv8/aes_armv8_ce.h"
struct lc_sym_state_armce {
	struct aes_aesni_block_ctx enc_block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

static int ctr_tester_one(uint8_t *iv, uint64_t *iv128)
{
	uint8_t buffer64[AES_BLOCKLEN] = { 0 };
	uint8_t data[AES_BLOCKLEN] = { 0 };
	uint8_t key[2 * AES_BLOCKLEN] = { 0 };
	unsigned int i;
	int ret = 0;
	LC_SYM_CTX_ON_STACK(aesni, lc_aes_ctr_aesni);
	LC_SYM_CTX_ON_STACK(aes_armce, lc_aes_ctr_armce);

	lc_sym_init(aesni);
	CKINT(lc_sym_setkey(aesni, key, sizeof(key)));
	CKINT(lc_sym_setiv(aesni, iv, AES_BLOCKLEN));

	lc_sym_init(aes_armce);
	CKINT(lc_sym_setkey(aes_armce, key, sizeof(key)));
	CKINT(lc_sym_setiv(aes_armce, iv, AES_BLOCKLEN));

	for (i = 0; i < 10; i++) {
		ctr_inc(iv);
		ctr128_inc(iv128);
		ctr128_to_ptr(buffer64, iv128);
		CKINT(lc_compare(buffer64, iv, AES_BLOCKLEN,
				 "CTR 64 maintenance"));

		/* Test counter management for AESNI implementation */
		if (lc_aes_ctr_aesni != lc_aes_ctr_c) {
			lc_sym_encrypt(aesni, data, data, sizeof(data));
			CKINT(lc_compare(
				buffer64,
				((struct lc_sym_state_aesni *)(aesni->sym_state))
					->iv,
				AES_BLOCKLEN, "CTR AESNI maintenance"));
		}

		/* Test counter management for ARM-CE implementation */
		if (lc_aes_ctr_armce != lc_aes_ctr_c) {
			lc_sym_encrypt(aes_armce, data, data, sizeof(data));
			CKINT(lc_compare(buffer64,
					 ((struct lc_sym_state_armce
						   *)(aes_armce->sym_state))
						 ->iv,
					 AES_BLOCKLEN,
					 "CTR ARM-CE maintenance"));
		}
	}

out:
	return ret;
}

static int ctr_tester(void)
{
	unsigned int i;
	uint8_t iv[AES_BLOCKLEN];
	uint64_t iv128[AES_CTR128_64BIT_WORDS];
	int ret;

	memset(iv, 0, sizeof(iv));
	memset(iv128, 0, sizeof(iv128));
	ret = ctr_tester_one(iv, iv128);

	memset(iv, 0, sizeof(iv));
	memset(iv128, 0, sizeof(iv128));
	for (i = AES_BLOCKLEN - 1; i >= AES_BLOCKLEN - sizeof(uint64_t); i--)
		iv[i] = 0xff;
	iv128[AES_CTR128_64BIT_WORDS - 1] = (uint64_t)-1;
	ret += ctr_tester_one(iv, iv128);

	memset(iv, 0, sizeof(iv));
	memset(iv128, 0, sizeof(iv128));
	for (i = AES_BLOCKLEN; i > 0; i--)
		iv[i - 1] = 0xff;
	for (i = AES_CTR128_64BIT_WORDS; i > 0; i--)
		iv128[i - 1] = (uint64_t)-1;
	ret += ctr_tester_one(iv, iv128);

	return ret;
}

static int test_ctr(void)
{
	int ret = 0;

	ret += ctr_tester();

	LC_EXEC_ONE_TEST(lc_aes_ctr);
	LC_EXEC_ONE_TEST(lc_aes_ctr_aesni);
	LC_EXEC_ONE_TEST(lc_aes_ctr_armce);
	LC_EXEC_ONE_TEST(lc_aes_ctr_c);
	LC_EXEC_ONE_TEST(lc_aes_ctr_riscv64);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return test_ctr();
}
