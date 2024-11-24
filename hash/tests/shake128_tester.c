/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "lc_cshake.h"
#include "lc_sha3.h"
#include "visibility.h"

#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_riscv_asm.h"

#define LC_EXEC_ONE_TEST(sha3_impl)                                            \
	if (sha3_impl)                                                         \
	ret += _shake_128_tester(sha3_impl, #sha3_impl)

static int _shake_128_tester(const struct lc_hash *shake_128, const char *name)
{
	static const uint8_t msg1[] = { 0xBE, 0x94, 0xD8, 0x3D, 0x37,
					0x66, 0xCF, 0x3E, 0xD3, 0x0A,
					0x11, 0x0C, 0x47, 0xA2 };
	static const uint8_t exp1[] = { 0xB0, 0x46, 0x01, 0xAA, 0x4D, 0x2C,
					0x30, 0xF6, 0x5F, 0x94, 0xD7, 0x02,
					0x5D, 0xBD, 0x22, 0x39 };
	uint8_t act1[sizeof(exp1)];
	static const uint8_t msg2[] = { 0xD7, 0x32, 0x8A, 0x5C, 0x57, 0xDB,
					0x97, 0xF3, 0x98, 0xC8, 0x4F, 0x68,
					0x2F, 0xE9, 0xCC, 0xA8 };
	static const uint8_t exp2[] = {
		0x02, 0x4B, 0x9D, 0x1B, 0x92, 0xEC, 0x6D, 0x85, 0x96, 0x58,
		0x31, 0x2F, 0xD3, 0xA7, 0xD8, 0x55, 0xDA, 0x88, 0x79, 0xC2,
		0x71, 0x47, 0xEE, 0xB4, 0xEF, 0x02, 0xE0, 0x51, 0x63, 0xB4,
		0x88, 0xC5, 0x49, 0x0A, 0x4B, 0x39, 0xAE, 0xBE, 0xB9, 0x61,
		0x94, 0x37, 0x48, 0xE4, 0x2E, 0xF8, 0x19, 0x6C, 0xD6, 0x15,
		0x17, 0xC1, 0x7C, 0x20, 0xF8, 0x24, 0xE1, 0x52, 0x8C, 0xFB,
		0x0E, 0x55, 0x3B, 0x04, 0xAB, 0x37, 0x73, 0x30, 0xA8, 0x0C,
		0x81, 0x97, 0xD8, 0xE1, 0xBF, 0x23, 0x29, 0x26, 0x66, 0xD2,
		0x36, 0xFF, 0x7E, 0xD3, 0xDD, 0xBA, 0x69, 0xBA, 0xEC, 0x05,
		0x09, 0x2E, 0x14, 0x1A, 0xF7, 0x9D, 0x8C, 0x91, 0xA5, 0xD2,
		0x9F, 0x59, 0x42, 0xBC, 0x8F, 0x8C, 0x80, 0xCE, 0x6A, 0xEA,
		0xAE, 0xDB, 0x69, 0x7A, 0x99, 0xCA, 0xCB, 0x63, 0xDA, 0xCE,
		0xFE, 0xD5, 0x5D, 0x07, 0x5D, 0x48, 0xFB, 0xEA, 0x0D, 0x95,
		0x87, 0x35, 0x5F, 0x5F, 0x25, 0x19, 0xF3, 0x74, 0xDA, 0xEE,
		0x63, 0x3F, 0xDE, 0xC6, 0xBE, 0xA1, 0x3D, 0xC4, 0xEA, 0x5C,
		0x92, 0x73, 0x12, 0x87, 0xB3, 0x0B, 0x29, 0x18, 0xD7, 0x2A,
		0xD6, 0xA4, 0x1D, 0xC8, 0x1F, 0x24, 0xC9, 0xA9, 0xCD, 0x4A,
		0xCB, 0xD2, 0x48, 0xD1, 0xD9, 0x44, 0xDE, 0x38, 0x98, 0x84,
		0xCE, 0x60, 0x1C, 0x50, 0x4D, 0x7F, 0x1F, 0x75, 0x72, 0x68,
		0x5F, 0x4A, 0x45, 0xA6, 0x98, 0xA2, 0x2C, 0x4D, 0x50, 0xB9,
		0x00, 0x99, 0x64, 0xF8, 0x75, 0x00, 0x03, 0x31, 0x4A, 0x47,
		0x30, 0xEA, 0x5D, 0x2E, 0x03, 0x0D, 0x16, 0x66, 0x9C, 0x44,
		0x6B, 0x72, 0x23, 0xEB, 0x34, 0xC5, 0xA1, 0xC3, 0x58, 0x7A,
		0xAA, 0xA3, 0xCE, 0x09, 0x87, 0x9D, 0x5E, 0xA6, 0xDE, 0x24,
		0xE5, 0x7F, 0xFB, 0x1B, 0x2E, 0x13, 0x88, 0xEC, 0x28, 0x81,
		0x1B, 0xAA, 0x69, 0x31, 0x68, 0x45, 0xED, 0xD4, 0x25, 0xA3,
		0x46, 0xF3, 0x58, 0x59, 0x8B, 0xFA, 0xC7, 0xF3, 0xF9, 0x4E,
		0x09, 0xC0, 0x83, 0x3C, 0xC6, 0xE8, 0x29, 0x9D, 0xC4, 0x97,
		0x55, 0xAC, 0x50, 0x9C, 0xC8, 0x11, 0xEE, 0x6F, 0x67, 0xD6,
		0xFE, 0x38, 0xC1, 0xFC, 0xC5, 0x9B, 0x78, 0x7E, 0xC0, 0x61,
		0xBE, 0x43, 0xB7, 0xFF, 0x3F, 0x8E, 0xF9, 0x98, 0x24, 0x78,
		0x52, 0x80, 0x83, 0xF7, 0x1C, 0x8A, 0x91, 0xB6, 0xC4, 0x5B,
		0xEB, 0x16, 0x6F, 0xB1, 0x8D, 0x7A, 0x7F, 0xDE, 0x72, 0x24,
		0xC0, 0x52, 0x7B, 0xB2, 0x8E, 0x2B, 0xAF, 0x67, 0x69, 0x43,
		0x73, 0x37, 0xD2, 0xB4, 0x02, 0xCA, 0x53, 0xCB, 0x51, 0x3C,
		0x7C, 0x5F, 0xCB, 0x99, 0xAB, 0x06, 0x2F, 0xEF, 0x7C, 0x57,
		0x4A, 0x04, 0xB2, 0x99, 0x89, 0xF0, 0x4B, 0x85, 0x63, 0x7A,
		0x31, 0x3C, 0x53, 0x89, 0xCB, 0x81, 0x63, 0xC7, 0xA1, 0x49,
		0xF7, 0x17, 0xB0, 0x82, 0x2F, 0x8A, 0x57, 0x9B, 0xDD, 0x23,
		0x1A, 0x0D, 0x8F, 0xC7, 0x1B, 0x45, 0x37, 0x08, 0x30, 0x32,
		0x37, 0xC4, 0x21, 0x39, 0xD5, 0xA7, 0xA8, 0xF1, 0x0A, 0x1E,
		0x0D, 0x8C, 0x9C, 0x00, 0xA9, 0xBC, 0x15, 0x8E, 0x96, 0xA0,
		0xAB, 0xAE, 0xA4, 0x13, 0x64, 0x80, 0x6D, 0x3F, 0xB5, 0x5D,
		0x97, 0x41, 0x2A, 0x09, 0xFE, 0xD4, 0xF1, 0xE5, 0x16, 0xCE,
		0x6E, 0xBC, 0x8E, 0xCB, 0x8E, 0x45, 0xE9, 0x91, 0xED, 0x66,
		0xA3, 0x9D, 0xB9, 0xD4, 0x0B, 0xEA, 0x1A, 0xE7, 0xA3, 0x82,
		0xAC, 0xAD, 0xD0, 0xE2, 0xCE, 0x93, 0x68, 0xC6, 0x53, 0x60,
		0x80, 0x3E, 0xE4, 0xA1, 0xE5, 0x90, 0xFF, 0x5A, 0xE9, 0x1B,
		0xB6, 0xD9, 0x31, 0xA5, 0xEA, 0x3E, 0xF1, 0x56, 0xF3, 0x0B,
		0x64, 0x7A, 0x57, 0xE6, 0x1C, 0xAE, 0xE9, 0xBB, 0x90, 0xB0,
		0xD0, 0x1F, 0x78, 0x8C
	};
	uint8_t act2[sizeof(exp2)];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx, shake_128);
	LC_SHAKE_128_CTX_ON_STACK(shake128_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       shake_128 == lc_shake128_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE(shake_128));

	lc_hash_init(ctx);
	lc_hash_update(ctx, msg1, sizeof(msg1));
	lc_hash_set_digestsize(ctx, sizeof(act1));
	lc_hash_final(ctx, act1);
	ret = lc_compare(act1, exp1, sizeof(act1), "SHAKE128 1");
	lc_hash_zero(ctx);

	if (ret)
		return ret;

	lc_hash_init(shake128_stack);
	lc_hash_update(shake128_stack, msg1, sizeof(msg1));
	lc_hash_set_digestsize(shake128_stack, sizeof(act1));
	lc_hash_final(shake128_stack, act1);
	ret = lc_compare(act1, exp1, sizeof(act1), "SHAKE128 1 - separate ctx");
	lc_hash_zero(shake128_stack);
	if (ret)
		return ret;

	lc_hash_init(ctx);
	lc_hash_update(ctx, msg2, sizeof(msg2));
	lc_hash_set_digestsize(ctx, sizeof(act2));
	lc_hash_final(ctx, act2);
	ret = lc_compare(act2, exp2, sizeof(act2), "SHAKE128 2");
	lc_hash_zero(ctx);

	if (ret)
		return ret;

	return ret;
}

static int shake128_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_shake128);
	LC_EXEC_ONE_TEST(lc_shake128_c);
	LC_EXEC_ONE_TEST(lc_shake128_arm_asm);
	LC_EXEC_ONE_TEST(lc_shake128_arm_ce);
	LC_EXEC_ONE_TEST(lc_shake128_arm_neon);
	LC_EXEC_ONE_TEST(lc_shake128_avx2);
	LC_EXEC_ONE_TEST(lc_shake128_avx512);
	LC_EXEC_ONE_TEST(lc_shake128_riscv_asm);
	LC_EXEC_ONE_TEST(lc_shake256_riscv_asm_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return shake128_tester();
}
