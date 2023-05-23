/*
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "visibility.h"

#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_riscv_asm.h"

#define LC_EXEC_ONE_TEST(sha3_impl)					       \
	if (sha3_impl)							       \
		ret += _cshake_128_tester(sha3_impl, #sha3_impl)

static int _cshake_128_tester(const struct lc_hash *cshake_128,
			      const char *name)
{
	static const uint8_t msg1[] = {
		0x0C, 0x77, 0x8C, 0x22, 0x60, 0xCA, 0xE8, 0x28,
		0xA0
	};
	static const uint8_t cust1[] = {
		0xD8, 0x3E, 0x11, 0x1C, 0xA8, 0x8A, 0x8D, 0xCE,
		0xC6, 0xDE, 0xCD, 0x33, 0x4D, 0x27, 0x45, 0x33,
		0x47, 0xA1, 0x58, 0x1B, 0x6B, 0x88, 0x91, 0x40,
		0x73, 0xBA, 0x59, 0x90, 0x05, 0x4D, 0xC0, 0xE4,
		0xDE, 0x22, 0x08, 0xF8, 0x63, 0x31, 0x79, 0xB9,
		0xB6, 0xE8, 0x17, 0x4E, 0xC7, 0xC9, 0x7B, 0xD6,
		0xFF, 0x55, 0x5D, 0xEE, 0x6F, 0x4A, 0x2C, 0xE1,
		0x37, 0x75, 0x4D, 0x21, 0x43, 0x44, 0xB7, 0xDE,
		0x2C, 0x95, 0xFD, 0xC8, 0xFE, 0x44, 0x88, 0xA4,
		0x90, 0xC7, 0x65, 0x98, 0x69, 0xC9, 0xB5, 0xC1,
		0xDC, 0x9D, 0xD4, 0xBD, 0x2B, 0xED, 0x7A, 0xDC,
		0xEA, 0x06, 0x3D, 0xEC, 0xD6, 0x09, 0x80, 0x1C,
		0x81, 0x80, 0x17, 0x7D, 0x8B, 0x57, 0x73, 0xD3,
		0x12, 0x89, 0xDB, 0xE9, 0x26, 0x17, 0xE7, 0x75,
		0x61, 0x24, 0x2B, 0xC3, 0x60, 0x38, 0x5E, 0x43,
		0x13, 0x89, 0x20, 0x72, 0x18, 0x9A, 0x2D, 0x6B,
		0xB0, 0x8C, 0xAF, 0x51, 0x3E, 0x17, 0xE6, 0x07,
		0x61, 0x34, 0xF5, 0x8A, 0x30, 0x8D, 0x65, 0x0B,
		0x79, 0x55, 0x86, 0x04, 0x75, 0x31, 0xA9, 0x31,
		0xD1, 0x55, 0x94, 0x71, 0x5F, 0xD5, 0x08, 0x07,
		0x13
	};
	static const uint8_t exp1[] = {
		0x77, 0x6e, 0x75, 0x95, 0x0d, 0xdd, 0x3b, 0xf8,
		0xc6, 0xcd, 0x35, 0xfe
	};
	uint8_t act1[sizeof(exp1)];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx, cshake_128);
	LC_CSHAKE_128_CTX_ON_STACK(cshake128_stack);

	printf("hash ctx %s (%s implementation) len %lu\n", name,
	       cshake_128 == lc_cshake128_c ? "C" : "accelerated", LC_HASH_CTX_SIZE(cshake_128));

	lc_cshake_init(ctx, NULL, 0, cust1, sizeof(cust1));
	lc_hash_update(ctx, msg1, sizeof(msg1));
	lc_hash_set_digestsize(ctx, sizeof(act1));
	lc_hash_final(ctx, act1);
	ret = lc_compare(act1, exp1, sizeof(act1), "cSHAKE128 1");
	lc_hash_zero(ctx);

	lc_cshake_init(cshake128_stack, NULL, 0, cust1, sizeof(cust1));
	lc_hash_update(cshake128_stack, msg1, sizeof(msg1));
	lc_hash_set_digestsize(cshake128_stack, sizeof(act1));
	lc_hash_final(cshake128_stack, act1);
	ret += lc_compare(act1, exp1, sizeof(act1), "cSHAKE128 2");
	lc_hash_zero(cshake128_stack);

	if (ret)
		return ret;

	return ret;
}

static int cshake128_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_cshake128);
	LC_EXEC_ONE_TEST(lc_cshake128_c);
	LC_EXEC_ONE_TEST(lc_cshake128_arm_asm);
	LC_EXEC_ONE_TEST(lc_cshake128_arm_ce);
	LC_EXEC_ONE_TEST(lc_cshake128_arm_neon);
	LC_EXEC_ONE_TEST(lc_cshake128_avx2);
	LC_EXEC_ONE_TEST(lc_cshake128_avx512);
	LC_EXEC_ONE_TEST(lc_cshake128_riscv_asm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return cshake128_tester();
}
