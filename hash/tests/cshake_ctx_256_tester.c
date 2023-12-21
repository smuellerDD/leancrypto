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

#define LC_EXEC_ONE_TEST(sha3_impl)                                            \
	if (sha3_impl)                                                         \
	ret += _cshake_256_tester(sha3_impl, #sha3_impl)

static int _cshake_256_tester(const struct lc_hash *cshake_256,
			      const char *name)
{
	static const uint8_t msg1[] = { 0xAF, 0x98, 0xC2, 0x12, 0x96, 0x1A,
					0xAA, 0x55, 0xBD, 0x3C, 0x61, 0xF1 };
	static const uint8_t cust1[] = {
		0x41, 0xE6, 0x62, 0x6C, 0x45, 0x41, 0x10, 0x9D, 0x57, 0x77,
		0x17, 0x40, 0x80, 0x09, 0xB0, 0x6B, 0x0C, 0x01, 0xF3, 0x5A,
		0xC1, 0xAA, 0xB1, 0xDB, 0x57, 0x9E, 0x7D, 0xE6, 0x7B, 0xD2,
		0xDF, 0xFB, 0x43, 0x7A, 0x65, 0x62, 0xF3, 0x81, 0x9D, 0xE5,
		0x01, 0x8C, 0xBC, 0xB6, 0x66, 0x7D, 0x90, 0xF1, 0x21, 0x05,
		0x6E, 0xB0, 0xC3, 0x60, 0x65, 0xA6, 0x48, 0x56, 0xED, 0xE2,
		0x27, 0x12, 0x29, 0x14, 0x2D, 0x7D, 0xBD, 0x10, 0xFB, 0xD1,
		0x71, 0x7A, 0xB2, 0xB6, 0xBB, 0x27, 0x50, 0xF9, 0x32, 0x45,
		0x81, 0xA4, 0xF9, 0xA4, 0xE7, 0x0D, 0x79, 0x00, 0x8B, 0x60,
		0x34, 0x65, 0xFB, 0x50, 0x9C, 0xBC, 0xB3, 0x0D
	};
	static const uint8_t exp1[] = {
		0x90, 0x67, 0x5B, 0x96, 0x09, 0x63, 0xE9, 0x2A, 0x5D, 0x2E,
		0x66, 0xE3, 0x15, 0x8D, 0x0E, 0xE5, 0xC0, 0x7B, 0x83, 0xBB,
		0x23, 0x7B, 0x2A, 0x51, 0xE7, 0xE1, 0x24, 0x03, 0x68, 0xBD,
		0x9F, 0x39, 0xC0, 0x96, 0x6E, 0x94, 0x37, 0x3B, 0x52, 0x6A,
		0x79, 0x1F, 0xD4, 0x03, 0x4E, 0x46, 0xFD, 0x46, 0xEA, 0xAF,
		0x57, 0x92, 0xB8, 0x4E, 0x50, 0x92, 0x81, 0xB6, 0x11, 0xD2,
		0x72, 0x14, 0xC7, 0xEE, 0x2F, 0x93, 0xDD, 0x46, 0x62, 0x7D,
		0x09, 0x2D, 0xD8, 0xA1, 0x58, 0x87, 0xEF, 0x5A, 0xAA, 0x3C,
		0x46, 0x8D, 0x7A, 0x4C, 0x57, 0x71, 0x7B, 0x9A, 0x4C, 0x92,
		0xEA
	};
	uint8_t act1[sizeof(exp1)];
	int ret;
	LC_CSHAKE_CTX_ON_STACK_REINIT(ctx_re, cshake_256);
	LC_CSHAKE_CTX_ON_STACK(ctx, cshake_256);

	printf("hash ctx %s (%s implementation) len %lu\n", name,
	       cshake_256 == lc_cshake256_c ? "C" : "accelerated",
	       LC_HASH_CTX_SIZE(cshake_256));

	lc_cshake_ctx_init(ctx_re, NULL, 0, cust1, sizeof(cust1));
	lc_cshake_ctx_update(ctx_re, msg1, sizeof(msg1));
	lc_cshake_ctx_final(ctx_re, act1, sizeof(act1));
	ret = lc_compare(act1, exp1, sizeof(act1), "cSHAKE256 reinit 1");

	/* no zeroization to test reinit */

	if (ret)
		return ret;

	lc_cshake_ctx_reinit(ctx_re);
	lc_cshake_ctx_update(ctx_re, msg1, sizeof(msg1));
	lc_cshake_ctx_final(ctx_re, act1, sizeof(act1));
	ret = lc_compare(act1, exp1, sizeof(act1), "cSHAKE256 reinit 2");
	lc_cshake_ctx_zero(ctx_re);
	if (ret)
		return ret;

	lc_cshake_ctx_init(ctx, NULL, 0, cust1, sizeof(cust1));
	lc_cshake_ctx_update(ctx, msg1, sizeof(msg1));
	lc_cshake_ctx_final(ctx, act1, sizeof(act1));
	ret = lc_compare(act1, exp1, sizeof(act1), "cSHAKE256 init 1");
	lc_cshake_ctx_zero(ctx);
	if (ret)
		return ret;

	return ret;
}

static int cshake256_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_cshake256);
	LC_EXEC_ONE_TEST(lc_cshake256_c);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_asm);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_ce);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_neon);
	LC_EXEC_ONE_TEST(lc_cshake256_avx2);
	LC_EXEC_ONE_TEST(lc_cshake256_avx512);
	LC_EXEC_ONE_TEST(lc_cshake256_riscv_asm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return cshake256_tester();
}
