/*
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "lc_sha3.h"
#include "test_helper_common.h"
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
	ret += _sha3_224_tester(sha3_impl, #sha3_impl)

static int _sha3_224_tester(const struct lc_hash *sha3_224, const char *name)
{
	static const uint8_t msg_224[] = { 0x50, 0xEF, 0x73 };
	static const uint8_t exp_224[] = { 0x42, 0xF9, 0xE4, 0xEA, 0xE8, 0x55,
					   0x49, 0x61, 0xD1, 0xD2, 0x7D, 0x47,
					   0xD9, 0xAF, 0x08, 0xAF, 0x98, 0x8F,
					   0x18, 0x9F, 0x53, 0x42, 0x2A, 0x07,
					   0xD8, 0x7C, 0x68, 0xC1 };
	struct lc_hash_ctx *sha3_heap = NULL;
	uint8_t act[LC_SHA3_224_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx224, sha3_224);
	LC_SHA3_224_CTX_ON_STACK(ctx224_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       sha3_224 == lc_sha3_224_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE(sha3_224));
	if (lc_hash_init(ctx224))
		return 1;
	lc_hash_update(ctx224, msg_224, 3);
	lc_hash_final(ctx224, act);
	ret = lc_compare(act, exp_224, LC_SHA3_224_SIZE_DIGEST, "SHA3-224");
	lc_hash_zero(ctx224);

	if (lc_hash_init(ctx224_stack))
		return 1;
	lc_hash_update(ctx224_stack, msg_224, 3);
	lc_hash_final(ctx224_stack, act);
	ret += lc_compare(act, exp_224, LC_SHA3_224_SIZE_DIGEST, "SHA3-224");
	lc_hash_zero(ctx224_stack);

	if (lc_hash_alloc(sha3_224, &sha3_heap)) {
		ret = 1;
		goto out;
	}
	if (lc_hash_init(sha3_heap)) {
		ret = 1;
		goto out;
	}
	lc_hash_update(sha3_heap, msg_224, 3);
	lc_hash_final(sha3_heap, act);
	ret += lc_compare(act, exp_224, LC_SHA3_224_SIZE_DIGEST, "SHA3-224");

out:
	lc_hash_zero_free(sha3_heap);
	return ret;
}

static int sha3_224_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha3_224);
	LC_EXEC_ONE_TEST(lc_sha3_224_c);
	LC_EXEC_ONE_TEST(lc_sha3_224_arm_asm);
	LC_EXEC_ONE_TEST(lc_sha3_224_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha3_224_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha3_224_avx2);
	LC_EXEC_ONE_TEST(lc_sha3_224_avx512);
	LC_EXEC_ONE_TEST(lc_sha3_224_riscv_asm);
	LC_EXEC_ONE_TEST(lc_sha3_224_riscv_asm_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = sha3_224_tester();

	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224), 1);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224_c),
				   lc_sha3_224 == lc_sha3_224_c);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224_arm_asm),
				   lc_sha3_224 == lc_sha3_224_arm_asm);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224_arm_ce),
				   lc_sha3_224 == lc_sha3_224_arm_ce);
	ret = test_validate_status(ret,
				   lc_hash_alg_status(lc_sha3_224_arm_neon),
				   lc_sha3_224 == lc_sha3_224_arm_neon);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224_avx2),
				   lc_sha3_224 == lc_sha3_224_avx2);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha3_224_avx512),
				   lc_sha3_224 == lc_sha3_224_avx512);
	ret = test_validate_status(ret,
				   lc_hash_alg_status(lc_sha3_224_riscv_asm),
				   lc_sha3_224 == lc_sha3_224_riscv_asm);
	ret = test_validate_status(
		ret, lc_hash_alg_status(lc_sha3_224_riscv_asm_zbb),
		lc_sha3_224 == lc_sha3_224_riscv_asm_zbb);
	ret += test_print_status();

	return ret;
}
