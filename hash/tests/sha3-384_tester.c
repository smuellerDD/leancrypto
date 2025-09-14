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
#include "ext_headers_internal.h"
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
	ret += s_ha3_384_tester(sha3_impl, #sha3_impl)

static int s_ha3_384_tester(const struct lc_hash *sha3_384, const char *name)
{
	static const uint8_t msg_384[] = { 0xE7, 0x3B, 0xAD };
	static const uint8_t exp_384[] = {
		0xc4, 0x02, 0xc8, 0x29, 0x90, 0x68, 0xaa, 0x30, 0x28, 0xa9,
		0xa4, 0x1c, 0xff, 0x9a, 0x0b, 0x74, 0x27, 0x31, 0x92, 0x70,
		0xf2, 0x42, 0x18, 0xda, 0xe8, 0x68, 0x1a, 0x89, 0x01, 0x51,
		0x0c, 0x47, 0x5a, 0x5f, 0xb9, 0x6b, 0x5c, 0xbc, 0x32, 0xdc,
		0xa1, 0x5f, 0x28, 0x53, 0xa0, 0xce, 0x55, 0xf6
	};
	struct lc_hash_ctx *sha3_heap = NULL;
	uint8_t act[LC_SHA3_384_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx384, sha3_384);
	LC_SHA3_384_CTX_ON_STACK(ctx384_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       sha3_384 == lc_sha3_384_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE(sha3_384));
	if (lc_hash_init(ctx384))
		return 1;
	lc_hash_update(ctx384, msg_384, 3);
	lc_hash_final(ctx384, act);
	ret = lc_compare(act, exp_384, LC_SHA3_384_SIZE_DIGEST, "SHA3-384");
	lc_hash_zero(ctx384);

	if (lc_hash_init(ctx384_stack))
		return 1;
	lc_hash_update(ctx384_stack, msg_384, 3);
	lc_hash_final(ctx384_stack, act);
	ret += lc_compare(act, exp_384, LC_SHA3_384_SIZE_DIGEST, "SHA3-384");
	lc_hash_zero(ctx384_stack);

	if (lc_hash_alloc(sha3_384, &sha3_heap)) {
		ret = 1;
		goto out;
	}
	if (lc_hash_init(sha3_heap)) {
		ret = 1;
		goto out;
	}
	lc_hash_update(sha3_heap, msg_384, 3);
	lc_hash_final(sha3_heap, act);
	ret += lc_compare(act, exp_384, LC_SHA3_384_SIZE_DIGEST, "SHA3-384");

out:
	lc_hash_zero_free(sha3_heap);
	return ret;
}

static int sha3_384_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha3_384);
	LC_EXEC_ONE_TEST(lc_sha3_384_c);
	LC_EXEC_ONE_TEST(lc_sha3_384_arm_asm);
	LC_EXEC_ONE_TEST(lc_sha3_384_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha3_384_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha3_384_avx2);
	LC_EXEC_ONE_TEST(lc_sha3_384_avx512);
	LC_EXEC_ONE_TEST(lc_sha3_384_riscv_asm);
	LC_EXEC_ONE_TEST(lc_sha3_384_riscv_asm_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = sha3_384_tester();

	ret = test_validate_status(ret, LC_ALG_STATUS_SHA3);
	ret += test_print_status();

	return ret;
}
