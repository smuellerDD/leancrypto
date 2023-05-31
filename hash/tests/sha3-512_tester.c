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
#include "lc_sha3.h"
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
		ret += _sha3_512_tester(sha3_impl, #sha3_impl)

static int _sha3_512_tester(const struct lc_hash *sha3_512, const char *name)
{
	static const uint8_t msg_512[] = { 0x82, 0xD9, 0x19 };
	static const uint8_t exp_512[] = { 0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5,
					   0x0A, 0x67, 0xFE, 0x69, 0xBD, 0x3F,
					   0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0,
					   0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
					   0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
					   0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B,
					   0x2A, 0xDB, 0x22, 0x84, 0x69, 0x5D,
					   0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
					   0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29,
					   0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
					   0x6E, 0xDE, 0x42, 0x91 };
	struct lc_hash_ctx *sha3_heap = NULL;
	uint8_t act[LC_SHA3_512_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx512, sha3_512);
	LC_SHA3_512_CTX_ON_STACK(ctx512_stack);

	printf("hash ctx %s (%s implementation) len %lu\n", name,
	       sha3_512 == lc_sha3_512_c ? "C" : "accelerated", LC_HASH_CTX_SIZE(sha3_512));
	lc_hash_init(ctx512);
	lc_hash_update(ctx512, msg_512, 3);
	lc_hash_final(ctx512, act);
	ret = lc_compare(act, exp_512, LC_SHA3_512_SIZE_DIGEST, "SHA3-512");
	lc_hash_zero(ctx512);

	lc_hash_init(ctx512_stack);
	lc_hash_update(ctx512_stack, msg_512, 3);
	lc_hash_final(ctx512_stack, act);
	ret += lc_compare(act, exp_512, LC_SHA3_512_SIZE_DIGEST, "SHA3-512");
	lc_hash_zero(ctx512_stack);

	if (lc_hash_alloc(sha3_512, &sha3_heap)) {
		ret = 1;
		goto out;
	}
	lc_hash_init(sha3_heap);
	lc_hash_update(sha3_heap, msg_512, 3);
	lc_hash_final(sha3_heap, act);
	ret += lc_compare(act, exp_512, LC_SHA3_512_SIZE_DIGEST, "SHA3-512");

out:
	lc_hash_zero_free(sha3_heap);
	return ret;
}

static int sha3_512_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha3_512);
	LC_EXEC_ONE_TEST(lc_sha3_512_c);
	LC_EXEC_ONE_TEST(lc_sha3_512_arm_asm);
	LC_EXEC_ONE_TEST(lc_sha3_512_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha3_512_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha3_512_avx2);
	LC_EXEC_ONE_TEST(lc_sha3_512_avx512);
	LC_EXEC_ONE_TEST(lc_sha3_512_riscv_asm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha3_512_tester();
}
