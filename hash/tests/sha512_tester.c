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
#include "lc_sha512.h"
#include "sha512_arm_ce.h"
#include "sha512_arm_neon.h"
#include "sha512_avx2.h"
#include "sha512_c.h"
#include "sha512_riscv.h"
#include "sha512_riscv_zbb.h"
#include "sha512_shani.h"
#include "test_helper_common.h"
#include "visibility.h"

#define LC_EXEC_ONE_TEST(sha512_impl)                                          \
	if (sha512_impl)                                                       \
	ret += _sha512_tester(sha512_impl, #sha512_impl)

static int _sha512_tester(const struct lc_hash *sha512, const char *name)
{
	struct lc_hash_ctx *ctx512 = NULL;
	static const uint8_t msg_512[] = { 0x7F, 0xAD, 0x12 };
	static const uint8_t exp_512[] = {
		0x53, 0x35, 0x98, 0xe5, 0x29, 0x49, 0x18, 0xa0, 0xaf, 0x4b,
		0x3a, 0x62, 0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb, 0x80, 0xe1,
		0x00, 0xa0, 0x74, 0x95, 0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
		0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb, 0x8e, 0xe3, 0x0c, 0x87,
		0x2f, 0x11, 0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52, 0xce, 0xc7,
		0x7c, 0xcf, 0xb8, 0xc7, 0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
		0x9f, 0x60, 0x0c, 0x79
	};
	uint8_t act[LC_SHA512_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx512_stack, sha512);
	LC_SHA512_CTX_ON_STACK(sha512_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       sha512 == lc_sha512_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE(sha512));
	if (lc_hash_init(ctx512_stack))
		return 1;
	lc_hash_update(ctx512_stack, msg_512, sizeof(msg_512));
	lc_hash_final(ctx512_stack, act);
	ret = lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "SHA-512");
	lc_hash_zero(ctx512_stack);

	if (lc_hash_alloc(lc_sha512, &ctx512))
		return 1;
	if (lc_hash_init(ctx512)) {
		lc_hash_zero_free(ctx512);
		return 1;
	}
	lc_hash_update(ctx512, msg_512, 3);
	lc_hash_final(ctx512, act);
	ret += lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "SHA-512");
	lc_hash_zero_free(ctx512);

	if (lc_hash_init(sha512_stack))
		return 1;
	lc_hash_update(sha512_stack, msg_512, sizeof(msg_512));
	lc_hash_final(sha512_stack, act);
	ret += lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "SHA-512 stack");
	lc_memset_secure(act, 0, sizeof(act));
	if (lc_sponge_extract_bytes(lc_sha512, sha512_stack->hash_state, act, 0,
				    sizeof(act)))
		return 1;
	ret += lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST,
			  "SHA-512 extact data");

	lc_hash_zero(sha512_stack);

	return ret;
}

static int sha512_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha512);
	LC_EXEC_ONE_TEST(lc_sha512_c);
	LC_EXEC_ONE_TEST(lc_sha512_avx2);
	LC_EXEC_ONE_TEST(lc_sha512_shani);
	LC_EXEC_ONE_TEST(lc_sha512_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha512_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha512_riscv);
	LC_EXEC_ONE_TEST(lc_sha512_riscv_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = sha512_tester();

	ret = test_validate_status(ret, LC_ALG_STATUS_SHA512);
	ret += test_print_status();

	return ret;
}
