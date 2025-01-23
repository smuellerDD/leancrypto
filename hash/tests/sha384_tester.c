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
#include "visibility.h"

#define LC_EXEC_ONE_TEST(sha384_impl)                                          \
	if (sha384_impl)                                                       \
	ret += _sha384_tester(sha384_impl, #sha384_impl)

static int _sha384_tester(const struct lc_hash *sha384, const char *name)
{
	struct lc_hash_ctx *ctx384 = NULL;
	static const uint8_t msg_384[] = { 0x61, 0x62, 0x63 };
	static const uint8_t exp_384[] = {
		0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0,
		0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB,
		0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF,
		0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
		0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7
	};
	uint8_t act[LC_SHA384_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx384_stack, sha384);
	LC_SHA384_CTX_ON_STACK(sha384_stack);

	printf("hash ctx %s (%s implementation) len %u\n", name,
	       sha384 == lc_sha384_c ? "C" : "accelerated",
	       (unsigned int)LC_HASH_CTX_SIZE(sha384));
	lc_hash_init(ctx384_stack);
	lc_hash_update(ctx384_stack, msg_384, sizeof(msg_384));
	lc_hash_final(ctx384_stack, act);
	ret = lc_compare(act, exp_384, LC_SHA384_SIZE_DIGEST, "SHA-384");
	lc_hash_zero(ctx384_stack);

	if (lc_hash_alloc(lc_sha384, &ctx384))
		return 1;
	lc_hash_init(ctx384);
	lc_hash_update(ctx384, msg_384, sizeof(msg_384));
	lc_hash_final(ctx384, act);
	ret += lc_compare(act, exp_384, LC_SHA384_SIZE_DIGEST, "SHA-384");
	lc_hash_zero_free(ctx384);

	lc_hash_init(sha384_stack);
	lc_hash_update(sha384_stack, msg_384, sizeof(msg_384));
	lc_hash_final(sha384_stack, act);
	lc_hash_zero(sha384_stack);
	ret += lc_compare(act, exp_384, LC_SHA384_SIZE_DIGEST, "SHA-384 stack");

	return ret;
}

static int sha384_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha384);
	LC_EXEC_ONE_TEST(lc_sha384_c);
	LC_EXEC_ONE_TEST(lc_sha384_avx2);
	LC_EXEC_ONE_TEST(lc_sha384_shani);
	LC_EXEC_ONE_TEST(lc_sha384_arm_ce);
	LC_EXEC_ONE_TEST(lc_sha384_arm_neon);
	LC_EXEC_ONE_TEST(lc_sha384_riscv);
	LC_EXEC_ONE_TEST(lc_sha384_riscv_zbb);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha384_tester();
}
