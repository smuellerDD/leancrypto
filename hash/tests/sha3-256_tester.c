/*
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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
#include "testfunctions.h"
#include "visibility.h"

#include "sha3_c.h"
#include "sha3_arm8_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"

#define LC_EXEC_ONE_TEST(sha3_impl)					       \
	if (sha3_impl)							       \
		ret += _sha3_256_tester(sha3_impl, #sha3_impl)

static int _sha3_256_tester(const struct lc_hash *sha3_256, const char *name)
{
	static const uint8_t msg_256[] = { 0x5E, 0x5E, 0xD6 };
	static const uint8_t exp_256[] = { 0xF1, 0x6E, 0x66, 0xC0, 0x43, 0x72,
					   0xB4, 0xA3, 0xE1, 0xE3, 0x2E, 0x07,
					   0xC4, 0x1C, 0x03, 0x40, 0x8A, 0xD5,
					   0x43, 0x86, 0x8C, 0xC4, 0x0E, 0xC5,
					   0x5E, 0x00, 0xBB, 0xBB, 0xBD, 0xF5,
					   0x91, 0x1E };
	uint8_t act[LC_SHA3_256_SIZE_DIGEST];
	int ret;
	LC_HASH_CTX_ON_STACK(ctx256, sha3_256);
	LC_SHA3_256_CTX_ON_STACK(ctx256_stack);

	printf("hash ctx %s (%s implementation) len %lu\n", name,
	       sha3_256 == lc_sha3_256_c ? "C" : "accelerated", LC_HASH_CTX_SIZE(sha3_256));
	lc_hash_init(ctx256);
	lc_hash_update(ctx256, msg_256, 3);
	lc_hash_final(ctx256, act);
	ret = compare(act, exp_256, LC_SHA3_256_SIZE_DIGEST, "SHA3-256");
	lc_hash_zero(ctx256);

	lc_hash_init(ctx256_stack);
	lc_hash_update(ctx256_stack, msg_256, 3);
	lc_hash_final(ctx256_stack, act);
	ret += compare(act, exp_256, LC_SHA3_256_SIZE_DIGEST, "SHA3-256");
	lc_hash_zero(ctx256_stack);

	return ret;
}

int sha3_256_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_sha3_256);
	LC_EXEC_ONE_TEST(lc_sha3_256_c);
	LC_EXEC_ONE_TEST(lc_sha3_256_arm8_neon);
	LC_EXEC_ONE_TEST(lc_sha3_256_avx2);
	LC_EXEC_ONE_TEST(lc_sha3_256_avx512);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha3_256_tester();
}
