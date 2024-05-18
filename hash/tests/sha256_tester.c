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
#include "lc_sha256.h"
#include "visibility.h"

static int sha256_tester(void)
{
	static const uint8_t msg_256[] = { 0x06, 0x3A, 0x53 };
	static const uint8_t exp_256[] = { 0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
					   0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
					   0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
					   0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
					   0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
					   0x6f, 0xf4 };
	uint8_t act[LC_SHA256_SIZE_DIGEST];
	int ret;
	LC_SHA256_CTX_ON_STACK(sha256_stack);

	printf("hash ctx len %" PRIu64 "\n", LC_HASH_CTX_SIZE(lc_sha256));
	lc_hash(lc_sha256, msg_256, sizeof(msg_256), act);
	ret = lc_compare(act, exp_256, LC_SHA256_SIZE_DIGEST, "SHA-256");

	lc_hash_init(sha256_stack);
	lc_hash_update(sha256_stack, msg_256, sizeof(msg_256));
	lc_hash_final(sha256_stack, act);
	lc_hash_zero(sha256_stack);
	ret += lc_compare(act, exp_256, LC_SHA256_SIZE_DIGEST, "SHA-256 stack");

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha256_tester();
}
