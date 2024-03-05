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
#include "lc_sha512.h"
#include "visibility.h"

static int sha512_tester(void)
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
	LC_SHA512_CTX_ON_STACK(sha512_stack);

	printf("hash ctx len %lu\n", LC_HASH_CTX_SIZE(lc_sha512));

	if (lc_hash_alloc(lc_sha512, &ctx512))
		return 1;
	lc_hash_init(ctx512);
	lc_hash_update(ctx512, msg_512, 3);
	lc_hash_final(ctx512, act);
	ret = lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "SHA-512");
	lc_hash_zero_free(ctx512);

	lc_hash_init(sha512_stack);
	lc_hash_update(sha512_stack, msg_512, sizeof(msg_512));
	lc_hash_final(sha512_stack, act);
	lc_hash_zero(sha512_stack);
	ret += lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "SHA-512 stack");

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha512_tester();
}
