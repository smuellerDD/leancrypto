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
#include "lc_hmac.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "test_helper_common.h"
#include "visibility.h"

static int hmac_sha2_256_tester(void)
{
	static const uint8_t msg_256[] = { 0xF2, 0xAA, 0xAA, 0x3A, 0x63, 0xD6,
					   0xE8, 0x10, 0xE7, 0xD1, 0x13, 0x57,
					   0xA0, 0x1E, 0xE7, 0xA6 };
	static const uint8_t key_256[] = {
		0x19, 0xC4, 0xAB, 0x40, 0xE3, 0x76, 0x3E, 0xF1, 0x24, 0x3F,
		0x77, 0xB3, 0xDB, 0x06, 0x0A, 0x86, 0xEF, 0xF0, 0xD5, 0x12,
		0x23, 0x00, 0xED, 0x7D, 0x8B, 0x25, 0x97, 0xC3, 0x18, 0x5C,
		0xE4, 0x23, 0x43, 0x4B, 0x91, 0xC3, 0x73, 0x3C, 0x2A, 0xC7,
		0xBC, 0xCE, 0x3A, 0x50, 0x54, 0x74, 0x36, 0x7F, 0x94, 0x2C,
		0xB3, 0x85, 0x42, 0x2A, 0xF1, 0xAA, 0x87, 0x1F, 0x7D, 0x0E,
		0x3E, 0xFA, 0xBF, 0x5E
	};
	static const uint8_t exp_256[] = { 0x69, 0xe3, 0x08, 0xca, 0x4a, 0x24,
					   0xac, 0xbe, 0xdf, 0x73, 0xd1, 0xb4,
					   0x67, 0x58, 0x70, 0x34, 0xe9, 0x49,
					   0x38, 0x33, 0x1b, 0xe8, 0xc2, 0x24,
					   0x02, 0x6c, 0x87, 0x8b, 0xae, 0x41,
					   0xb4, 0xcd };
	uint8_t act[LC_SHA256_SIZE_DIGEST];
	struct lc_hmac_ctx *hmac_ctx;
	int ret;

	if (lc_hmac_alloc(lc_sha256, &hmac_ctx))
		return 1;
	CKINT(lc_hmac_init(hmac_ctx, key_256, sizeof(key_256)));
	lc_hmac_update(hmac_ctx, msg_256, sizeof(msg_256));
	lc_hmac_final(hmac_ctx, act);
	lc_hmac_zero_free(hmac_ctx);

	ret = lc_compare(act, exp_256, LC_SHA256_SIZE_DIGEST, "HMAC SHA2-256");

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = hmac_sha2_256_tester();

	if (lc_status_get_result(LC_ALG_STATUS_SHA256) !=
	    lc_alg_status_result_passed) {
		printf("SHA-256 self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_SHA256));
		return 1;
	}

	if (lc_status_get_result(LC_ALG_STATUS_HMAC) !=
	    lc_alg_status_result_passed) {
		printf("HMAC self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_HMAC));
		return 1;
	}

	ret += test_print_status();

	return ret;
}
