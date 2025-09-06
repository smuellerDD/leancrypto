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
#include "lc_kmac.h"
#include "ret_checkers.h"
#include "visibility.h"

#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"

#define LC_EXEC_ONE_TEST(sha3_impl)                                            \
	if (sha3_impl)                                                         \
	ret += _kmac_256_xof_more_tester(sha3_impl, #sha3_impl)

static int _kmac_256_xof_more_tester(const struct lc_hash *cshake_256,
				     const char *name)
{
	static const uint8_t msg1[] = {
		0x6F, 0x50, 0xA7, 0xC3, 0x48, 0xCE, 0xA5, 0x10, 0x6A,
		0xBE, 0x32, 0xE4, 0xF0, 0x9E, 0x7B, 0xC6, 0x0E, 0x5F,
		0x8F, 0xE1, 0x17, 0xF9, 0x41, 0x29, 0x73, 0xC2, 0xAC,
		0x0E, 0xD6, 0x87, 0xCD, 0x41, 0x99, 0xB7, 0xCD, 0x5B,
		0x89, 0xA4, 0x02, 0x82, 0xD8, 0x54, 0x51
	};
	static const uint8_t key1[] = {
		0x04, 0xBB, 0xB3, 0xF4, 0x84, 0x74, 0x25, 0x97, 0x72, 0xD8,
		0xF0, 0x78, 0x3C, 0xAC, 0x31, 0x67, 0x4B, 0x50, 0x7D, 0x64,
		0xBB, 0xC3, 0xED, 0x98, 0xE4, 0x23, 0xEF, 0xEC, 0xA6, 0xD1,
		0x68, 0xD1, 0x8F, 0x36, 0xED, 0x5A, 0xDB, 0x0E, 0xFD, 0x8C,
		0x3A, 0x43, 0x91, 0x2F, 0x32, 0x9C, 0xF0, 0x4B, 0x75, 0x4A,
		0xD3, 0xEA, 0xAA, 0xE4, 0x88, 0xF2, 0x15, 0x8F, 0x02, 0x82,
		0x01, 0x60, 0xDB, 0x03, 0x08, 0x23, 0x14, 0x2D, 0xF7, 0xA6,
		0xB2, 0x1F, 0x3B, 0x28, 0x48, 0x44, 0xB5, 0x03, 0x28, 0xE6,
		0xA5, 0xF1, 0x4C, 0x81, 0xD4, 0x70, 0xF5, 0xA4, 0x64, 0xE4,
		0x00, 0x8D, 0x2D, 0x38, 0xB4, 0x83, 0x87
	};
	static const uint8_t cust1[] = {
		0xCD, 0xD2, 0x11, 0x8F, 0xB7, 0xF9, 0xFC, 0x88, 0xF2, 0x96,
		0x88, 0xA2, 0xF9, 0x40, 0x70, 0xE5, 0x2D, 0xA5, 0xDA, 0xAD,
		0xD3, 0x12, 0xFB, 0x9F, 0xA4, 0xBF, 0xC6, 0x15, 0x77, 0xFE,
		0xBA, 0xF7, 0x89, 0x56, 0x8A, 0xF0, 0x81, 0xB0, 0x79, 0xDE,
		0x69, 0xC6, 0x1D, 0x0E, 0x0F, 0xB4, 0xC7, 0x2F, 0xE0, 0xC2,
		0x95, 0xA3, 0xF3, 0xF7, 0x3D, 0x57, 0xC3, 0x92, 0x40, 0x31,
		0xD8, 0x65, 0x4E, 0x10, 0xA4, 0x97, 0x57, 0xC0
	};
	uint8_t act1[LC_SHA3_256_SIZE_BLOCK * 3 + 5];
	uint8_t act2[LC_SHA3_256_SIZE_BLOCK * 3 + 5];
	int ret;
	LC_KMAC_CTX_ON_STACK_REINIT(kmac, cshake_256);

	printf("hash ctx %s (%s implementation) len %lu\n", name,
	       cshake_256 == lc_cshake256_c ? "C" : "accelerated",
	       LC_KMAC_CTX_SIZE(cshake_256));

	CKINT(lc_kmac_init(kmac, key1, sizeof(key1), cust1, sizeof(cust1)));
	lc_kmac_update(kmac, msg1, sizeof(msg1));
	lc_kmac_final_xof(kmac, act1, sizeof(act1));

	lc_kmac_reinit(kmac);
	lc_kmac_update(kmac, msg1, sizeof(msg1));
	lc_kmac_final_xof(kmac, act2, LC_SHA3_256_SIZE_BLOCK);
	lc_kmac_final_xof(kmac, act2 + LC_SHA3_256_SIZE_BLOCK,
			  LC_SHA3_256_SIZE_BLOCK);
	lc_kmac_final_xof(kmac, act2 + 2 * LC_SHA3_256_SIZE_BLOCK,
			  sizeof(act2) - 2 * LC_SHA3_256_SIZE_BLOCK);

	ret = lc_compare(act1, act2, sizeof(act1), "KMAC256 XOF More");
	lc_kmac_zero(kmac);

out:
	return ret;
}

static int kmac_xof_more_tester(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(lc_cshake256);
	LC_EXEC_ONE_TEST(lc_cshake256_c);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_asm);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_ce);
	LC_EXEC_ONE_TEST(lc_cshake256_arm_neon);
	LC_EXEC_ONE_TEST(lc_cshake256_avx2);
	LC_EXEC_ONE_TEST(lc_cshake256_avx512);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kmac_xof_more_tester();
}
