/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "lc_kdf_ctr.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "visibility.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/CounterMode.zip
 */
static int kdf_ctr_tester(void)
{
	struct lc_rng_ctx *ctr_kdf_rng_heap = NULL;
	int ret;
	static const uint8_t key[] = { 0xdd, 0x1d, 0x91, 0xb7, 0xd9, 0x0b, 0x2b,
				       0xd3, 0x13, 0x85, 0x33, 0xce, 0x92, 0xb2,
				       0x72, 0xfb, 0xf8, 0xa3, 0x69, 0x31, 0x6a,
				       0xef, 0xe2, 0x42, 0xe6, 0x59, 0xcc, 0x0a,
				       0xe2, 0x38, 0xaf, 0xe0 };
	static const uint8_t label[] = {
		0x01, 0x32, 0x2b, 0x96, 0xb3, 0x0a, 0xcd, 0x19, 0x79, 0x79,
		0x44, 0x4e, 0x46, 0x8e, 0x1c, 0x5c, 0x68, 0x59, 0xbf, 0x1b,
		0x1c, 0xf9, 0x51, 0xb7, 0xe7, 0x25, 0x30, 0x3e, 0x23, 0x7e,
		0x46, 0xb8, 0x64, 0xa1, 0x45, 0xfa, 0xb2, 0x5e, 0x51, 0x7b,
		0x08, 0xf8, 0x68, 0x3d, 0x03, 0x15, 0xbb, 0x29, 0x11, 0xd8,
		0x0a, 0x0e, 0x8a, 0xba, 0x17, 0xf3, 0xb4, 0x13, 0xfa, 0xac
	};
	static const uint8_t exp[] = { 0x10, 0x62, 0x13, 0x42, 0xbf, 0xb0,
				       0xfd, 0x40, 0x04, 0x6c, 0x0e, 0x29,
				       0xf2, 0xcf, 0xdb, 0xf0 };
	uint8_t act[sizeof(exp)];

	static const uint8_t key2[] = { 0xBD, 0x7B, 0xD8, 0x07, 0x10, 0xE5,
					0xD4, 0x8A, 0xCB, 0x09, 0x3D, 0x4A,
					0x92, 0x61, 0x6F, 0x6A };
	static const uint8_t label2[] = { 0xf3, 0x33, 0x4d, 0x6c, 0x13, 0x10,
					  0xeb, 0x4c, 0x0c, 0x43, 0x8e, 0x3a,
					  0xac, 0xed, 0xb5, 0xb1, 0x13, 0x32,
					  0x7c, 0xeb, 0x93, 0x30, 0xc4, 0x38,
					  0x3a, 0x81, 0x08, 0x48, 0x28, 0x67,
					  0xaa, 0x5a };
	static const uint8_t exp2[] = {
		0x20, 0xc7, 0x45, 0xea, 0xb4, 0x45, 0x17, 0x1a, 0xc4, 0xba,
		0xf1, 0x37, 0x69, 0xb1, 0xf4, 0xa2, 0xb6, 0x4e, 0x4d, 0x77,
		0xfa, 0x49, 0x91, 0xd5, 0xed, 0xff, 0xb5, 0xc4, 0x91, 0x26,
		0x50, 0xb9, 0xfe, 0x43, 0xf0, 0x0a, 0xfa, 0x11, 0xb6, 0xbf,
		0x5d, 0xc8, 0x5a, 0x8a, 0xf0, 0xa7, 0x69, 0xf6, 0xa4, 0x45,
		0xe9, 0xeb, 0xb0, 0xa4, 0x67, 0xb9, 0x3e, 0xe2, 0xa9, 0x5b,
		0x6b, 0x75, 0x90, 0x73, 0x1e, 0xad, 0x0c, 0xf3, 0x7f, 0x16,
		0x8c, 0x9c, 0x13, 0x33, 0xfc, 0xd1, 0x40, 0x99, 0x68, 0x7e,
		0x41, 0xa0, 0xa1, 0xb2, 0x9d, 0xd0, 0x09, 0x93, 0xea, 0x82,
		0x43, 0x6b, 0x37, 0x69, 0xcc, 0x18, 0x2a, 0x79, 0x2b, 0x60,
		0x5f, 0x57, 0xf4, 0x10, 0xac, 0x39, 0x19, 0x6f, 0x49, 0xb7,
		0x70, 0x13, 0x5b, 0x8f, 0xf2, 0xce, 0xc6, 0x43, 0x0e, 0x29,
		0x7a, 0xe4, 0x32, 0x9e, 0x58, 0x91, 0xc3, 0x66, 0xdb, 0x62,
		0x7a, 0xa5, 0x4e, 0x7c, 0x8e, 0x71, 0x05, 0xb7, 0xc7, 0x3d,
		0xd0, 0x29, 0xdf, 0xa8, 0xcd, 0x7d, 0xa9, 0x18, 0xed, 0x25,
		0xd4, 0xd6, 0xcb, 0xad, 0x2e, 0x0c, 0xbe, 0x60, 0x56, 0x58,
		0x5c, 0x67, 0x1a, 0xbd, 0x0e, 0xbd, 0xd1, 0x08, 0xf4, 0xd4,
		0xd1, 0xdf, 0x45, 0xa0, 0x05, 0x1a, 0xad, 0x30, 0xde, 0x53,
		0x61, 0x6e, 0x69, 0xa6, 0x73, 0x46, 0x89, 0x6a, 0x0f, 0x52,
		0x7e, 0xfa, 0xe4, 0x28, 0x92, 0xc9, 0x87, 0x33, 0x47, 0x94,
		0x89, 0x57, 0x52, 0x2b, 0x32, 0xa6, 0x39, 0x9d, 0x66, 0x56,
		0x59, 0xa7, 0xee, 0x74, 0xa7, 0x52, 0x64, 0x9c, 0x19, 0x2d,
		0xd0, 0x74, 0x8b, 0xa8, 0x92, 0xa3, 0xa1, 0xf6, 0xd7, 0x7a,
		0xba, 0x8b, 0x35, 0x3f, 0x1a, 0x71, 0x82, 0x7e, 0x37, 0x42,
		0x9c, 0x14, 0x2a, 0x9d, 0x94, 0xdb, 0xc4, 0x12, 0x6e, 0x91,
		0x4e, 0x24, 0x7a, 0x7b, 0x6c, 0x1d, 0xdf, 0x2a, 0x59, 0xd9,
		0xfb, 0x07, 0x01, 0x5e, 0x24, 0x11, 0x75, 0x18, 0xcc, 0x2b,
		0x2a, 0xd3, 0xc2, 0x84, 0x00, 0x73, 0xfd, 0xc2, 0xdc, 0xd4,
		0xeb, 0x9c, 0x61, 0xe1, 0xd1, 0x9c, 0xb5, 0x91, 0xb6, 0x45,
		0x6a, 0x48, 0x88, 0x59, 0x98, 0x23, 0xbc, 0x04, 0x02, 0x86,
		0xf6, 0x93, 0xd3, 0x09, 0xff, 0x1c, 0xc9, 0x04, 0x74, 0xcc,
		0x71, 0x51, 0x83, 0xf7, 0x77, 0x67, 0x3a, 0xa7, 0xe5, 0x33,
		0xc1, 0xf2, 0xeb, 0x9a, 0x9a, 0x90, 0xfb, 0x59, 0xf3, 0xee,
		0xd9, 0x78, 0xaa, 0xf9, 0x52, 0x56, 0xd3, 0xe2, 0x3b, 0x7c,
		0x7e, 0x9d, 0x4b, 0xaf, 0xe5, 0x3b, 0xe4, 0xb2, 0x9c, 0xf2,
		0x23, 0x99, 0xab, 0x73, 0xcd, 0xea, 0xa5, 0xe2, 0xe6, 0x61,
		0xdc, 0x2f, 0xc3, 0x9f, 0x6f, 0x49, 0x69, 0xe5, 0x72, 0x19,
		0x74, 0xc7, 0x13, 0x23, 0xd3, 0xbf, 0x93, 0xb0, 0x07, 0x35,
		0x2d, 0x03, 0x7f, 0x71, 0x76, 0x7c, 0xf5, 0x68, 0x0c, 0x96,
		0x06, 0x77, 0x65, 0x77, 0x99, 0xc5, 0x26, 0xee, 0x53, 0x45,
		0x03, 0x96, 0x48, 0xe0, 0x94, 0x4e, 0x4f, 0x02, 0xc3, 0x88,
		0x48, 0x0e, 0x3e, 0x26, 0x6c, 0x17, 0x6c, 0x75, 0x41, 0x1d,
		0x38, 0x5a, 0xcb, 0xf7, 0x65, 0xa8, 0xa8, 0x2f, 0x79, 0x60,
		0x51, 0xe2
	};
	uint8_t act2[sizeof(exp2)];
	LC_CTR_KDF_DRNG_CTX_ON_STACK(ctr_kdf_rng, lc_sha256);

	CKINT_LOG(lc_kdf_ctr(lc_sha256, key, sizeof(key), label, sizeof(label),
			     act, sizeof(act)),
		  "CTR KDF failed\n");

	ret = lc_compare(act, exp, sizeof(exp), "CTR KDF SHA-256");
	if (ret)
		goto out;

	CKINT_LOG(lc_rng_seed(ctr_kdf_rng, key, sizeof(key), NULL, 0),
		  "Counter KDF extract stack failed\n");

	CKINT_LOG(lc_rng_generate(ctr_kdf_rng, label, sizeof(label), act,
				  sizeof(act)),
		  "Counter KDF expand stack failed\n");

	ret = lc_compare(act, exp, sizeof(exp), "CTR KDF SHA-256 RNG");
	if (ret)
		goto out;

	CKINT_LOG(lc_kdf_ctr(lc_sha256, key2, sizeof(key2), label2,
			     sizeof(label2), act2, sizeof(act2)),
		  "CTR KDF failed\n");

	ret = lc_compare(act2, exp2, sizeof(exp2), "CTR KDF SHA-256");
	if (ret)
		goto out;

	CKINT_LOG(lc_kdf_ctr_rng_alloc(&ctr_kdf_rng_heap, lc_sha256),
		  "Allocation of heap CTR KDF RNG context failed: %d\n", ret);

	CKINT_LOG(lc_rng_seed(ctr_kdf_rng_heap, key2, sizeof(key2), NULL, 0),
		  "Counter KDF extract stack failed\n");

	CKINT_LOG(lc_rng_generate(ctr_kdf_rng_heap, label2, sizeof(label2),
				  act2, sizeof(act2)),
		  "Counter KDF expand stack failed\n");

	ret = lc_compare(act2, exp2, sizeof(exp2), "CTR KDF SHA-256 RNG");

out:
	lc_rng_zero_free(ctr_kdf_rng_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kdf_ctr_tester();
}
