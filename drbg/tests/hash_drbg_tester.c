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

#include "lc_hash_drbg_sha512.h"
#include "compare.h"

static int hash_drbg_tester(void)
{
#if 1
	static const uint8_t ent_nonce[] = {
		0x9E, 0x28, 0x52, 0xF1, 0xD8, 0xB2, 0x3C, 0x1A,
		0x80, 0xCA, 0x75, 0x29, 0x37, 0xAC, 0x58, 0x54,
		0x61, 0x98, 0xDB, 0x72, 0x81, 0xB7, 0x43, 0xDB,
		0x37, 0x21, 0x8E, 0x86, 0x40, 0x3B, 0x74, 0xF9,
		0x88, 0x45, 0x49, 0xDC, 0x49, 0x26, 0xBB, 0xAA,
		0x83, 0x3E, 0x50, 0x42, 0xA9, 0x52, 0xAE, 0x97,
		0xB2, 0x1B, 0x72, 0x93, 0x7C, 0xC7, 0x29, 0x5C,
		0x47, 0x2B, 0x70, 0xFB, 0xEC, 0xAC, 0xD9, 0x2C
	};
	static const uint8_t pers[] = {
		0x12, 0x6B, 0xE1, 0x49, 0x3F, 0x41, 0x28, 0x9A,
		0xDC, 0x5C, 0x7F, 0x00, 0x43, 0x40, 0xFF, 0x21,
		0xA7, 0xEC, 0x4D, 0xAD, 0xFF, 0xDA, 0x64, 0x2D,
		0xE4, 0x65, 0xAB, 0x2E, 0x98, 0x54, 0x19, 0x1A
	};
	static const uint8_t addtl1[] = {
		0x89, 0x18, 0x8A, 0xB5, 0x82, 0x0B, 0x05, 0x98,
		0xF9, 0x81, 0xB3, 0x34, 0x44, 0x6D, 0xD4, 0x38,
		0x29, 0xCD, 0x50, 0x4E, 0x06, 0xFE, 0x11, 0xF2,
		0x3C, 0x70, 0x0D, 0xAC, 0xA8, 0x28, 0x0E, 0x40
	};
	static const uint8_t addtl2[] = {
		0x67, 0x87, 0xEE, 0x02, 0xA6, 0x0F, 0x2F, 0x8D,
		0x8D, 0xF3, 0x4A, 0xBF, 0xA3, 0x61, 0x7E, 0xD6,
		0xB2, 0xB1, 0x37, 0x61, 0xA5, 0x41, 0xB3, 0x8C,
		0x2A, 0xF9, 0x01, 0x08, 0x3F, 0xC9, 0x0D, 0xCA
	};
	static const uint8_t exp[] = {
		0x4d, 0xa6, 0x34, 0x92, 0x52, 0x48, 0x31, 0x53,
		0x5c, 0x2d, 0xd8, 0xe9, 0xbd, 0x2f, 0x31, 0x9b,
		0x11, 0xc2, 0xda, 0x2f, 0xd7, 0x21, 0x05, 0xed,
		0x2c, 0x67, 0x04, 0x37, 0xbd, 0x53, 0xb3, 0x4e,
		0x9d, 0x0c, 0x16, 0x54, 0x89, 0xca, 0xe3, 0x39,
		0xc0, 0x77, 0xb3, 0xb5, 0xfa, 0xae, 0x9c, 0x59,
		0x90, 0x43, 0x09, 0x43, 0xf1, 0x4c, 0x70, 0x3e,
		0x00, 0x02, 0xa7, 0xf3, 0x13, 0x93, 0x98, 0xba,
		0x8b, 0xf4, 0xdf, 0x9e, 0x3f, 0x8d, 0x65, 0x0f,
		0x7a, 0x35, 0xd7, 0xa1, 0x4d, 0x13, 0x70, 0x50,
		0x01, 0xd8, 0x54, 0x26, 0x74, 0x2a, 0xdc, 0x35,
		0xb6, 0x59, 0xc2, 0xfb, 0x75, 0xfa, 0x47, 0x7c,
		0x06, 0x26, 0xfc, 0xcc, 0x20, 0xa0, 0x11, 0xc4,
		0xc4, 0xe8, 0xe5, 0x79, 0x33, 0x39, 0x30, 0x64,
		0xb3, 0x75, 0x7b, 0x2f, 0x04, 0x52, 0x0a, 0x60,
		0x41, 0x71, 0xcf, 0x3b, 0x1f, 0x30, 0x5b, 0x81,
		0x53, 0x2a, 0x26, 0xde, 0x3a, 0x4c, 0x5a, 0x64,
		0xe2, 0x29, 0x3e, 0x38, 0x8f, 0x8e, 0x1e, 0x76,
		0x08, 0xea, 0x81, 0x9e, 0x5d, 0x7b, 0x3a, 0xad,
		0x64, 0xc7, 0x1c, 0x32, 0x51, 0x9d, 0x67, 0xe3,
		0x75, 0x8f, 0x73, 0x23, 0x55, 0xbd, 0x1b, 0x70,
		0x9a, 0x8b, 0x8f, 0x5d, 0xcf, 0xe5, 0xac, 0x6d,
		0xc9, 0xf9, 0x48, 0xfc, 0xeb, 0xd6, 0x3a, 0x37,
		0x01, 0x4e, 0x6a, 0xae, 0x7b, 0x83, 0xf5, 0x13,
		0x22, 0x97, 0x2b, 0xc8, 0xd0, 0x9d, 0xd4, 0x91,
		0x18, 0xa1, 0x4b, 0x36, 0xf3, 0x0d, 0x3f, 0x4e,
		0x6d, 0x96, 0x8d, 0x79, 0xd8, 0xd7, 0xf0, 0x31,
		0x57, 0xf8, 0x32, 0x93, 0x10, 0xf6, 0xba, 0xab,
		0x57, 0xa6, 0xec, 0xb8, 0xbc, 0x9b, 0x0b, 0xef,
		0xa5, 0x00, 0x78, 0x7f, 0x63, 0x3e, 0x0f, 0x45,
		0x3b, 0x6d, 0xd9, 0xea, 0x58, 0xee, 0x29, 0x48,
		0xad, 0x33, 0xcb, 0x1b, 0xbf, 0xd1, 0x1d, 0x2a
	};
	uint8_t act[256];
	LC_DRBG_HASH_CTX_ON_STACK(drbg_stack);
	struct lc_drbg_state *drbg = NULL;
	int ret = 0;

	printf("hash DRBG ctx len %lu\n",
	       LC_DRBG_HASH_CTX_SIZE(LC_DRBG_HASH_CORE));
	if (lc_drbg_healthcheck_sanity(drbg_stack))
		return 1;

	if (lc_drbg_seed(drbg_stack, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl1, 32, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl2, 32, act, 256) < 0)
		goto out;

	ret += compare(act, exp, 256, "Hash DRBG SHA-512");

	lc_drbg_zero(drbg_stack);

	/* Rerun to verify that drbg_zero works properly */
	if (lc_drbg_seed(drbg_stack, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl1, 32, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl2, 32, act, 256) < 0)
		goto out;

	ret += compare(act, exp, 256, "Hash DRBG SHA-512");

	lc_drbg_zero(drbg_stack);

	if (lc_drbg_hash_alloc(&drbg))
		goto out;

	if (lc_drbg_seed(drbg, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg, addtl1, 32, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg, addtl2, 32, act, 256) < 0)
		goto out;
#endif
#if 0
	static const uint8_t ent_nonce[] = {
		0x76, 0xE6, 0xE0, 0xC1, 0x11, 0x9D, 0xDD, 0x8C,
		0x2A, 0x09, 0x14, 0x86, 0x68, 0x65, 0xAE, 0xEA,
		0xF9, 0x63, 0x36, 0x39, 0xFD, 0xDF, 0x76, 0x0B,
		0x0F, 0x83, 0xBF, 0x6A, 0x12, 0xAE, 0x62, 0xD9,
		0x2A, 0x4D, 0x72, 0x21, 0x8C, 0x85, 0x83, 0x59,
		0xC5, 0x91, 0xE6, 0x77, 0xDF, 0xAC, 0x4A, 0x88,
		0x8C, 0xF9, 0xE3, 0x13, 0xCA, 0x19, 0x00, 0x73,
		0xD8, 0x3A, 0xEB, 0x59, 0x76, 0x4C, 0x8D, 0x60
	};
	static const uint8_t pers[] = {
		0x01, 0xB7, 0xAD, 0x65, 0xD5, 0x1C, 0x87, 0xFB,
		0x79, 0xFE, 0x07, 0x33, 0x77, 0x88, 0x11, 0xE4,
		0xA9, 0x17, 0x3F, 0xFA, 0x85, 0xF5, 0x8C, 0x73,
		0xFE, 0xA0, 0xED, 0xEA, 0xAC, 0x9D, 0x69, 0x8F
	};
	static const uint8_t exp[] = {
		0x06, 0x85, 0xc5, 0x6f, 0x25, 0x83, 0xa0, 0xe6,
		0x06, 0x34, 0xa6, 0x75, 0x15, 0x2e, 0xf8, 0xe2,
		0x7c, 0xae, 0xc4, 0x95, 0xfb, 0x08, 0x92, 0x26,
		0x35, 0xd5, 0xec, 0x43, 0x9b, 0x88, 0x4a, 0x2c,
		0x1a, 0x51, 0x9d, 0x3b, 0x45, 0x74, 0xc4, 0x20,
		0x11, 0x98, 0xf6, 0xd5, 0x1d, 0x05, 0xd7, 0xf2,
		0x7a, 0xf6, 0x64, 0x0f, 0xbe, 0x28, 0x63, 0x2f,
		0x91, 0x6a, 0x37, 0x38, 0x83, 0xb4, 0x79, 0x54,
		0x5c, 0x29, 0x4b, 0x40, 0x38, 0x82, 0xa6, 0xb8,
		0x3b, 0x7a, 0xa0, 0xb4, 0xb5, 0x12, 0x69, 0xfc,
		0x1f, 0xa7, 0xc4, 0x54, 0xfc, 0x45, 0xf4, 0x35,
		0x41, 0x40, 0x2d, 0x3d, 0x91, 0xb2, 0x06, 0xf0,
		0xef, 0xd7, 0x56, 0x7a, 0x43, 0x39, 0x31, 0x03,
		0x8b, 0x84, 0xb7, 0x70, 0x6a, 0x6c, 0x6c, 0x7a,
		0x0b, 0x82, 0x93, 0x09, 0xb4, 0x1a, 0xfb, 0x67,
		0xdd, 0x3d, 0x04, 0x9e, 0x28, 0x36, 0x2b, 0xd7,
		0x47, 0x70, 0x61, 0x87, 0x99, 0xb3, 0xf0, 0xa0,
		0x8a, 0x1e, 0xb8, 0x5a, 0x19, 0xc3, 0xbc, 0xfd,
		0x3d, 0x5d, 0x6c, 0x72, 0xf7, 0x37, 0x38, 0xe6,
		0xc6, 0xaf, 0x8b, 0xe4, 0x12, 0x71, 0x91, 0xb3,
		0xa4, 0xae, 0x37, 0xc8, 0x0f, 0xa4, 0x2d, 0x71,
		0x0e, 0xcc, 0x03, 0x51, 0xcd, 0x09, 0x6b, 0x4e,
		0xee, 0x22, 0xf0, 0xc3, 0x62, 0x73, 0x3a, 0x2b,
		0x3c, 0x88, 0xac, 0xbd, 0x08, 0xfe, 0x93, 0x80,
		0x61, 0x86, 0x10, 0xe4, 0x30, 0x5a, 0x11, 0x79,
		0x03, 0x65, 0x21, 0x7c, 0xfb, 0xc6, 0x1f, 0x00,
		0x5c, 0xf5, 0x5f, 0x1d, 0x90, 0xc8, 0x30, 0x31,
		0xb3, 0x93, 0x10, 0x76, 0x24, 0x21, 0xc6, 0xa6,
		0xdb, 0x25, 0x4a, 0xf9, 0xb7, 0xd8, 0x98, 0x7c,
		0xc2, 0xaa, 0xab, 0xd9, 0xb6, 0x15, 0x2c, 0xc7,
		0x79, 0x76, 0x7e, 0x27, 0x52, 0xa0, 0xe4, 0x76,
		0x90, 0xff, 0xcc, 0xd9, 0x4e, 0x07, 0xa7, 0x80
	};
	uint8_t act[256];
	struct lc_drbg_state *drbg;
	int ret = 1;

	if (lc_drbg_alloc(&drbg))
		goto out;

	if (lc_drbg_seed(drbg, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg, NULL, 0, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg, NULL, 0, act, 256) < 0)
		goto out;
#endif
#if 0
	static const uint8_t ent_nonce[] = {
		0x39, 0x67, 0x0A, 0xDC, 0x7C, 0xE4, 0xF8, 0x81,
		0x9B, 0xBA, 0xBB, 0x4E, 0x52, 0x60, 0xBC, 0xB5,
		0x2D, 0x1B, 0xE8, 0x71, 0x1F, 0x17, 0x50, 0x4F,
		0x42, 0xFF, 0x73, 0xE4, 0x30, 0x80, 0x27, 0x01,
		0x45, 0x66, 0x82, 0x8E, 0xEC, 0xAF, 0xE5, 0x6C,
		0x46, 0x2A, 0x40, 0x4F, 0x06, 0x6C, 0xE2, 0x5E,
		0xAC, 0xFE, 0xAC, 0xED, 0x34, 0x5E, 0x8A, 0xD9,
		0xE2, 0x94, 0x1E, 0x03, 0xDF, 0xA2, 0x42, 0x31
	};

	static const uint8_t exp[] = {
		0x6b, 0x94, 0x47, 0x0b, 0x8b, 0xbc, 0x4a, 0x47,
		0xf9, 0xfe, 0x12, 0x60, 0x91, 0x37, 0x23, 0xd0,
		0xda, 0xbf, 0x3e, 0x53, 0x4e, 0x1b, 0xaa, 0xeb,
		0xa5, 0x8a, 0x1d, 0x25, 0x26, 0x77, 0x67, 0x51,
		0x9c, 0x8c, 0x41, 0x36, 0xf8, 0x52, 0xad, 0x5b,
		0x9e, 0xe3, 0x23, 0x5b, 0x13, 0x62, 0x48, 0x87,
		0x0f, 0x43, 0x42, 0x69, 0xea, 0x6c, 0x2d, 0xc7,
		0x78, 0x33, 0xa4, 0xfc, 0x5d, 0xe1, 0xac, 0x20,
		0x8f, 0x57, 0x9c, 0x95, 0x5e, 0xa1, 0x09, 0xae,
		0x3b, 0x6a, 0xc0, 0x0b, 0x25, 0xe7, 0x28, 0x81,
		0x10, 0xfb, 0x37, 0xd7, 0x2b, 0x3a, 0xe7, 0x07,
		0xff, 0xe6, 0x55, 0xa7, 0x20, 0xb9, 0x5e, 0x07,
		0x71, 0xdd, 0xb3, 0x30, 0x60, 0x66, 0x9a, 0x22,
		0xf9, 0x7a, 0xa0, 0x66, 0xd0, 0x7e, 0xed, 0xa3,
		0x99, 0xc6, 0xb3, 0xcd, 0x7e, 0xa2, 0xa2, 0xfc,
		0x4a, 0x5d, 0xf6, 0xf7, 0x39, 0xed, 0x23, 0x7e,
		0xd7, 0xab, 0xa0, 0xf5, 0xd1, 0xfd, 0x65, 0x45,
		0x2e, 0x00, 0x5b, 0xa9, 0x8a, 0xba, 0x23, 0xf1,
		0xf0, 0x02, 0x7d, 0xde, 0xc9, 0x6a, 0x72, 0x9a,
		0xe4, 0x4a, 0x32, 0x3b, 0xce, 0x1d, 0x2f, 0x30,
		0xa1, 0xee, 0x85, 0x6c, 0x44, 0xd7, 0x7f, 0x30,
		0xa7, 0x24, 0xdc, 0x13, 0xf6, 0x02, 0x49, 0xe3,
		0xaf, 0xe0, 0x86, 0xe4, 0x97, 0xb6, 0x1e, 0x32,
		0x09, 0xd2, 0xf9, 0x5f, 0x24, 0x24, 0x24, 0x3f,
		0xf3, 0xa6, 0x59, 0xb1, 0xd6, 0x65, 0xcd, 0x46,
		0x76, 0xdd, 0x26, 0x92, 0x5d, 0xf2, 0x46, 0xd7,
		0x30, 0x57, 0x67, 0x03, 0x69, 0x43, 0xdc, 0x26,
		0xc3, 0x87, 0xb3, 0x39, 0x30, 0x9c, 0xea, 0x27,
		0x36, 0x79, 0xfa, 0x30, 0x6a, 0xf1, 0xe1, 0x93,
		0xce, 0xc2, 0x5e, 0x31, 0xeb, 0x18, 0xaa, 0xb0,
		0x55, 0xbe, 0x21, 0xaf, 0x82, 0xc9, 0x61, 0x92,
		0xad, 0xcb, 0x66, 0xeb, 0xa2, 0xc1, 0xe9, 0x7d
	};
	uint8_t act[256];
	struct lc_drbg_state *drbg;
	int ret = 1;

	if (lc_drbg_alloc(&drbg))
		goto out;

	if (lc_drbg_seed(drbg, ent_nonce, 64, NULL, 0))
		goto out;

	if (lc_drbg_generate(drbg, NULL, 0, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg, NULL, 0, act, 256) < 0)
		goto out;
#endif

	ret += compare(act, exp, 256, "Hash DRBG SHA-512");

out:
	lc_drbg_zero_free(drbg);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hash_drbg_tester();
}
