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
#include "lc_hash_drbg_sha3_512.h"

static int hash_sha3_drbg_tester(void)
{
	static const uint8_t ent_nonce[] = {
		0x9E, 0x28, 0x52, 0xF1, 0xD8, 0xB2, 0x3C, 0x1A, 0x80, 0xCA,
		0x75, 0x29, 0x37, 0xAC, 0x58, 0x54, 0x61, 0x98, 0xDB, 0x72,
		0x81, 0xB7, 0x43, 0xDB, 0x37, 0x21, 0x8E, 0x86, 0x40, 0x3B,
		0x74, 0xF9, 0x88, 0x45, 0x49, 0xDC, 0x49, 0x26, 0xBB, 0xAA,
		0x83, 0x3E, 0x50, 0x42, 0xA9, 0x52, 0xAE, 0x97, 0xB2, 0x1B,
		0x72, 0x93, 0x7C, 0xC7, 0x29, 0x5C, 0x47, 0x2B, 0x70, 0xFB,
		0xEC, 0xAC, 0xD9, 0x2C
	};
	static const uint8_t pers[] = { 0x12, 0x6B, 0xE1, 0x49, 0x3F, 0x41,
					0x28, 0x9A, 0xDC, 0x5C, 0x7F, 0x00,
					0x43, 0x40, 0xFF, 0x21, 0xA7, 0xEC,
					0x4D, 0xAD, 0xFF, 0xDA, 0x64, 0x2D,
					0xE4, 0x65, 0xAB, 0x2E, 0x98, 0x54,
					0x19, 0x1A };
	static const uint8_t addtl1[] = { 0x89, 0x18, 0x8A, 0xB5, 0x82, 0x0B,
					  0x05, 0x98, 0xF9, 0x81, 0xB3, 0x34,
					  0x44, 0x6D, 0xD4, 0x38, 0x29, 0xCD,
					  0x50, 0x4E, 0x06, 0xFE, 0x11, 0xF2,
					  0x3C, 0x70, 0x0D, 0xAC, 0xA8, 0x28,
					  0x0E, 0x40 };
	static const uint8_t addtl2[] = { 0x67, 0x87, 0xEE, 0x02, 0xA6, 0x0F,
					  0x2F, 0x8D, 0x8D, 0xF3, 0x4A, 0xBF,
					  0xA3, 0x61, 0x7E, 0xD6, 0xB2, 0xB1,
					  0x37, 0x61, 0xA5, 0x41, 0xB3, 0x8C,
					  0x2A, 0xF9, 0x01, 0x08, 0x3F, 0xC9,
					  0x0D, 0xCA };
	static const uint8_t exp[] = {
		0xe0, 0x13, 0x4b, 0xb3, 0xe0, 0xbc, 0x0e, 0xd8, 0x13, 0x03,
		0xcb, 0x50, 0x61, 0x3d, 0xd9, 0x82, 0xca, 0x97, 0x5a, 0x6c,
		0x47, 0xfc, 0x4e, 0x89, 0xd5, 0x54, 0x64, 0xc0, 0x36, 0x0e,
		0x58, 0xe0, 0x20, 0xeb, 0x3d, 0x45, 0x3e, 0x98, 0x0a, 0x8e,
		0x89, 0x34, 0x15, 0x78, 0x37, 0x2d, 0x88, 0xff, 0xc6, 0x49,
		0x14, 0x4d, 0xd9, 0x80, 0x4d, 0x60, 0x8a, 0x1f, 0xdd, 0x02,
		0x5d, 0xb3, 0xd7, 0xa0, 0xba, 0x3b, 0xdd, 0x86, 0x45, 0xd4,
		0x5a, 0xf6, 0x20, 0x89, 0x04, 0xb4, 0x62, 0x7f, 0x2f, 0xec,
		0x83, 0xb4, 0xe3, 0x6f, 0xf9, 0x5f, 0x6d, 0x8d, 0x3b, 0xf5,
		0xf2, 0x5d, 0x5f, 0x1e, 0xb0, 0x38, 0x68, 0xf9, 0xc0, 0xab,
		0x97, 0x9a, 0x3b, 0x03, 0x40, 0xbc, 0xf6, 0xcd, 0xde, 0xfb,
		0xa2, 0x46, 0x16, 0x43, 0x60, 0x4e, 0x7c, 0x77, 0xde, 0xf9,
		0xe7, 0xf6, 0x64, 0x26, 0x52, 0x74, 0x76, 0xb9, 0x5f, 0x8e,
		0x8b, 0xac, 0xca, 0x4c, 0x32, 0x4e, 0x98, 0xa7, 0xc1, 0x9c,
		0x5a, 0xa4, 0x01, 0x60, 0x64, 0x18, 0x19, 0x95, 0x11, 0xaf,
		0x21, 0x78, 0x75, 0x7b, 0x83, 0x94, 0x56, 0x2d, 0x6c, 0x23,
		0xdf, 0x68, 0x13, 0x7b, 0x19, 0x71, 0x03, 0xaa, 0xeb, 0xd3,
		0xbc, 0x08, 0x66, 0x2f, 0x9d, 0x13, 0x79, 0x59, 0x4b, 0x32,
		0x4f, 0xcc, 0x84, 0xae, 0xb9, 0x10, 0x73, 0x54, 0x4e, 0x6c,
		0xa9, 0x0f, 0xc3, 0xda, 0x86, 0xae, 0xc6, 0x1a, 0xa2, 0x3e,
		0x50, 0x36, 0xc2, 0xf4, 0x51, 0x64, 0xec, 0xc2, 0xa6, 0x95,
		0x95, 0xeb, 0xd8, 0x60, 0x8e, 0xb3, 0x85, 0x3a, 0x4a, 0x06,
		0xb2, 0x47, 0xd0, 0xc6, 0x57, 0x4b, 0xb1, 0x31, 0x85, 0xe4,
		0xbf, 0x57, 0xda, 0xc1, 0xfa, 0xc4, 0xdc, 0xce, 0x1d, 0x56,
		0x83, 0xab, 0x31, 0x72, 0xf5, 0xbe, 0x72, 0x17, 0x57, 0x40,
		0x42, 0x31, 0x9d, 0x7f, 0xf5, 0x02
	};
	uint8_t act[256];
	LC_DRBG_HASH_CTX_ON_STACK(drbg_stack);
	struct lc_drbg_state *drbg = NULL;
	int ret = 0;

	printf("hash DRBG SHA3-512 ctx len %lu\n", LC_DRBG_HASH_MAX_CTX_SIZE);
	if (lc_drbg_healthcheck_sanity(drbg_stack))
		return 1;

	if (lc_drbg_seed(drbg_stack, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl1, 32, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl2, 32, act, 256) < 0)
		goto out;

	ret += compare(act, exp, 256, "Hash DRBG SHA3-512");

	lc_drbg_zero(drbg_stack);

	/* Rerun to verify that drbg_zero works properly */
	if (lc_drbg_seed(drbg_stack, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl1, 32, act, 256) < 0)
		goto out;

	if (lc_drbg_generate(drbg_stack, addtl2, 32, act, 256) < 0)
		goto out;

	ret += compare(act, exp, 256, "Hash DRBG SHA3-512");

	lc_drbg_zero(drbg_stack);

#if 0
	/*
	 * Using the allocation function, the SHA-512 DRBG is allocated
	 * due to the included header file into the drbg.c file. Thus, we do not
	 * test this
	 */
	if (lc_drbg_alloc(&drbg))
		goto out;

	if (lc_drbg_seed(drbg, ent_nonce, 64, pers, 32))
		goto out;

	if (lc_drbg_generate(drbg, act, 256, addtl1, 32) < 0)
		goto out;

	if (lc_drbg_generate(drbg, act, 256, addtl2, 32) < 0)
		goto out;

	ret += compare(act, exp, 256, "Hash DRBG SHA-512");
#endif

out:
	lc_drbg_zero_free(drbg);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hash_sha3_drbg_tester();
}
