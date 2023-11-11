/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#include "ed25519.h"
#include "compare.h"
#include "selftest_rng.h"
#include "ret_checkers.h"
#include "visibility.h"

/* Test vector obtained from NIST ACVP demo server */
static int ed25519_sigver_pos_tester(void)
{
	static const struct lc_ed25519_pk pk = {
		.pk = { 0xDE, 0xE0, 0x76, 0xAD, 0x68, 0xDC, 0x56, 0x56,
			0xAA, 0x3E, 0xF7, 0x93, 0x37, 0xFD, 0xFD, 0x3E,
			0x4F, 0x8D, 0xB9, 0x4A, 0xFF, 0xEE, 0xF4, 0xEA,
			0xDA, 0xA8, 0x08, 0x1D, 0x00, 0x6E, 0x5A, 0xC0 }
	};
	static const struct lc_ed25519_sig sig = {
		.sig = { 0x9F, 0xB9, 0x57, 0x68, 0xE6, 0x87, 0x91, 0xFC,
			 0xD6, 0x04, 0xF0, 0x68, 0x5F, 0x57, 0xC4, 0x33,
			 0xEF, 0xBE, 0x0A, 0xE6, 0x6F, 0x89, 0x90, 0xA1,
			 0xB1, 0xFF, 0x62, 0xA2, 0x50, 0x7F, 0xB2, 0xA0,
			 0xEA, 0xB7, 0x6C, 0xDD, 0x37, 0x3B, 0x9C, 0x20,
			 0x5E, 0x15, 0x63, 0xF4, 0xA9, 0xAE, 0xCB, 0x25,
			 0x61, 0xDF, 0xAD, 0x89, 0x61, 0xC5, 0x73, 0xB8,
			 0xC8, 0x34, 0x24, 0xF6, 0x47, 0x56, 0x79, 0x08 }
	};
	static const uint8_t msg[] = {
		0xA6, 0x3D, 0xEB, 0x88, 0x01, 0x0E, 0xFD, 0x0B, 0x43, 0x92,
		0x48, 0x38, 0x12, 0xF5, 0x03, 0xA9, 0xD1, 0x99, 0xA9, 0xCF,
		0xA7, 0x08, 0x5F, 0x68, 0x31, 0xFE, 0xE3, 0x21, 0xA9, 0x28,
		0x46, 0x8E, 0x55, 0x74, 0x26, 0x7E, 0xB2, 0xBD, 0x9C, 0xB8,
		0x1E, 0xD3, 0x7A, 0x88, 0xF2, 0x18, 0x0D, 0x8D, 0x6A, 0x07,
		0xD9, 0xC5, 0x87, 0xFF, 0xB1, 0xCD, 0xBB, 0x9E, 0x46, 0x9D,
		0xC6, 0x1C, 0xDE, 0xBE, 0x1A, 0x3A, 0x51, 0x1F, 0x82, 0x6E,
		0xB0, 0xAA, 0x5F, 0x30, 0xCF, 0x58, 0xD5, 0x1B, 0x06, 0x77,
		0x9C, 0xAA, 0x3D, 0x88, 0xE6, 0x61, 0xC9, 0xA6, 0x94, 0xA9,
		0xEC, 0x63, 0x68, 0xFB, 0xE9, 0xEE, 0x2C, 0x4F, 0xA3, 0xF9,
		0x8F, 0xAA, 0x38, 0xA7, 0x8F, 0xBF, 0x26, 0x50, 0xA6, 0x45,
		0x76, 0xA7, 0x01, 0xAE, 0x99, 0xB0, 0x0A, 0x0A, 0x0D, 0xBE,
		0x34, 0xE1, 0xC9, 0xBB, 0x15, 0x40, 0x6A, 0x86
	};
	int ret = !!lc_ed25519_verify(&sig, msg, sizeof(msg), &pk);

	return ret;
}

/* Test vector obtained from NIST ACVP demo server */
static int ed25519_sigver_neg_tester(void)
{
	static const struct lc_ed25519_pk pk = {
		.pk = { 0xDB, 0x33, 0xBA, 0x2C, 0x95, 0xFF, 0x40, 0xC9,
			0xB5, 0x70, 0xD6, 0x5B, 0xEE, 0x72, 0x56, 0x80,
			0xC3, 0xF1, 0x35, 0x4B, 0xA7, 0x69, 0xAA, 0x31,
			0x0A, 0x50, 0x9F, 0x31, 0x58, 0x33, 0xF6, 0xEB }
	};
	static const struct lc_ed25519_sig sig = {
		.sig = { 0x9D, 0xA5, 0xB6, 0xFD, 0x56, 0xFF, 0xE6, 0x00,
			 0x13, 0xE6, 0xD8, 0x0A, 0xF5, 0x04, 0xC2, 0x3C,
			 0x8A, 0x2F, 0x80, 0x36, 0x42, 0x3E, 0xBC, 0x9F,
			 0x9B, 0xF3, 0x75, 0x95, 0x5E, 0x2F, 0x77, 0x52,
			 0x06, 0x7D, 0x05, 0xD0, 0x08, 0xE2, 0xDC, 0xF5,
			 0xF5, 0xE9, 0xC1, 0x50, 0x3C, 0x20, 0x5D, 0xC1,
			 0xC8, 0x0B, 0x32, 0xCC, 0x6F, 0x07, 0x83, 0xDE,
			 0x7C, 0x2C, 0x06, 0x08, 0x32, 0x5F, 0x1C, 0xBE }
	};
	static const uint8_t msg[] = {
		0x11, 0xE4, 0x0B, 0xC1, 0x65, 0xA5, 0xBD, 0x4E, 0x87, 0xA9,
		0xDD, 0xE7, 0xE4, 0xB2, 0x75, 0x22, 0x46, 0x80, 0xF5, 0x53,
		0xF4, 0x7D, 0x25, 0xAA, 0x9F, 0x35, 0x11, 0x81, 0xB1, 0xF3,
		0x17, 0x09, 0x4C, 0x2F, 0x47, 0xDC, 0x37, 0xC2, 0x93, 0x7B,
		0xC1, 0xF1, 0xC0, 0xBD, 0x3B, 0x9D, 0xD2, 0x1F, 0x09, 0xA4,
		0x0B, 0x9E, 0xB4, 0x9F, 0x7B, 0x58, 0xC1, 0x43, 0x83, 0xF8,
		0x20, 0x7E, 0x3F, 0x47, 0x67, 0x18, 0x84, 0xB6, 0xD2, 0x7F,
		0xC6, 0x52, 0x1E, 0xA9, 0xF2, 0x6F, 0xD6, 0xE6, 0xED, 0x23,
		0x2E, 0x32, 0x00, 0xF0, 0x3B, 0x7E, 0x22, 0xD1, 0xE6, 0x19,
		0x5B, 0xFE, 0x15, 0xB2, 0x24, 0xB4, 0x60, 0x96, 0xA4, 0x29,
		0xC1, 0x00, 0x52, 0x09, 0x95, 0x47, 0x1D, 0xD6, 0x71, 0x61,
		0x71, 0x1C, 0x41, 0x99, 0xAA, 0x45, 0x33, 0xA0, 0xDE, 0x0B,
		0x42, 0x46, 0xB6, 0x24, 0x88, 0x5C, 0x9A, 0x3C
	};
	int ret = lc_ed25519_verify(&sig, msg, sizeof(msg), &pk);

	if (ret != -EINVAL && ret != -EBADMSG)
		return 1;

	return 0;
}

/* Test vector generated with libsodium using the ACVP parser tool */
static int ed25519_siggen_tester(void)
{
	static const struct lc_ed25519_sk sk = {
		.sk = { 0x42, 0x58, 0x0d, 0x49, 0xbe, 0x95, 0x1f, 0x95,
			0xdf, 0xca, 0x13, 0x60, 0xda, 0x43, 0x09, 0x58,
			0xd9, 0x30, 0xc7, 0xa1, 0x71, 0xbd, 0xa0, 0x99,
			0x92, 0x5a, 0xb5, 0xb7, 0xcd, 0x88, 0x51, 0xae,
			0x5d, 0x10, 0xd0, 0x95, 0x66, 0xa2, 0xd8, 0x75,
			0xea, 0xcf, 0xa0, 0x87, 0x73, 0x9a, 0xcd, 0xb9,
			0x5c, 0xfb, 0xfa, 0x94, 0x05, 0x5a, 0x14, 0xd7,
			0x59, 0x0b, 0xd4, 0xb1, 0x06, 0xe8, 0x09, 0xbd }
	};
	static const struct lc_ed25519_sig exp_sig = {
		.sig = { 0xb6, 0x53, 0xe0, 0x0b, 0xf2, 0x07, 0xd1, 0x83,
			 0xdd, 0x7b, 0xef, 0x59, 0xaa, 0x7b, 0x23, 0xb5,
			 0xfe, 0x76, 0x9c, 0x2a, 0x6b, 0xf2, 0x10, 0xd6,
			 0xa7, 0xa2, 0x17, 0xf2, 0xb1, 0xa5, 0x5d, 0xd6,
			 0x92, 0xdf, 0xec, 0x22, 0xf0, 0x18, 0xac, 0x7f,
			 0x21, 0x9c, 0xe1, 0xb8, 0x74, 0x30, 0x9d, 0xe9,
			 0xa4, 0x2d, 0x1b, 0x89, 0x1c, 0xb3, 0xb9, 0x47,
			 0xb8, 0xc6, 0xbb, 0xd4, 0xcf, 0xb7, 0xa4, 0x0b }
	};
	static const uint8_t msg[] = {
		0x67, 0xB1, 0x9B, 0xA7, 0x05, 0xCF, 0xEE, 0x74, 0x82, 0x10,
		0xCC, 0xB6, 0x98, 0xFF, 0x84, 0xBC, 0x8C, 0x59, 0x8E, 0x45,
		0x26, 0x2C, 0x39, 0xDF, 0xB7, 0x8B, 0xAA, 0x9A, 0x4E, 0xA9,
		0x6C, 0x83, 0x46, 0x65, 0x84, 0x92, 0x7E, 0xD2, 0x90, 0xB3,
		0x9E, 0x80, 0x18, 0xC8, 0x4B, 0xEB, 0x84, 0x24, 0x82, 0x00,
		0x83, 0x2F, 0xC4, 0x69, 0xE1, 0xEC, 0x44, 0x19, 0x7A, 0x96,
		0x82, 0x8C, 0xF4, 0x9B, 0xD9, 0x18, 0xA2, 0x1D, 0x24, 0x07,
		0xBC, 0x0F, 0x89, 0x53, 0xAE, 0x07, 0x18, 0x7D, 0xF9, 0x31,
		0x21, 0x2D, 0x26, 0x43, 0x45, 0x46, 0x9B, 0xE9, 0x82, 0xA8,
		0x99, 0x3A, 0xE2, 0x19, 0x06, 0x4C, 0x87, 0x31, 0x46, 0x44,
		0x1D, 0xA5, 0x51, 0xA9, 0x43, 0xC8, 0x75, 0x60, 0x52, 0x63,
		0x94, 0xDD, 0x54, 0x5C, 0xAF, 0x88, 0xD9, 0x7C, 0xCD, 0x1F,
		0x5D, 0xC0, 0xC3, 0x76, 0xB0, 0x00, 0xD7, 0xFE
	};
	struct lc_ed25519_sig sig;
	int ret;

	CKINT(lc_ed25519_sign(&sig, msg, sizeof(msg), &sk, NULL));
	lc_compare(sig.sig, exp_sig.sig, sizeof(exp_sig.sig),
		   "ED25519 Signature generation failed\n");

out:
	return ret;
}

static int ed25519_pwc_tester(void)
{
	struct lc_ed25519_pk pk;
	struct lc_ed25519_sk sk;
	struct lc_ed25519_sig sig;
	int ret;
	const uint8_t msg[] = { 0x01, 0x02, 0x03 };
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	CKINT(lc_ed25519_keypair(&pk, &sk, selftest_rng));
	CKINT(lc_ed25519_sign(&sig, msg, sizeof(msg), &sk, selftest_rng));
	CKINT(lc_ed25519_verify(&sig, msg, sizeof(msg), &pk));

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	ret += ed25519_pwc_tester();
	ret += ed25519_sigver_pos_tester();
	ret += ed25519_sigver_neg_tester();
	ret += ed25519_siggen_tester();

	return ret;
}
