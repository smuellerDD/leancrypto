/*
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "lc_sha512.h"
#include "visibility.h"

static int hmac_sha2_512_tester(void)
{
	static const uint8_t msg_512[] = {
		0x32, 0x9D, 0x57, 0x59, 0xEC, 0x2B, 0x51, 0xB6,
		0x1F, 0xE2, 0x79, 0x18, 0xE9, 0x8F, 0xA7, 0x2D
	};
	static const uint8_t key_512[] = {
		0x6F, 0xD3, 0xFB, 0x41, 0xE3, 0xC3, 0x00, 0x8C,
		0x1E, 0x9E, 0x70, 0xBB, 0xF9, 0x5E, 0x65, 0x37,
		0x25, 0x63, 0x28, 0x46, 0xE4, 0x04, 0x20, 0xC9,
		0x8E, 0x71, 0x5C, 0xA8, 0x5D, 0x48, 0xAB, 0x07,
		0x06, 0x86, 0x0F, 0xD3, 0x1A, 0x6D, 0x38, 0x5B,
		0xE3, 0x3C, 0x5D, 0x0C, 0xF4, 0xE0, 0x27, 0x7B,
		0x8A, 0xD6, 0x61, 0x95, 0x96, 0xAE, 0xB3, 0x7E,
		0xA6, 0x15, 0xAF, 0x1B, 0x1E, 0xE4, 0xC8, 0x7C,
		0xAB, 0x65, 0x9C, 0x21, 0xDA, 0xEF, 0x0E, 0x87,
		0xF9, 0xBF, 0xF4, 0x98, 0x82, 0xC6, 0xDE, 0x3D,
		0x8D, 0x7B, 0x8C, 0x26, 0xC4, 0x56, 0x6C, 0xA3,
		0xA7, 0xE9, 0xC2, 0x28, 0xF5, 0x31, 0x1B, 0xD8,
		0xD4, 0xE0, 0xD3, 0xD3, 0x1E, 0xB4, 0xF7, 0x16,
		0xFD, 0x26, 0xEC, 0x03, 0x51, 0x5B, 0x68, 0x69,
		0x3E, 0xA4, 0x4D, 0x3A, 0xBC, 0x9D, 0x5C, 0x7F,
		0x38, 0xBA, 0xD5, 0xD1, 0x06, 0x0B, 0xAE, 0xE5,
		0xC2, 0x46, 0xF4, 0xEA, 0x30, 0x1C, 0xE2, 0xDA,
		0xB5, 0x49, 0xC3, 0x21, 0xD6, 0xA5, 0x5E, 0x7D,
		0xBA, 0xC9, 0x34, 0xA3, 0x17, 0xDE, 0x1F, 0xC8,
		0xCB, 0x04, 0xF0, 0x01, 0x8F, 0xAC, 0x5F, 0xC1,
		0x48, 0xC2, 0xA8, 0xB0, 0xD8, 0x22, 0x32, 0x72,
		0x48, 0x64, 0x18, 0xDC, 0x66, 0x28, 0x83, 0x29,
		0xBB, 0x65, 0x7D, 0x66, 0xCC, 0xF6, 0xA7, 0x6B,
		0xF6, 0xCC, 0x0D, 0x62, 0x8F, 0x2A, 0x3F, 0xCE,
		0x25, 0x2A, 0x49, 0x59, 0xCE, 0x1A, 0xE2, 0x38,
		0x2F, 0x01, 0x99, 0xBE, 0x49, 0x16, 0x95, 0xD8,
		0x66, 0x80, 0x2B, 0xCE, 0x7A, 0x85, 0xEB, 0x91,
		0x1B, 0x77, 0xCA, 0xBB, 0x5A, 0x61, 0x74, 0xE2,
		0x23, 0x62, 0xF2, 0xFC, 0x00, 0xEA, 0xAA, 0xE7,
		0x33, 0xF8, 0xEB, 0xB8, 0x88, 0xC3, 0xE2, 0xC1,
		0x88, 0x67, 0xC4, 0x04, 0x0C, 0x62, 0x30, 0x17,
		0x26, 0x4A, 0x43, 0x79, 0x02, 0x16, 0x30, 0x1B,
		0xB9, 0x21, 0x82, 0x2C, 0xD7, 0x1E, 0x40, 0x2B,
		0x85, 0x38, 0x31, 0xAB, 0x9D, 0x11, 0xDC, 0x5E,
		0xF0, 0xCC, 0xD1, 0x8A, 0x7C, 0x2E, 0x03, 0xA5,
		0x8F, 0xC9, 0x1A, 0x41, 0x15, 0x2F, 0x20, 0x64,
		0xA3, 0x89, 0xC9, 0x64, 0x22, 0xD3, 0x8E, 0x59,
		0xF2, 0x41, 0x32, 0x10, 0x08, 0xBF, 0xE1, 0x40,
		0x8C, 0x59, 0xA8, 0x23, 0x7B, 0xD4, 0xA4, 0x83,
		0x86, 0xA4, 0x00, 0x65, 0x77, 0x33, 0x6D, 0xB7,
		0x49, 0x39, 0x6B, 0x7F, 0x51, 0x68, 0xB8, 0x98,
		0xEF, 0x4D, 0x5F, 0x21, 0xB1, 0x8A, 0x49, 0x8F,
		0x2F, 0x92, 0x75, 0x83, 0xE7, 0x6A, 0x9E, 0x0E,
		0x08, 0x1A, 0xCD, 0xDA, 0x6C, 0x7D, 0xA7, 0x52,
		0x63, 0xE4, 0x9B, 0x51, 0x4F, 0x11, 0xD2, 0x02,
		0xDC, 0x8F, 0x8D, 0x19, 0xE3, 0xAC, 0x9D, 0x53,
		0x7E, 0x6C, 0xE3, 0x1F, 0x86, 0xD0, 0x9C, 0xE4,
		0x8B, 0xBA, 0x90, 0x23, 0x6A, 0x95, 0x28, 0x7D,
		0x66, 0x42, 0xCE, 0x4F, 0xDD, 0xC8, 0xFC, 0x12,
		0xB1, 0xFB, 0x53, 0x83, 0x4F, 0x29, 0xC9, 0x98,
		0x3E, 0x38, 0x6F, 0x95, 0xFB, 0x0D, 0x94, 0x31,
		0x33, 0x79, 0x1A, 0x4B, 0x23, 0x83, 0xFD, 0x30,
		0x12, 0xDD, 0x43, 0xAC, 0x45, 0xDC, 0x8B, 0xEE,
		0x01, 0xDE, 0x2C, 0x1A, 0x01, 0xD0, 0x5E, 0xA5,
		0x05, 0xB4, 0xA7, 0x68, 0xC5, 0x3B, 0x5A, 0xA9,
		0xEF, 0x13, 0x2C, 0x69, 0xB6, 0xFE, 0xF0, 0xDD,
		0x16, 0x55, 0x53, 0xAD, 0xCE, 0xCE, 0x4D, 0xE6,
		0xA0, 0x35, 0xD0, 0x55, 0xB7, 0x84, 0x44, 0x60,
		0xE2, 0xD1, 0x49, 0x14, 0x61, 0x14, 0x86, 0x66,
		0x8A, 0x11, 0x7B, 0x92, 0xC2, 0x2C, 0x23, 0xD2,
		0x33, 0xE4, 0x9E, 0x46, 0x30, 0x40, 0x76, 0x4F,
		0xC8, 0x08, 0x7C, 0x4B, 0xA1, 0xE4, 0xBB, 0x6A,
		0xA6, 0xEF, 0x96, 0xDA, 0xD0, 0x24, 0xC1, 0xB5,
		0x9B, 0x83, 0xEE, 0x45, 0x1E, 0x15, 0xEF, 0x1D,
		0x80, 0x71, 0x3A, 0x72, 0xEE, 0xEB, 0x4F, 0x78,
		0xAB, 0x19, 0x38, 0x23, 0xC9, 0x21, 0xEA, 0x78,
		0x57, 0x99, 0xA8, 0xB2, 0x49, 0xA4, 0x43, 0x6D,
		0x56, 0x8D, 0x31, 0x7F, 0xB9, 0x21, 0x69, 0x01,
		0x2C, 0x46, 0x6D, 0x8B, 0x5D, 0x12, 0x04, 0x4E,
		0xA1, 0xDF, 0x7E, 0x14, 0x92, 0x18, 0x43, 0xCD,
		0x03, 0xA7, 0x67, 0x87, 0x16, 0x1B, 0x63, 0xEE,
		0xFD, 0x98, 0x85, 0xF3, 0x3A, 0xF0, 0x58, 0x2A,
		0x2E, 0xCA, 0x3C, 0x0C, 0xEF, 0xED, 0x20, 0xBE,
		0x21, 0xBE, 0xCD, 0xAD, 0x93, 0x41, 0x05, 0xDC,
		0x80, 0x6B, 0x70, 0x12, 0x4C, 0x97, 0xCB, 0x68,
		0x53, 0x5D, 0x79, 0x7E, 0xD0, 0x25, 0x0D, 0x6E,
		0x8D, 0x11, 0x55, 0x97, 0xF5, 0xC4, 0x39, 0x73,
		0xB9, 0xB3, 0x1E, 0xE2, 0x83, 0xB7, 0x4B, 0x76,
		0x16, 0x56, 0x18, 0x47, 0x5F, 0xE6, 0x3C, 0x84,
		0x62, 0x31, 0xD0, 0x29, 0x61, 0xDA, 0x71, 0x40,
		0xA0, 0x51, 0x65, 0xDE, 0xB7, 0x1C, 0x32, 0x99,
		0xB3, 0xCF, 0xF8, 0x88, 0x1B, 0x2E, 0x99, 0x24,
		0x86, 0xDA, 0x58, 0x42, 0x65, 0xAE, 0xBF, 0xF2,
		0xF0, 0x0D, 0xB4, 0x28, 0x5D, 0xEC, 0x43, 0xB2,
		0x3B, 0x3A, 0x10, 0x1D, 0xDB, 0xD2, 0x50, 0x6F,
		0x98, 0x7E, 0xF5, 0x1F, 0xD9, 0x2D, 0x91, 0x16,
		0x59, 0x2E, 0x16, 0xA4, 0x8C, 0xAC, 0x7A, 0xB1,
		0x6E, 0x40, 0xB1, 0x08, 0x8B, 0xCB, 0x17, 0xA8,
		0xEE, 0xD1, 0xB5, 0xAD, 0x45, 0xF3, 0x52, 0x9C,
		0x7E, 0xE5, 0xEE, 0xDF, 0x5F, 0x2E, 0x33, 0xA1,
		0x15, 0x3F, 0xF3, 0x75, 0x95, 0x32, 0x84, 0xF0,
		0xE7, 0x56, 0x10, 0x2E, 0x6E, 0xCE, 0x54, 0x87,
		0x5E, 0x55, 0x4D, 0x0D, 0xCE, 0xA7, 0x56, 0x4C,
		0xA3, 0xAB, 0xD6, 0x10, 0x9D, 0x61, 0x07, 0x7F,
		0x6F, 0x1F, 0xD7, 0xE0, 0x52, 0x75, 0xFE, 0x3C,
		0xDE, 0x84, 0x54, 0x9C, 0x40, 0xF6, 0x48, 0x54,
		0xF6, 0x8C, 0x41, 0x67, 0xAD, 0xA3, 0xC1, 0xED,
		0x1F, 0x45, 0xEB, 0x94, 0x6E, 0x62, 0x75, 0x3B,
		0xF2, 0x50, 0x25, 0xB7, 0x23, 0x4B, 0x13, 0xA0,
		0xBD, 0xFA, 0xB0, 0x90, 0x94, 0x76, 0x92, 0x8F,
		0x3F, 0x45, 0x73, 0x12, 0x9D, 0xFA, 0xCF, 0x95,
		0xD6, 0xFB, 0x2B, 0x66, 0x15, 0xBB, 0x37, 0x8F,
		0x14, 0xE8, 0x12, 0xD2, 0x86, 0x88, 0x9A, 0x6A,
		0x9F, 0xDF, 0x62, 0x7D, 0x38, 0x98, 0xE8, 0x4B,
		0xAC, 0x01, 0x4F, 0xA5, 0xF2, 0x8A, 0x24, 0x04,
		0x23, 0xAB, 0x3F, 0xBD, 0xB5, 0xB3, 0x7F, 0x1F,
		0x78, 0xE9, 0x28, 0x7C, 0xC1, 0x3E, 0x90, 0x8F,
		0xEB, 0x66, 0x9C, 0xC2, 0xFF, 0xF3, 0x40, 0x15,
		0xB9, 0xE0, 0x19, 0x95, 0xDA, 0xAF, 0x78, 0x3D,
		0x65, 0xD4, 0x11, 0x16, 0x17, 0x85, 0xD0, 0x3C,
		0xA1, 0x61, 0x70, 0x79, 0xAE, 0xA1, 0x2C, 0xC5,
		0x96, 0x2A, 0x55, 0x6B, 0xC7, 0x89, 0xD9, 0x34,
		0xC2, 0x56, 0x42, 0x85, 0xEF, 0x21, 0x80, 0xE8,
		0x62, 0xD6, 0x1D, 0xED, 0x04, 0x27, 0xB9, 0x40,
		0xD1, 0x64, 0x4B, 0xD8, 0x27, 0x03, 0x6C, 0xFC,
		0x66, 0x08, 0xB7, 0x5A, 0x98, 0xDB, 0x14, 0x82,
		0xC2, 0x15, 0x3D, 0xD1, 0xC5, 0xA1, 0xA0, 0xED
	};
	static const uint8_t exp_512[] = {
		0xa1, 0xed, 0xcb, 0xa7, 0xbe, 0xa4, 0xa7, 0xaf,
		0x68, 0x2b, 0xd3, 0xc1, 0xaa, 0x50, 0xc0, 0x82,
		0x66, 0x6f, 0x0f, 0x2f, 0xde, 0xd8, 0x63, 0x5a,
		0x21, 0x95, 0xf1, 0x0e, 0xe9, 0x8b, 0xd7, 0xf2,
		0x0c, 0x3b, 0x76, 0x45, 0xd5, 0x40, 0x99, 0x39,
		0x37, 0xac, 0x1b, 0x6c, 0x34, 0x29, 0x7c, 0x1f,
		0x2f, 0x7b, 0x40, 0xa2, 0x5a, 0x1b, 0x82, 0x5f,
		0xa5, 0xa3, 0x34, 0x09, 0x0e, 0xf7, 0x3b, 0x7b
	};
	uint8_t act[LC_SHA512_SIZE_DIGEST];
	int ret;
	LC_HMAC_CTX_ON_STACK(hmac, lc_sha512);

	lc_hmac_init(hmac, key_512, sizeof(key_512));
	lc_hmac_update(hmac, msg_512, sizeof(msg_512));
	lc_hmac_final(hmac, act);
	lc_hmac_zero(hmac);

	ret = lc_compare(act, exp_512, LC_SHA512_SIZE_DIGEST, "HMAC SHA2-512");

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hmac_sha2_512_tester();
}
