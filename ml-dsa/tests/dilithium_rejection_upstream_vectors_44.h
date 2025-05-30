/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * Test vectors are obtained from
 * https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html#name-known-answer-tests
 */

#ifndef DILITHIUM_REJECTION_UPSTREAM_VECTORS_44_H
#define DILITHIUM_REJECTION_UPSTREAM_VECTORS_44_H

#include "dilithium_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dilithium_rejection_testvector {
	uint8_t seed[LC_DILITHIUM_SEEDBYTES];
	uint8_t pk[LC_DILITHIUM_PUBLICKEYBYTES];
	uint8_t sk[LC_DILITHIUM_SECRETKEYBYTES];
	uint8_t key_hash[LC_SHA256_SIZE_DIGEST];
	uint8_t msg[32];
	uint8_t sig_hash[LC_SHA256_SIZE_DIGEST];
	uint8_t sig[LC_DILITHIUM_CRYPTO_BYTES];
};

static const struct dilithium_rejection_testvector dilithium_rejection_testvectors[] = {
	{
		/* Data from Table 1 */
		.seed = { 0x5C, 0x62, 0x4F, 0xCC, 0x18, 0x62, 0x45, 0x24,
			  0x52, 0xD0, 0xC6, 0x65, 0x84, 0x0D, 0x82, 0x37,
			  0xF4, 0x31, 0x08, 0xE5, 0x49, 0x9E, 0xDC, 0xDC,
			  0x10, 0x8F, 0xBC, 0x49, 0xD5, 0x96, 0xE4, 0xB7 },
		.key_hash = { 0xAC, 0x82, 0x5C, 0x59, 0xD8, 0xA4, 0xC4, 0x53,
			      0xA2, 0xC4, 0xEF, 0xEA, 0x83, 0x95, 0x74, 0x1C,
			      0xA4, 0x04, 0xF3, 0x00, 0x0E, 0x28, 0xD5, 0x6B,
			      0x25, 0xD0, 0x3B, 0xB4, 0x02, 0xE5, 0xCB, 0x2F },
		.msg = { 0x95, 0x1F, 0xDF, 0x54, 0x73, 0xA4, 0xCB, 0xA6,
			 0xD9, 0xE5, 0xB5, 0xDB, 0x7E, 0x79, 0xFB, 0x81,
			 0x73, 0x92, 0x1B, 0xA5, 0xB1, 0x3E, 0x92, 0x71,
			 0x40, 0x1B, 0x8F, 0x90, 0x7B, 0x8B, 0x7D, 0x5B },
		.sig_hash = { 0xDC, 0xC7, 0x1A, 0x42, 0x1B, 0xC6, 0xFF, 0xAF,
			      0xB7, 0xDF, 0x0C, 0x7F, 0x6D, 0x01, 0x8A, 0x19,
			      0xAD, 0xA1, 0x54, 0xD1, 0xE2, 0xEE, 0x36, 0x0E,
			      0xD5, 0x33, 0xCE, 0xCD, 0x5D, 0xC9, 0x80, 0xAD },
	},
	{
		.seed = { 0x83, 0x6E, 0xAB, 0xED, 0xB4, 0xD2, 0xCD, 0x9B,
			  0xE6, 0xA4, 0xD9, 0x57, 0xCF, 0x5E, 0xE6, 0xBF,
			  0x48, 0x93, 0x04, 0x13, 0x68, 0x64, 0xC5, 0x5C,
			  0x2C, 0x5F, 0x01, 0xDA, 0x50, 0x47, 0xD1, 0x8B },
		.key_hash = { 0xE1, 0xFF, 0x40, 0xD9, 0x6E, 0x35, 0x52, 0xFA,
			      0xB5, 0x31, 0xD1, 0x71, 0x50, 0x84, 0xB7, 0xE3,
			      0x8C, 0xCD, 0xBA, 0xCC, 0x0A, 0x8A, 0xF9, 0x4C,
			      0x30, 0x95, 0x9F, 0xB4, 0xC7, 0xF5, 0xA4, 0x45 },
		.msg = { 0x19, 0x9A, 0x0A, 0xB7, 0x35, 0xE9, 0x00, 0x41,
			 0x63, 0xDD, 0x02, 0xD3, 0x19, 0xA6, 0x1C, 0xFE,
			 0x81, 0x63, 0x8E, 0x3B, 0xF4, 0x7B, 0xB1, 0xE9,
			 0x0E, 0x90, 0xD6, 0xE3, 0xEA, 0x54, 0x52, 0x47 },
		.sig_hash = { 0xA2, 0x60, 0x8B, 0xC2, 0x7E, 0x60, 0x54, 0x1D,
			      0x27, 0xB6, 0xA1, 0x4F, 0x46, 0x0D, 0x54, 0xA4,
			      0x8C, 0x02, 0x98, 0xDC, 0xC3, 0xF4, 0x59, 0x99,
			      0xF2, 0x90, 0x47, 0xA3, 0x13, 0x5C, 0x49, 0x41 },
	},
	{
		.seed = { 0xCA, 0x5A, 0x01, 0xE1, 0xEA, 0x65, 0x52, 0xCB,
			  0x5C, 0x98, 0x03, 0x46, 0x2B, 0x94, 0xC2, 0xF1,
			  0xDC, 0x9D, 0x13, 0xBB, 0x17, 0xA6, 0xAC, 0xE5,
			  0x10, 0xD1, 0x57, 0x05, 0x6A, 0x2C, 0x61, 0x14 },
		.key_hash = { 0xA4, 0x65, 0x2D, 0xC4, 0xA2, 0x71, 0x09, 0x52,
			      0x68, 0xDD, 0x84, 0xA5, 0xB0, 0x74, 0x4D, 0xFD,
			      0xBE, 0x2E, 0x64, 0x2E, 0x4D, 0x41, 0xFB, 0xC4,
			      0x32, 0x9C, 0x2F, 0xBA, 0x53, 0x4C, 0x0E, 0x13 },
		.msg = { 0x8C, 0x8C, 0xAC, 0xA8, 0x8F, 0xFF, 0x52, 0xB9,
			 0x33, 0x05, 0x10, 0x53, 0x7B, 0x37, 0x01, 0xB3,
			 0x99, 0x3F, 0x37, 0x26, 0x13, 0x6A, 0x65, 0x0F,
			 0x48, 0xF8, 0x60, 0x45, 0x51, 0x55, 0x08, 0x32 },
		.sig_hash = { 0xB4, 0xB1, 0x42, 0x20, 0x91, 0x37, 0x39, 0x7D,
			      0xAD, 0x50, 0x4C, 0xAE, 0xD0, 0x1D, 0x39, 0x0A,
			      0xDA, 0xF4, 0x99, 0x73, 0xD8, 0xD2, 0x41, 0x4F,
			      0xC3, 0x45, 0x7F, 0xB7, 0xAF, 0x77, 0x51, 0x89 },
	},
	{
		.seed = { 0x9C, 0x00, 0x5F, 0x15, 0x50, 0xB4, 0xF3, 0x18,
			  0x55, 0xC6, 0xB9, 0x2F, 0x97, 0x87, 0x36, 0x73,
			  0x3F, 0x37, 0x79, 0x1C, 0xB3, 0x9D, 0xD1, 0x82,
			  0xD7, 0xBA, 0x57, 0x32, 0xBD, 0xC2, 0x48, 0x3E },
		.key_hash = { 0x24, 0x85, 0xAA, 0x99, 0x34, 0x5F, 0x1B, 0x33,
			      0x4D, 0x4D, 0x94, 0xB6, 0x10, 0xFB, 0xFF, 0xCC,
			      0xB6, 0x26, 0xCB, 0xFD, 0x4E, 0x9F, 0xF0, 0xE1,
			      0xF6, 0xFC, 0x35, 0x09, 0x3C, 0x42, 0x35, 0x44 },
		.msg = { 0xB7, 0x44, 0x34, 0x3F, 0x30, 0xF7, 0xFE, 0xE0,
			 0x88, 0x99, 0x8B, 0xA5, 0x74, 0xE7, 0x99, 0xF1,
			 0xBF, 0x39, 0x39, 0xC0, 0x6C, 0x29, 0xBF, 0x9A,
			 0xC1, 0x0F, 0x35, 0x88, 0xA5, 0x7E, 0x21, 0xE2 },
		.sig_hash = { 0x5B, 0x80, 0xA6, 0x0B, 0xAA, 0x48, 0x0B, 0x9D,
			      0x0C, 0x7D, 0x2C, 0x05, 0xB5, 0x09, 0x28, 0xC4,
			      0xBF, 0x68, 0x08, 0xDD, 0xA6, 0x93, 0x64, 0x20,
			      0x58, 0xA3, 0xEB, 0x77, 0xEA, 0xA7, 0x68, 0xFC },
	},
	{
		.seed = { 0x4F, 0xAB, 0x54, 0x85, 0xB0, 0x09, 0x39, 0x9E,
			  0x8A, 0xE6, 0xFC, 0x3D, 0x3E, 0xEF, 0xBF, 0xE8,
			  0xE0, 0x97, 0x96, 0xE4, 0x47, 0x7A, 0xAB, 0xD5,
			  0xEB, 0x1C, 0xC9, 0x08, 0xFA, 0x73, 0x4D, 0xE3 },
		.key_hash = { 0xCB, 0x56, 0x90, 0x9A, 0x7C, 0xF3, 0x00, 0x8A,
			      0x66, 0x2D, 0xC6, 0x35, 0xED, 0xCB, 0x79, 0xDC,
			      0x15, 0x1C, 0xA7, 0xAC, 0xBA, 0xE1, 0x7B, 0x54,
			      0x43, 0x84, 0xAB, 0xD9, 0x1B, 0xBB, 0xC1, 0xE9 },
		.msg = { 0x7C, 0xAB, 0x0F, 0xDC, 0xF4, 0xBE, 0xA5, 0xF0,
			 0x39, 0x13, 0x74, 0x78, 0xAA, 0x45, 0xC9, 0xC4,
			 0x8E, 0xF9, 0x6D, 0x90, 0x6F, 0xC4, 0x9F, 0x6E,
			 0x2F, 0x13, 0x81, 0x11, 0xBF, 0x1B, 0x4A, 0x4E },
		.sig_hash = { 0x6C, 0xC3, 0x8D, 0x73, 0xD6, 0x39, 0x68, 0x2A,
			      0xBC, 0x55, 0x6D, 0xC6, 0xDC, 0xF4, 0x36, 0xDE,
			      0x24, 0x03, 0x30, 0x91, 0xF3, 0x40, 0x04, 0xF4,
			      0x10, 0xFA, 0xBC, 0x68, 0x87, 0xF7, 0x7A, 0xB0 },
	},
	{
		/* Data from Table 2 */
		.seed = { 0x09, 0x0D, 0x97, 0xC1, 0xF4, 0x16, 0x6E, 0xB3,
			  0x2C, 0xA6, 0x7C, 0x5F, 0xB5, 0x64, 0xAC, 0xBE,
			  0x07, 0x35, 0xDB, 0x4A, 0xF4, 0xB8, 0xDB, 0x3A,
			  0x7C, 0x2C, 0xE7, 0x40, 0x23, 0x57, 0xCA, 0x44 },
		.key_hash = { 0x26, 0xD7, 0x9E, 0x40, 0x68, 0x04, 0x0E, 0x99,
			      0x6B, 0xC9, 0xEB, 0x50, 0x34, 0xC2, 0x04, 0x89,
			      0xC0, 0xAD, 0x38, 0xDC, 0x2F, 0xEC, 0x19, 0x18,
			      0xD0, 0x76, 0x0C, 0x86, 0x21, 0x87, 0x24, 0x08 },
		.msg = { 0xE3, 0x83, 0x83, 0x64, 0xB3, 0x7F, 0x47, 0xED,
			 0xFC, 0xA2, 0xB5, 0x77, 0xB2, 0x0B, 0x80, 0xC3,
			 0xCB, 0x51, 0xB9, 0xF5, 0x6E, 0x0E, 0x4C, 0xDB,
			 0x7D, 0xF0, 0x02, 0xC8, 0x74, 0x03, 0x92, 0x52 },
		.sig_hash = { 0xCD, 0x91, 0x15, 0x0C, 0x61, 0x0F, 0xF0, 0x2D,
			      0xE1, 0xDD, 0x70, 0x49, 0xC3, 0x09, 0xEF, 0xE8,
			      0x00, 0xCE, 0x5C, 0x1B, 0xC2, 0xE5, 0xA3, 0x2D,
			      0x75, 0x2A, 0xB6, 0x2C, 0x5B, 0xF5, 0xE1, 0x6F },
	},
	{
		.seed = { 0xCF, 0xC7, 0x3D, 0x07, 0xA8, 0x83, 0x54, 0x3A,
			  0x80, 0x4F, 0x77, 0x00, 0x70, 0x86, 0x18, 0x25,
			  0x14, 0x3A, 0x62, 0xF2, 0xF9, 0x7D, 0x05, 0xFC,
			  0xE0, 0x0F, 0xD8, 0xB2, 0x5D, 0x29, 0xA4, 0x3F },
		.key_hash = { 0x89, 0x14, 0x2A, 0xB2, 0x6D, 0x6E, 0xB6, 0xC0,
			      0x1F, 0xA3, 0xF1, 0x89, 0xA9, 0xC8, 0x77, 0x59,
			      0x77, 0x40, 0xD6, 0x85, 0x98, 0x3F, 0x29, 0xBB,
			      0xDD, 0x35, 0x96, 0x64, 0x82, 0x66, 0xAE, 0x0E },
		.msg = { 0x09, 0x60, 0xC1, 0x3E, 0x9B, 0xA4, 0x67, 0xA9,
			 0x38, 0x45, 0x01, 0x20, 0xCC, 0x96, 0xFF, 0x6F,
			 0x04, 0xB7, 0xE5, 0x57, 0xC9, 0x9A, 0x83, 0x86,
			 0x19, 0xA4, 0x8F, 0x9A, 0x38, 0x73, 0x8A, 0xB8 },
		.sig_hash = { 0xB6, 0x29, 0x6F, 0xFF, 0x0C, 0x1F, 0x23, 0xDE,
			      0x49, 0x06, 0xD5, 0x81, 0x44, 0xB0, 0x0A, 0x2D,
			      0xB1, 0x3A, 0xD2, 0x5E, 0x49, 0xB4, 0xB8, 0x57,
			      0x3A, 0x62, 0xEF, 0xEE, 0xCB, 0x54, 0x4D, 0xD7 },
	}
};

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_REJECTION_UPSTREAM_VECTORS_44_H */
