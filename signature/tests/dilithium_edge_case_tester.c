/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_edge_case_tester.h"
#include "ext_headers.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef LC_DILITHIUM_TYPE_44
#define DILITHIUM_TYPE LC_DILITHIUM_44
#else
#error "Dilithium edge cases are only defined for Dilithium 44"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct dilithium_edge_case {
	uint8_t seed[32];
	uint8_t key_hash[LC_SHA256_SIZE_DIGEST];
	uint8_t msg[32];
	uint8_t sig_hash[LC_SHA256_SIZE_DIGEST];
};

static const struct dilithium_edge_case tcs[] = {
	{
		.seed = { 0x9E, 0xFC, 0xCC, 0x46, 0x52, 0xFF, 0xCC, 0xA9,
			  0x21, 0x67, 0x50, 0x44, 0x21, 0x2B, 0x98, 0x45,
			  0xA0, 0x65, 0x91, 0xED, 0x6C, 0x21, 0xBD, 0xAA,
			  0x70, 0x53, 0xF1, 0x87, 0x88, 0xB8, 0xFA, 0xB8 },
		.key_hash = { 0xF5, 0x72, 0x1F, 0x92, 0x49, 0xEC, 0x74, 0x0A,
			      0x32, 0xC8, 0xED, 0xAD, 0x28, 0xDE, 0x59, 0x13,
			      0x58, 0x7D, 0xD0, 0x95, 0x09, 0x39, 0x6B, 0xCC,
			      0x82, 0x46, 0x6E, 0xD9, 0xD0, 0x5C, 0x24, 0x22 },
		.msg = { 0x63, 0x6E, 0xF5, 0x78, 0xFF, 0x26, 0xE7, 0x28,
			 0x6B, 0xF9, 0xE6, 0xAA, 0x83, 0x2F, 0xD1, 0xB3,
			 0xE2, 0x83, 0x0C, 0x97, 0x15, 0x71, 0x42, 0x5A,
			 0xD3, 0x92, 0x51, 0x97, 0xC9, 0xBD, 0xCF, 0x35 },
		.sig_hash = { 0x13, 0x79, 0xAC, 0xF5, 0x63, 0x22, 0x68, 0xAA,
			      0xA4, 0xCD, 0x11, 0x3B, 0xE8, 0xD2, 0xE9, 0x9A,
			      0x88, 0x61, 0x13, 0xCC, 0x57, 0x7C, 0x7D, 0xB4,
			      0x95, 0xE8, 0xFF, 0x24, 0x42, 0x78, 0x19, 0x00 },
	},
	{
		.seed = { 0xB6, 0xD8, 0xDF, 0x65, 0x3C, 0xB0, 0xAC, 0x35,
			  0x8B, 0x8D, 0xCB, 0x50, 0x43, 0xCB, 0xD7, 0x7D,
			  0xC7, 0x57, 0x38, 0xCA, 0x95, 0x61, 0x46, 0x0A,
			  0xF3, 0x0C, 0x68, 0x27, 0x50, 0x2D, 0x38, 0xB0 },
		.key_hash = { 0x9F, 0xFE, 0x68, 0x22, 0x1D, 0x54, 0x9A, 0xBB,
			      0x63, 0x90, 0x13, 0x48, 0xC8, 0x11, 0xE2, 0xD4,
			      0xCC, 0x46, 0xAF, 0x33, 0xE9, 0x07, 0x98, 0xF1,
			      0xE2, 0xEE, 0x6C, 0xFF, 0xDA, 0x6E, 0xFB, 0x6C },
		.msg = { 0xD1, 0xCC, 0x97, 0x2E, 0xBE, 0x55, 0x55, 0x7C,
			 0x9B, 0xDF, 0xA2, 0x11, 0xF5, 0x09, 0xC7, 0x6B,
			 0x98, 0x67, 0xFE, 0x08, 0xCE, 0x92, 0xAF, 0x4D,
			 0x9A, 0xE8, 0x4A, 0xBD, 0x94, 0x71, 0xE2, 0x80 },
		.sig_hash = { 0x19, 0x77, 0x15, 0x94, 0x29, 0x81, 0x4B, 0xC3,
			      0x05, 0x4B, 0x5D, 0xFB, 0x91, 0x2C, 0xA9, 0x12,
			      0xFD, 0x77, 0x9D, 0x1F, 0x4D, 0x70, 0x6B, 0xC9,
			      0xD7, 0x52, 0xE9, 0xE9, 0x24, 0x82, 0x49, 0xF8 },
	},
	{
		.seed = { 0x19, 0xA4, 0x57, 0x84, 0x02, 0xEA, 0x7A, 0x3B,
			  0x0F, 0xA1, 0xE6, 0xA6, 0x42, 0xB3, 0x46, 0x20,
			  0x2F, 0x70, 0xFD, 0x48, 0xEF, 0xF8, 0x87, 0x16,
			  0x70, 0x0D, 0x2F, 0xB8, 0x56, 0xF6, 0x37, 0xE1 },
		.key_hash = { 0x6C, 0x34, 0x6D, 0xF3, 0x31, 0x2E, 0x5F, 0x08,
			      0xAA, 0x6F, 0xD5, 0x36, 0xB6, 0x50, 0xB0, 0x00,
			      0x0E, 0x87, 0x59, 0x56, 0xE1, 0x1D, 0xA6, 0x41,
			      0xC2, 0xA0, 0x9A, 0xE2, 0xC0, 0x08, 0xD7, 0x39 },
		.msg = { 0xF6, 0xBA, 0x1E, 0x9E, 0xDB, 0xB1, 0xDD, 0x6C,
			 0x31, 0xD5, 0x0E, 0x03, 0x9E, 0xBB, 0x5D, 0x2E,
			 0x6B, 0xDD, 0x88, 0xEC, 0x74, 0xD4, 0x15, 0xC5,
			 0x5B, 0xF2, 0xBD, 0xF8, 0x11, 0x9C, 0x1F, 0x99 },
		.sig_hash = { 0x9B, 0xF7, 0x31, 0x0C, 0xBA, 0x86, 0xAA, 0x09,
			      0x65, 0x59, 0x51, 0x74, 0x63, 0x56, 0xBA, 0xEB,
			      0x31, 0x60, 0x92, 0x8A, 0x47, 0x2F, 0x0F, 0x80,
			      0x03, 0x21, 0xA1, 0x10, 0x2D, 0x51, 0x32, 0x77 },
	},
	{
		.seed = { 0x19, 0xA4, 0x57, 0x84, 0x02, 0xEA, 0x7A, 0x3B,
			  0x0F, 0xA1, 0xE6, 0xA6, 0x42, 0xB3, 0x46, 0x20,
			  0x2F, 0x70, 0xFD, 0x48, 0xEF, 0xF8, 0x87, 0x16,
			  0x70, 0x0D, 0x2F, 0xB8, 0x56, 0xF6, 0x37, 0xE1 },
		.key_hash = { 0x6C, 0x34, 0x6D, 0xF3, 0x31, 0x2E, 0x5F, 0x08,
			      0xAA, 0x6F, 0xD5, 0x36, 0xB6, 0x50, 0xB0, 0x00,
			      0x0E, 0x87, 0x59, 0x56, 0xE1, 0x1D, 0xA6, 0x41,
			      0xC2, 0xA0, 0x9A, 0xE2, 0xC0, 0x08, 0xD7, 0x39 },
		.msg = { 0x59, 0x33, 0x4D, 0x14, 0x33, 0xCC, 0x31, 0x7A,
			 0x4E, 0x0B, 0x20, 0xAB, 0x4C, 0x86, 0x95, 0xFE,
			 0x92, 0x38, 0x4F, 0x09, 0x4C, 0xFC, 0x4A, 0xB9,
			 0xE2, 0x73, 0x19, 0x21, 0xCF, 0xE8, 0x2E, 0x95 },
		.sig_hash = { 0x2B, 0xBF, 0x13, 0xA3, 0x0D, 0xF7, 0xF2, 0x0B,
			      0xB2, 0x04, 0x69, 0xC0, 0xAA, 0x1A, 0x37, 0x20,
			      0x73, 0x27, 0xE1, 0xAE, 0xC8, 0xDC, 0x03, 0x53,
			      0x42, 0x69, 0x51, 0xF1, 0x34, 0xC7, 0xF3, 0x36 },
	},
	{
		.seed = { 0xD0, 0xCB, 0xB0, 0x72, 0x34, 0xCF, 0x3D, 0xAC,
			  0x9A, 0xBC, 0xFE, 0xAD, 0x5F, 0x30, 0xD3, 0x86,
			  0x50, 0x3D, 0x74, 0x39, 0x4F, 0xF2, 0xE8, 0x9C,
			  0x57, 0x28, 0x93, 0x62, 0x3B, 0x35, 0x2C, 0xE2 },
		.key_hash = { 0x17, 0x25, 0xAF, 0x74, 0x35, 0x65, 0x10, 0x74,
			      0xD1, 0x15, 0x18, 0x0A, 0xB3, 0xBD, 0x70, 0x45,
			      0xE3, 0x11, 0x9A, 0xC7, 0xB0, 0x1E, 0x32, 0x9C,
			      0x66, 0x7C, 0xAB, 0xDB, 0xA7, 0xAF, 0x81, 0xA9 },
		.msg = { 0x6A, 0x98, 0xB5, 0x95, 0x52, 0xC3, 0xAB, 0xF1,
			 0xE1, 0x2C, 0xE1, 0x02, 0x14, 0xDE, 0xB3, 0x3E,
			 0x26, 0x6E, 0x83, 0x43, 0x96, 0x74, 0xB1, 0xC6,
			 0x2A, 0x81, 0x18, 0xCD, 0x29, 0x9F, 0x4D, 0xDA },
		.sig_hash = { 0xFB, 0xFB, 0x9F, 0xDD, 0x99, 0x32, 0xB7, 0xAD,
			      0xCD, 0x6E, 0xB9, 0xC1, 0x98, 0x89, 0x54, 0xF5,
			      0x52, 0x3B, 0x50, 0xE4, 0x00, 0x95, 0x8B, 0x7E,
			      0x3E, 0x2F, 0xBD, 0x51, 0x4D, 0x07, 0xB8, 0x11 },
	},
	{
		.seed = { 0xAF, 0x3B, 0x13, 0x7E, 0x67, 0x8A, 0x32, 0xC9,
			  0x89, 0x0D, 0xA5, 0x7B, 0x90, 0x82, 0x12, 0xB8,
			  0x83, 0xDF, 0x5F, 0x53, 0x69, 0x89, 0x06, 0xAC,
			  0x25, 0x9D, 0xC9, 0x57, 0xF3, 0xAA, 0x0F, 0x49 },
		.key_hash = { 0xC5, 0x92, 0xA4, 0x4E, 0x6B, 0xA3, 0x8F, 0x32,
			      0xED, 0x2A, 0xD6, 0x02, 0x0C, 0xFE, 0xF4, 0x76,
			      0x2A, 0xEF, 0x29, 0xFE, 0x1E, 0x6B, 0x81, 0xB1,
			      0x3F, 0x01, 0x1B, 0x70, 0xB4, 0xB2, 0x78, 0x78 },
		.msg = { 0xE5, 0xE6, 0xCD, 0xA6, 0x4A, 0x9B, 0xCD, 0xCE,
			 0x1B, 0x3C, 0xF6, 0x0E, 0xD5, 0xFB, 0xD3, 0x20,
			 0x67, 0xB0, 0x07, 0xE9, 0x9A, 0xE8, 0xD3, 0x0B,
			 0xCB, 0xB3, 0xA4, 0x7D, 0x66, 0x06, 0xBC, 0x63 },
		.sig_hash = { 0xD3, 0x14, 0x00, 0xBA, 0x00, 0x8C, 0x66, 0xC1,
			      0x3C, 0xB8, 0x2B, 0xF7, 0xC4, 0xEB, 0x98, 0xB4,
			      0x12, 0x7B, 0x0D, 0x01, 0x8A, 0x26, 0xB5, 0xF7,
			      0x8B, 0x72, 0x4E, 0x48, 0x16, 0xD0, 0x57, 0x5B },
	},
	{
		.seed = { 0x41, 0xF1, 0xDD, 0x6A, 0xDB, 0xE9, 0x9B, 0x20,
			  0xF7, 0xC0, 0x9C, 0xBE, 0xC3, 0x5F, 0xE4, 0xD5,
			  0x77, 0x12, 0x1A, 0xB1, 0xA2, 0xD1, 0xF1, 0x9A,
			  0x67, 0xD0, 0x93, 0xA8, 0x89, 0xA2, 0x12, 0xBF },
		.key_hash = { 0x81, 0xC9, 0x8C, 0xAE, 0xA0, 0xC9, 0x6C, 0xDC,
			      0x7E, 0x6E, 0x89, 0x9F, 0x3D, 0x21, 0xC6, 0x5D,
			      0x5A, 0x1B, 0xA1, 0xAD, 0xBF, 0xB0, 0x57, 0x09,
			      0xA3, 0xDD, 0x94, 0x76, 0x06, 0x57, 0x48, 0x1D },
		.msg = { 0xDE, 0xFC, 0x0A, 0x18, 0x1C, 0x7E, 0xEE, 0x47,
			 0xE3, 0x66, 0xB7, 0x75, 0x06, 0x9E, 0x4E, 0x75,
			 0xE9, 0xB0, 0x3E, 0x41, 0xA3, 0x2F, 0xD9, 0x92,
			 0xF5, 0x32, 0x1F, 0x5F, 0x3A, 0xBF, 0x3A, 0x1E },
		.sig_hash = { 0xFC, 0x78, 0x35, 0xD7, 0xBC, 0x7A, 0x00, 0x5D,
			      0xC9, 0xE8, 0x0A, 0x33, 0x1D, 0x24, 0xFE, 0xAB,
			      0x4A, 0x09, 0xF2, 0x22, 0x69, 0xDA, 0x05, 0xD8,
			      0x8F, 0x31, 0x11, 0x4E, 0x65, 0x52, 0x2C, 0xC0 },
	},
	{
		.seed = { 0xED, 0xC1, 0x5B, 0xAB, 0x40, 0xD4, 0xF0, 0x06,
			  0x1A, 0x42, 0xBB, 0x1B, 0x1E, 0x25, 0xFB, 0x88,
			  0xDD, 0xA8, 0x1D, 0xE5, 0x56, 0xB5, 0xB7, 0xD1,
			  0xD1, 0xF6, 0xF9, 0x76, 0xBF, 0x18, 0xD3, 0x42 },
		.key_hash = { 0xB4, 0x80, 0x37, 0x91, 0x5B, 0xEA, 0xF7, 0x3F,
			      0xD8, 0x07, 0x1C, 0x4A, 0x37, 0xD8, 0x65, 0x0F,
			      0x9B, 0xDC, 0x43, 0xFF, 0x44, 0x8C, 0xA5, 0xFC,
			      0x2A, 0x5D, 0x82, 0x12, 0x8A, 0x54, 0x15, 0xE2 },
		.msg = { 0x9A, 0xFE, 0x6C, 0xEC, 0x7B, 0xEB, 0xCE, 0x17,
			 0x6F, 0x3B, 0xED, 0x99, 0xF6, 0x53, 0x0B, 0x30,
			 0x23, 0x5F, 0x9D, 0xCE, 0x8D, 0xB2, 0xB8, 0x45,
			 0xAB, 0xC2, 0x9D, 0xDC, 0x78, 0x00, 0xD0, 0xDF },
		.sig_hash = { 0xFF, 0x8D, 0x01, 0x8D, 0x77, 0x6D, 0xDB, 0xE4,
			      0x37, 0xE1, 0x0A, 0xFA, 0x01, 0x09, 0x2F, 0x62,
			      0x2E, 0x13, 0x3B, 0xC9, 0x68, 0xE6, 0xF3, 0x54,
			      0x7B, 0x5E, 0xEC, 0x05, 0x82, 0x34, 0x0B, 0xA2 },
	},
	{
		.seed = { 0x06, 0xDE, 0x27, 0x93, 0x5B, 0x35, 0x46, 0x10,
			  0x8C, 0xB5, 0xDF, 0x5B, 0x9D, 0x20, 0x96, 0x2E,
			  0x66, 0xE9, 0x48, 0x3D, 0x28, 0xB6, 0xBD, 0x35,
			  0x26, 0xBC, 0x29, 0xE6, 0x7D, 0x63, 0x93, 0x46 },
		.key_hash = { 0xDE, 0xFF, 0x61, 0x03, 0xF2, 0x46, 0x1E, 0xE3,
			      0x66, 0x45, 0x98, 0xD0, 0x47, 0x30, 0x8D, 0xF5,
			      0x94, 0x48, 0x1D, 0x8A, 0x79, 0x09, 0xD6, 0x65,
			      0xA3, 0x9D, 0x9E, 0x3F, 0x7B, 0xFD, 0x37, 0x8E },
		.msg = { 0x2B, 0xC5, 0x3B, 0xCC, 0x90, 0x14, 0x35, 0x1E,
			 0xBE, 0x53, 0x92, 0x74, 0x37, 0xDC, 0x3B, 0x34,
			 0x45, 0x22, 0x1D, 0x36, 0x70, 0x60, 0xA7, 0xE0,
			 0x23, 0x87, 0xF0, 0x5D, 0x6A, 0xF8, 0x8C, 0xDA },
		.sig_hash = { 0x9B, 0x76, 0x74, 0x58, 0xCC, 0x66, 0xB0, 0xCA,
			      0xC8, 0xCB, 0xB2, 0x36, 0x88, 0xAE, 0x62, 0xA0,
			      0x31, 0xAA, 0x0C, 0x0C, 0x1A, 0x2A, 0x94, 0xD0,
			      0x5B, 0xCC, 0xE6, 0x3F, 0x89, 0xF6, 0x62, 0xDE },
	},
	{
		.seed = { 0x0E, 0xB9, 0xFC, 0x82, 0x94, 0x14, 0x92, 0xB5,
			  0x44, 0xB3, 0x35, 0x29, 0x9F, 0x0A, 0x99, 0x88,
			  0x14, 0x9B, 0x07, 0x34, 0x81, 0xE5, 0x24, 0xA4,
			  0x63, 0xE0, 0xDC, 0xBB, 0x5C, 0xA6, 0xD0, 0xCD },
		.key_hash = { 0x39, 0x81, 0xCD, 0xAE, 0x11, 0x6B, 0x3F, 0xBB,
			      0xD4, 0xFB, 0x5F, 0x84, 0xB6, 0x2E, 0xF8, 0xB7,
			      0x99, 0xE4, 0x85, 0x97, 0x80, 0x06, 0x3D, 0xE7,
			      0xCD, 0x7C, 0xD1, 0xFE, 0x1C, 0x95, 0xF1, 0x2A },
		.msg = { 0x91, 0xA6, 0xC4, 0xDA, 0x9E, 0xFA, 0x41, 0xC5,
			 0x89, 0x18, 0x3A, 0x46, 0x0B, 0xEB, 0x2B, 0xF7,
			 0x17, 0xA6, 0x35, 0x38, 0xAD, 0x67, 0x76, 0x98,
			 0xC2, 0xF1, 0xFB, 0xFD, 0x4E, 0xE5, 0xFB, 0x03 },
		.sig_hash = { 0x13, 0x30, 0x50, 0x97, 0x57, 0x04, 0x2F, 0xF7,
			      0xCE, 0x5D, 0x37, 0x0D, 0xAC, 0x53, 0xEF, 0xF6,
			      0x45, 0xD3, 0x87, 0xE9, 0xF9, 0xF5, 0x9E, 0x26,
			      0xDA, 0x7C, 0xA4, 0x78, 0x15, 0xC2, 0xBF, 0x59 },
	},
	{
		.seed = { 0x6C, 0xB6, 0x03, 0x0A, 0xA7, 0x6C, 0x4F, 0x40,
			  0x79, 0xFC, 0x03, 0x96, 0x66, 0x4F, 0xF3, 0x61,
			  0xB9, 0x94, 0x69, 0x7D, 0xB2, 0xFE, 0x9F, 0x18,
			  0x28, 0x35, 0xCA, 0x0A, 0x93, 0xFE, 0x6B, 0x3B },
		.key_hash = { 0xE7, 0x7B, 0xF7, 0x34, 0x34, 0x96, 0x0A, 0x36,
			      0xBF, 0x59, 0x72, 0x4E, 0x8B, 0x26, 0x37, 0x0E,
			      0x7F, 0x84, 0x48, 0x05, 0x63, 0xC0, 0xBD, 0xC7,
			      0x5A, 0x5F, 0xAF, 0x2B, 0x47, 0xC0, 0xA5, 0x9B },
		.msg = { 0x35, 0xC0, 0x34, 0xA8, 0xD7, 0x7C, 0xBD, 0x04,
			 0x2F, 0xBC, 0x6F, 0x00, 0x83, 0xFA, 0x29, 0x37,
			 0x4F, 0x7A, 0xDC, 0x8F, 0x66, 0xCC, 0xED, 0x05,
			 0x56, 0xF6, 0x9D, 0x18, 0x14, 0xE4, 0xD4, 0x53 },
		.sig_hash = { 0xEE, 0xD5, 0xA7, 0x8D, 0xC8, 0x3D, 0x3F, 0x0D,
			      0xD6, 0xD2, 0xCD, 0x17, 0x76, 0x5F, 0x3C, 0x71,
			      0xCB, 0xE3, 0xD2, 0xDD, 0x1C, 0x28, 0x2A, 0x80,
			      0x05, 0x77, 0xA3, 0xD8, 0x8E, 0x55, 0x32, 0xB5 },
	},
	{
		.seed = { 0x96, 0xEC, 0x11, 0xB9, 0xD0, 0x89, 0xE5, 0x86,
			  0xE7, 0x68, 0x6E, 0xE4, 0xA0, 0xD0, 0xEF, 0xD7,
			  0x6E, 0x4B, 0x03, 0xD4, 0xA3, 0xBC, 0x1A, 0x1C,
			  0xC1, 0x9E, 0x3E, 0x6D, 0x9B, 0x0B, 0x09, 0x32 },
		.key_hash = { 0x64, 0x94, 0xB7, 0x02, 0x09, 0xB2, 0x95, 0x7B,
			      0x4F, 0x2F, 0xEF, 0xFD, 0x60, 0x8F, 0x46, 0xF2,
			      0xEE, 0x23, 0x04, 0x48, 0x05, 0x5E, 0x85, 0xF2,
			      0x7A, 0xCF, 0x75, 0x04, 0xDD, 0x52, 0xBD, 0x86 },
		.msg = { 0x86, 0x00, 0x36, 0xA4, 0x5D, 0x33, 0x1B, 0xCD,
			 0x28, 0xDE, 0xC0, 0x68, 0x41, 0x23, 0x3F, 0xCB,
			 0x73, 0xF6, 0xDD, 0x65, 0x15, 0x60, 0x4C, 0x39,
			 0xF8, 0x5F, 0xA7, 0x90, 0x32, 0x6F, 0x1C, 0x70 },
		.sig_hash = { 0xEE, 0xE8, 0x52, 0x99, 0xE4, 0xC2, 0x05, 0xD5,
			      0x83, 0x30, 0x13, 0xB2, 0x2A, 0xD2, 0x1B, 0x45,
			      0x9A, 0x24, 0x1F, 0xC5, 0xF9, 0xFD, 0x97, 0xC5,
			      0xBA, 0xB3, 0x30, 0x68, 0xB6, 0x1F, 0x14, 0x59 },
	},
	{
		.seed = { 0x96, 0xEC, 0x11, 0xB9, 0xD0, 0x89, 0xE5, 0x86,
			  0xE7, 0x68, 0x6E, 0xE4, 0xA0, 0xD0, 0xEF, 0xD7,
			  0x6E, 0x4B, 0x03, 0xD4, 0xA3, 0xBC, 0x1A, 0x1C,
			  0xC1, 0x9E, 0x3E, 0x6D, 0x9B, 0x0B, 0x09, 0x32 },
		.key_hash = { 0x64, 0x94, 0xB7, 0x02, 0x09, 0xB2, 0x95, 0x7B,
			      0x4F, 0x2F, 0xEF, 0xFD, 0x60, 0x8F, 0x46, 0xF2,
			      0xEE, 0x23, 0x04, 0x48, 0x05, 0x5E, 0x85, 0xF2,
			      0x7A, 0xCF, 0x75, 0x04, 0xDD, 0x52, 0xBD, 0x86 },
		.msg = { 0xEB, 0x9E, 0x8D, 0xD8, 0xC0, 0x13, 0xFF, 0x6B,
			 0x35, 0x43, 0x45, 0x44, 0x95, 0x6D, 0x35, 0xD9,
			 0xBF, 0xDC, 0xD0, 0x08, 0xC9, 0xDB, 0x10, 0x66,
			 0x8D, 0xAA, 0x4C, 0x41, 0xE0, 0x1A, 0x98, 0xD6 },
		.sig_hash = { 0x70, 0x1A, 0x51, 0x42, 0x9F, 0x14, 0x4D, 0x5D,
			      0x94, 0x60, 0xE5, 0x08, 0x50, 0xF5, 0x5A, 0x07,
			      0xF3, 0x5F, 0x72, 0x12, 0x48, 0xD2, 0x15, 0xEF,
			      0xDC, 0xEC, 0xCA, 0x02, 0xE9, 0xAC, 0x1C, 0xF2 },
	},
	{
		.seed = { 0xDA, 0x0A, 0xAB, 0x12, 0x0F, 0x3C, 0xAF, 0x12,
			  0xB6, 0x2D, 0x72, 0xC4, 0xB7, 0x64, 0xFE, 0x47,
			  0x50, 0x24, 0x10, 0x12, 0x5F, 0xA3, 0x13, 0x78,
			  0x27, 0xAA, 0x55, 0xF8, 0xB1, 0xB0, 0xAF, 0xFA },
		.key_hash = { 0xE9, 0x1C, 0xC1, 0x90, 0xF7, 0xDD, 0x83, 0x57,
			      0xA5, 0xAA, 0xDD, 0xEF, 0x6A, 0xB7, 0x17, 0xB7,
			      0xB3, 0xAC, 0x4C, 0xCB, 0x3F, 0x7D, 0xA9, 0x50,
			      0x45, 0x3C, 0xD9, 0x2A, 0x39, 0x79, 0x91, 0xFF },
		.msg = { 0x54, 0x67, 0xA7, 0xF2, 0xB8, 0x2F, 0x60, 0x10,
			 0xCF, 0xE6, 0x58, 0xAE, 0x18, 0xB7, 0x2F, 0x34,
			 0x7A, 0x9A, 0xCC, 0x7C, 0x4F, 0xC9, 0x03, 0x03,
			 0xAD, 0xF9, 0x3F, 0xFB, 0x5F, 0x61, 0x2A, 0x63 },
		.sig_hash = { 0xA8, 0x22, 0x58, 0xC5, 0x3B, 0x59, 0x34, 0x63,
			      0x8F, 0x26, 0xD6, 0xA2, 0x5B, 0x5E, 0x09, 0x3D,
			      0x37, 0x24, 0x01, 0x2E, 0x79, 0xA3, 0x39, 0x2F,
			      0xFA, 0x39, 0x81, 0x62, 0xC4, 0x10, 0x55, 0x17 },
	},
	{
		.seed = { 0x56, 0x3E, 0x18, 0x4C, 0x05, 0xA6, 0x94, 0x5E,
			  0x6C, 0x72, 0x22, 0x5E, 0x19, 0x73, 0x75, 0xEC,
			  0x81, 0x86, 0x46, 0x0A, 0xDF, 0x6B, 0x97, 0x0E,
			  0xD8, 0x37, 0xED, 0xB2, 0xCC, 0x37, 0xCE, 0x0D },
		.key_hash = { 0x65, 0x4A, 0xB2, 0x60, 0x0B, 0xD2, 0x99, 0x86,
			      0xF2, 0x4A, 0xB4, 0xAC, 0x0B, 0xC2, 0xF1, 0xFF,
			      0x6E, 0x32, 0xA2, 0xEB, 0x18, 0x9A, 0xB5, 0x8D,
			      0x0A, 0x33, 0x57, 0x9B, 0x92, 0x13, 0x0D, 0xC4 },
		.msg = { 0x24, 0x03, 0x1D, 0xAF, 0x81, 0xB8, 0xBD, 0xD1,
			 0x51, 0xFC, 0x61, 0xF5, 0xAD, 0x91, 0x9E, 0x82,
			 0xFA, 0x18, 0xDF, 0xD2, 0xE1, 0xEB, 0x47, 0x25,
			 0xD8, 0x2E, 0x81, 0x87, 0x9B, 0x00, 0x20, 0xF6 },
		.sig_hash = { 0xAE, 0x5C, 0x85, 0xBE, 0xD5, 0x86, 0x1B, 0x80,
			      0xEA, 0x20, 0x5D, 0x03, 0x0D, 0x0D, 0x47, 0x1D,
			      0x87, 0xE7, 0x2E, 0x65, 0x8A, 0x11, 0x41, 0x60,
			      0x84, 0x81, 0xA1, 0x16, 0xCA, 0xF9, 0xFA, 0x31 },
	},
	{
		.seed = { 0x4E, 0x21, 0xC3, 0xCD, 0xB8, 0x38, 0x08, 0x3C,
			  0x5D, 0xC6, 0x8A, 0xD4, 0x8D, 0xA7, 0x0A, 0x1C,
			  0x3B, 0x85, 0x8B, 0x55, 0xE1, 0x47, 0x72, 0xA6,
			  0x08, 0xBD, 0xD7, 0xFE, 0x6F, 0xC1, 0x06, 0x81 },
		.key_hash = { 0x73, 0xA5, 0xE9, 0x4A, 0x0D, 0x73, 0x26, 0xDF,
			      0xAB, 0xDC, 0xCC, 0x01, 0x20, 0xE7, 0xDF, 0x22,
			      0xCA, 0x7E, 0xA8, 0xF2, 0x0E, 0x3C, 0xE3, 0x80,
			      0x59, 0x15, 0xB3, 0x2A, 0x7A, 0x8B, 0x44, 0xF7 },
		.msg = { 0xD5, 0x4E, 0x63, 0x4A, 0xF8, 0xB5, 0xF5, 0x5A,
			 0x5D, 0xC4, 0xF8, 0x17, 0x55, 0x92, 0x06, 0x63,
			 0xC8, 0xD3, 0x3B, 0x0B, 0x76, 0xCB, 0xA1, 0x3C,
			 0xAB, 0x15, 0xF5, 0x64, 0xA5, 0x70, 0x2E, 0xAF },
		.sig_hash = { 0x2D, 0xFD, 0x78, 0xBF, 0xB7, 0x84, 0x8D, 0x7E,
			      0x5D, 0xD8, 0x10, 0xCC, 0xBB, 0x4D, 0x1C, 0x4A,
			      0x00, 0xCE, 0x51, 0x4E, 0x63, 0xF3, 0x4C, 0xAB,
			      0xDF, 0x53, 0x69, 0x58, 0xCD, 0xE6, 0xE0, 0xD1 },
	},
	{
		.seed = { 0xE4, 0x43, 0xF1, 0xF2, 0x00, 0x6E, 0x78, 0x87,
			  0x85, 0xD9, 0x41, 0xA7, 0x5F, 0xB8, 0x79, 0xF6,
			  0x82, 0xB9, 0xA7, 0x23, 0x83, 0x89, 0xAD, 0xA2,
			  0x54, 0x1E, 0xAB, 0xE2, 0xE2, 0x8E, 0xEB, 0xD5 },
		.key_hash = { 0x3B, 0x1A, 0x78, 0x15, 0xB6, 0x25, 0xA5, 0xEE,
			      0xB7, 0x98, 0x3A, 0x22, 0x58, 0x0D, 0x17, 0x57,
			      0xA1, 0xC8, 0x80, 0xF7, 0x62, 0xD7, 0xFE, 0x01,
			      0x10, 0x9F, 0xE1, 0xB7, 0x3E, 0x3B, 0x4F, 0x0E },
		.msg = { 0xC9, 0x33, 0x26, 0xB1, 0xE7, 0x6E, 0xC0, 0x26,
			 0xDA, 0x5C, 0xA2, 0x29, 0xAE, 0x46, 0x64, 0x71,
			 0x5B, 0x78, 0xEB, 0x4D, 0xB7, 0x43, 0xBC, 0x03,
			 0x1D, 0x54, 0xBE, 0x08, 0xF7, 0x62, 0x81, 0x7A },
		.sig_hash = { 0x0B, 0x2C, 0x4C, 0x82, 0x7D, 0xA8, 0x12, 0x61,
			      0x95, 0x9A, 0x49, 0x21, 0x72, 0x9D, 0xAE, 0x65,
			      0x45, 0x32, 0x6E, 0x7B, 0x7D, 0x3D, 0xE9, 0xE5,
			      0x61, 0x5D, 0xC3, 0x6C, 0xBB, 0x2B, 0x24, 0xF4 },
	},
	{
		.seed = { 0xBC, 0x0E, 0x8F, 0x7F, 0x35, 0x16, 0xA9, 0xC8,
			  0x6D, 0x20, 0xBF, 0xF7, 0x5A, 0xE0, 0x56, 0x90,
			  0x5D, 0x84, 0x04, 0x14, 0xDB, 0xC6, 0x62, 0xB4,
			  0x1C, 0x8F, 0xD2, 0x2C, 0x4B, 0xD7, 0x26, 0x02 },
		.key_hash = { 0x41, 0x70, 0x19, 0x8F, 0x73, 0x49, 0x3F, 0x08,
			      0x1E, 0x38, 0x27, 0x13, 0x5B, 0x00, 0xC8, 0x9D,
			      0x38, 0x9F, 0x24, 0xDA, 0x6F, 0x30, 0x26, 0x68,
			      0x49, 0x38, 0xAE, 0x28, 0x4F, 0x38, 0xCF, 0xF6 },
		.msg = { 0x79, 0xE1, 0x88, 0x96, 0x17, 0xC5, 0x50, 0xF5,
			 0x44, 0xE0, 0xBF, 0xF6, 0x74, 0x6C, 0x89, 0xFB,
			 0x01, 0x8F, 0x97, 0x01, 0x0E, 0x3A, 0x72, 0x64,
			 0x8A, 0x36, 0xBD, 0x84, 0x4E, 0x7F, 0xD7, 0x02 },
		.sig_hash = { 0xEF, 0x9C, 0x71, 0x2D, 0x5E, 0x96, 0xD4, 0x37,
			      0xD5, 0xCA, 0x30, 0xE4, 0xE0, 0xA2, 0x88, 0x92,
			      0x89, 0x77, 0x27, 0x02, 0x31, 0xE4, 0x59, 0x35,
			      0x0F, 0xC4, 0x73, 0x0F, 0x1B, 0x63, 0xDA, 0x1A },
	},
	{
		.seed = { 0xF8, 0x29, 0x9C, 0x7C, 0x15, 0x5E, 0x6A, 0x54,
			  0x3C, 0x3B, 0xB2, 0xED, 0x85, 0xC5, 0xB7, 0xDD,
			  0xF4, 0x1A, 0x1C, 0xA2, 0xC7, 0x9A, 0xBB, 0x91,
			  0x46, 0xE6, 0x20, 0xA5, 0xE3, 0xC6, 0xCD, 0x52 },
		.key_hash = { 0xAC, 0xC9, 0x3A, 0x8A, 0x6C, 0xE0, 0x9E, 0x91,
			      0x33, 0x17, 0x65, 0xEB, 0x3E, 0x0B, 0x43, 0xD5,
			      0x14, 0x22, 0x0A, 0x62, 0x22, 0x84, 0x17, 0x53,
			      0xA4, 0x77, 0x50, 0x8F, 0x33, 0x16, 0xD9, 0x96 },
		.msg = { 0x7C, 0x35, 0x2A, 0x16, 0x21, 0xB0, 0xB7, 0x1D,
			 0xB7, 0xC9, 0x88, 0xF3, 0xC7, 0x8E, 0x13, 0xD0,
			 0xDE, 0xAF, 0x15, 0x2F, 0x33, 0x7C, 0xA3, 0xB9,
			 0xD6, 0xDD, 0xBB, 0x77, 0x35, 0x85, 0x7F, 0xE4 },
		.sig_hash = { 0x78, 0x77, 0x05, 0x01, 0x0E, 0xFF, 0xA3, 0xF9,
			      0xB2, 0xD3, 0x5C, 0xFD, 0x7A, 0xB9, 0xDF, 0x0A,
			      0x71, 0x62, 0xA3, 0x81, 0x61, 0x8B, 0x1F, 0x91,
			      0xA7, 0x62, 0x20, 0x38, 0xB6, 0x87, 0x67, 0xF8 },
	},
	{
		.seed = { 0x61, 0x33, 0x55, 0xAC, 0x3C, 0x5A, 0x47, 0x21,
			  0xEC, 0xA5, 0xC3, 0x5A, 0x98, 0x33, 0x51, 0xCB,
			  0x48, 0xE7, 0xDB, 0xA3, 0x09, 0x14, 0xF0, 0x4A,
			  0xCB, 0x1C, 0xD0, 0xEC, 0xA6, 0xB4, 0x67, 0x97 },
		.key_hash = { 0x34, 0x6D, 0x05, 0x40, 0xD9, 0xCA, 0x26, 0x18,
			      0xC7, 0xB4, 0x2A, 0xD3, 0xD4, 0x3A, 0x23, 0x6C,
			      0x87, 0x62, 0x56, 0x65, 0xBA, 0x66, 0x20, 0x6D,
			      0xCF, 0xCD, 0xE9, 0x4A, 0xB6, 0x07, 0x34, 0x9C },
		.msg = { 0x47, 0xFB, 0x0D, 0x33, 0x6E, 0xAC, 0x39, 0xE0,
			 0x2D, 0x4C, 0x2A, 0x1D, 0xB7, 0x4B, 0x41, 0x96,
			 0xC3, 0x49, 0x0B, 0x6E, 0xE2, 0xF0, 0xCA, 0x59,
			 0xD9, 0xC7, 0xC8, 0xEA, 0xEA, 0x53, 0xB4, 0xDA },
		.sig_hash = { 0x32, 0x4D, 0x20, 0xD6, 0x9B, 0x4D, 0xF8, 0xAA,
			      0xD0, 0xD3, 0x8B, 0xCA, 0xEB, 0x90, 0x0E, 0x41,
			      0xD6, 0x9F, 0xF1, 0x29, 0xFF, 0x57, 0x54, 0x04,
			      0x4B, 0x31, 0xE5, 0x56, 0xCC, 0x37, 0xC3, 0x8A },
	},
	{
		.seed = { 0xB6, 0xAA, 0x3B, 0xA3, 0xB3, 0x28, 0x9E, 0x24,
			  0x84, 0xB7, 0xAD, 0x76, 0xAD, 0x17, 0xC7, 0xB8,
			  0x6C, 0xEA, 0xE6, 0x32, 0xC1, 0x1B, 0x43, 0xE4,
			  0xC0, 0x82, 0x65, 0x43, 0xFF, 0xC6, 0x80, 0x54 },
		.key_hash = { 0x67, 0x3D, 0x01, 0xFE, 0xD8, 0x8C, 0x52, 0x7B,
			      0x29, 0xA7, 0xAD, 0xC2, 0x6F, 0x9C, 0x73, 0xEA,
			      0x35, 0x2E, 0xB4, 0x33, 0x7E, 0x5A, 0x20, 0x67,
			      0x0B, 0xF3, 0x31, 0xAE, 0x72, 0x50, 0x02, 0x5E },
		.msg = { 0xBE, 0x77, 0xA2, 0xBF, 0xA9, 0xE5, 0xF0, 0xF0,
			 0x37, 0x94, 0x87, 0x7A, 0xF7, 0x3D, 0xA4, 0x95,
			 0xD0, 0xC3, 0xA8, 0x09, 0xEB, 0x36, 0x5A, 0x5D,
			 0xE5, 0x49, 0x0C, 0x3A, 0x4B, 0x4F, 0xBC, 0x90 },
		.sig_hash = { 0xBE, 0xEA, 0x38, 0x88, 0xAF, 0x93, 0x7E, 0x01,
			      0x1A, 0x8D, 0x77, 0x1F, 0x45, 0x1A, 0x39, 0x42,
			      0x55, 0x67, 0x0E, 0x30, 0x3E, 0x50, 0x7F, 0x46,
			      0x02, 0x89, 0xB0, 0xB0, 0x19, 0xCE, 0x47, 0x0C },
	},
	{
		.seed = { 0xC5, 0x3F, 0xB3, 0x94, 0x9E, 0xFE, 0xB0, 0x5F,
			  0xAB, 0xA2, 0x06, 0xF5, 0xA6, 0xE2, 0xB4, 0xD2,
			  0x14, 0xC3, 0x64, 0x54, 0xC5, 0x5F, 0xA3, 0x8F,
			  0x3F, 0x57, 0x1B, 0xF1, 0xAB, 0x83, 0xA8, 0xAC },
		.key_hash = { 0x34, 0x23, 0x70, 0x8B, 0x76, 0x24, 0x52, 0xEA,
			      0x34, 0xE4, 0xA1, 0x75, 0xC5, 0x5D, 0xC0, 0x5E,
			      0xDD, 0x77, 0x66, 0xB4, 0x9C, 0x78, 0x32, 0xEF,
			      0xB2, 0xB5, 0x1E, 0x03, 0xBB, 0x73, 0xDF, 0x27 },
		.msg = { 0x5D, 0x1D, 0x45, 0x55, 0xCF, 0x47, 0xB8, 0xF5,
			 0x3F, 0x8F, 0x8C, 0x32, 0x5A, 0x2C, 0x18, 0xF4,
			 0x0A, 0xA5, 0x42, 0xE8, 0x1C, 0xFB, 0xA5, 0x1D,
			 0x6C, 0x26, 0x12, 0x7F, 0x4A, 0x5F, 0x07, 0xBF },
		.sig_hash = { 0xB7, 0xB6, 0xF0, 0x2F, 0x21, 0x6A, 0xF4, 0xB1,
			      0x73, 0xCF, 0xA2, 0x46, 0x8E, 0xC1, 0x57, 0x0C,
			      0x0B, 0x1C, 0x79, 0x03, 0xCC, 0x5E, 0x7B, 0x15,
			      0xFA, 0x78, 0xD5, 0xFA, 0x52, 0x63, 0xFF, 0x04 },
	},
	{
		.seed = { 0xD9, 0xBA, 0xC8, 0xAC, 0x09, 0x21, 0x3F, 0x46,
			  0x35, 0x8B, 0x7E, 0xF7, 0xEB, 0x0D, 0x9C, 0xAF,
			  0xC5, 0x49, 0x2A, 0x4A, 0x47, 0x3A, 0x01, 0xBC,
			  0x6D, 0x70, 0x8E, 0x4D, 0x84, 0x59, 0x88, 0x1A },
		.key_hash = { 0x5A, 0xF1, 0xDA, 0xB8, 0x93, 0x66, 0x2B, 0x90,
			      0xF8, 0xDC, 0x13, 0xAA, 0x4C, 0x01, 0x80, 0x61,
			      0x0F, 0x20, 0xF3, 0x3C, 0xDF, 0x56, 0xEF, 0xB4,
			      0xF7, 0xF6, 0x3D, 0x26, 0xC8, 0x57, 0xAF, 0xCC },
		.msg = { 0xFF, 0x05, 0xD3, 0x33, 0xB0, 0xF9, 0x08, 0xE8,
			 0x39, 0xDC, 0xB8, 0xB2, 0xD0, 0x2B, 0xBE, 0x88,
			 0x64, 0x04, 0x83, 0x55, 0xEF, 0x83, 0x8C, 0xE4,
			 0x13, 0x70, 0x1D, 0x9B, 0x5F, 0xFE, 0x8B, 0x22 },
		.sig_hash = { 0x5C, 0x88, 0x2C, 0xE4, 0x20, 0x5F, 0x92, 0x14,
			      0xDC, 0xB1, 0xAC, 0xB4, 0xB4, 0xF8, 0xDF, 0xE3,
			      0x1D, 0x3A, 0x49, 0xB6, 0xDD, 0x20, 0x2B, 0xFF,
			      0x10, 0xB7, 0xFC, 0xC4, 0x46, 0xCC, 0x50, 0xAA },
	}
};

static int dilithium_edge_tester_internal(
	const struct dilithium_edge_case *tc,
	int (*_lc_dilithium_keypair_from_seed)(struct lc_dilithium_pk *pk,
					       struct lc_dilithium_sk *sk,
					       const uint8_t *seed,
					       size_t seedlen),
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sig sig;
		uint8_t msg[10];
	};
	uint8_t digest[LC_SHA256_SIZE_DIGEST];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SHA256_CTX_ON_STACK(sha256);
	int ret = 0;

	CKINT(_lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, tc->seed,
					      sizeof(tc->seed)));

	/* SHA2-256(pk || sk) */
	lc_hash_init(sha256);

	lc_hash_update(sha256, ws->pk.pk, sizeof(ws->pk.pk));
	lc_hash_update(sha256, ws->sk.sk, sizeof(ws->sk.sk));

	lc_hash_final(sha256, digest);

	ret = lc_compare(digest, tc->key_hash, LC_SHA256_SIZE_DIGEST,
			 "Key hash");
	if (ret)
		return ret;

	CKINT(_lc_dilithium_sign(&ws->sig, tc->msg, sizeof(tc->msg), &ws->sk,
				 NULL));

	/* SHA256(sig) */
	lc_hash(lc_sha256, ws->sig.sig, sizeof(ws->sig.sig), digest);

	ret = lc_compare(digest, tc->sig_hash, LC_SHA256_SIZE_DIGEST,
			 "Signature hash");
	if (ret)
		return ret;

out:
	LC_RELEASE_MEM(ws);
	return ret ? 1 : 0;
}

int dilithium_edge_tester(
	int (*_lc_dilithium_keypair_from_seed)(struct lc_dilithium_pk *pk,
					       struct lc_dilithium_sk *sk,
					       const uint8_t *seed,
					       size_t seedlen),
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(tcs); i++)
		ret += dilithium_edge_tester_internal(
			&tcs[i], _lc_dilithium_keypair_from_seed,
			_lc_dilithium_sign);

	return ret;
}