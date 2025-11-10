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
#include "fips_mode.h"
#include "hmac_selftest.h"
#include "lc_hmac.h"
#include "lc_sha512.h"

int hmac_sha512_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg_512[] = { FIPS140_MOD(0xC1),
					   0xB4,
					   0x8B,
					   0x27,
					   0x02,
					   0xC2,
					   0xC6,
					   0x05,
					   0xC0,
					   0xC8,
					   0x24,
					   0xDA,
					   0x56,
					   0x30,
					   0xFD,
					   0x90 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key_512[] = { 0x16, 0xD9, 0x8A, 0x84, 0x8C, 0x44,
					   0x94, 0x8B, 0xB3, 0x3B, 0x69, 0x67,
					   0xCE, 0xB9, 0xB3, 0x3B };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_512[] = {
		0x69, 0x9a, 0xa4, 0x59, 0x83, 0x85, 0x73, 0xbb, 0x74, 0x42,
		0xd8, 0xc5, 0x22, 0xde, 0x6f, 0x04, 0x4d, 0xf9, 0xb8, 0x82,
		0x7b, 0x1a, 0xcf, 0x1b, 0x9a, 0xa5, 0x30, 0xd8, 0x5c, 0x9a,
		0x49, 0x8d, 0x83, 0x0f, 0xbb, 0xf8, 0x22, 0xaf, 0xc0, 0xf8,
		0xcc, 0xcc, 0x86, 0xc9, 0xd4, 0xbe, 0xe5, 0xcc, 0x29, 0xb5,
		0xf2, 0xb0, 0x83, 0x92, 0x9d, 0x17, 0x15, 0x14, 0xf2, 0x91,
		0x83, 0xf2, 0xb7, 0x94
	};
	uint8_t act[LC_SHA512_SIZE_DIGEST];

	lc_hmac_nocheck(lc_sha512, key_512, sizeof(key_512), msg_512,
			sizeof(msg_512), act);
	return lc_compare_selftest(LC_ALG_STATUS_HMAC, act, exp_512,
				   sizeof(exp_512), "HMAC SHA2-512");
}
