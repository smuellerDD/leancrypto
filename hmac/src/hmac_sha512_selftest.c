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
	static const uint8_t msg_512[] = { FIPS140_MOD(0xC1), 0xB4, 0x8B, 0x27, 0x02, 0xC2,
					   0xC6, 0x05, 0xC0, 0xC8, 0x24, 0xDA,
					   0x56, 0x30, 0xFD, 0x90 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key_512[] = { 0x16, 0xD9, 0x8A, 0x84, 0x8C,
					   0x44, 0x94, 0x8B, 0xB3, 0x3B,
					   0x69, 0x67, 0xCE, 0xB9 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_512[] = {
		0xb2, 0x0d, 0x95, 0xcf, 0x2d, 0x97, 0x4e, 0x02, 0x11, 0x50,
		0xd2, 0xe1, 0xdb, 0xf8, 0xd2, 0x9e, 0x59, 0x94, 0x9f, 0x07,
		0xa0, 0x26, 0x46, 0xde, 0xc8, 0x0b, 0xbb, 0xf3, 0x70, 0xbe,
		0xf7, 0x58, 0x89, 0xbf, 0x92, 0x59, 0x1e, 0x3c, 0x3b, 0x1c,
		0x50, 0x49, 0xe8, 0x03, 0x1c, 0x45, 0x67, 0x5d, 0x5d, 0xa1,
		0x5c, 0x8f, 0xe3, 0x51, 0xed, 0xd1, 0x14, 0x80, 0x08, 0x5a,
		0x9a, 0x51, 0x6a, 0xa7
	};
	uint8_t act[LC_SHA3_512_SIZE_DIGEST];

	lc_hmac_nocheck(lc_sha512, key_512, sizeof(key_512), msg_512,
			sizeof(msg_512), act);
	return lc_compare_selftest(LC_ALG_STATUS_HMAC, act, exp_512,
				   sizeof(exp_512), "HMAC SHA2-512");
}
