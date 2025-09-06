/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ascon_selftest.h"
#include "compare.h"
#include "hash_common.h"

void ascon_256_selftest_common(const struct lc_hash *ascon)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = { 0xD7, 0xE4, 0xC7, 0xED, 0x9B, 0x8A, 0x32,
				       0x5C, 0xD0, 0x8B, 0x9E, 0xF2, 0x59, 0xF8,
				       0x87, 0x70, 0x54, 0xEC, 0xD8, 0x30, 0x4F,
				       0xE1, 0xB2, 0xD7, 0xFD, 0x84, 0x71, 0x37,
				       0xDF, 0x67, 0x27, 0xEE };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_ASCON256);

	lc_hash_nocheck(ascon, msg, sizeof(msg), act);

	lc_compare_selftest(LC_ALG_STATUS_ASCON256, act, exp, sizeof(exp),
			    "Ascon 256");
}

void ascon_xof_selftest_common(const struct lc_hash *ascon)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = { 0x21, 0xF7, 0xFD, 0x74, 0x58, 0x8E, 0x24,
				       0x4A, 0xF4, 0x5F, 0x90, 0x16, 0xB8, 0xDB,
				       0x19, 0xB8, 0x57, 0xEC, 0x5E, 0x62, 0x08,
				       0x97, 0x8C, 0xFC, 0x1B, 0x46, 0x11, 0xED,
				       0x91, 0xFB, 0x38, 0xF8 };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_ASCONXOF);

	lc_xof_nocheck(ascon, msg, sizeof(msg), act, sizeof(act));

	lc_compare_selftest(LC_ALG_STATUS_ASCONXOF, act, exp, sizeof(exp),
			    "Ascon XOF");
}

void ascon_cxof_selftest_common(const struct lc_hash *ascon)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = { 0xE2, 0xFE, 0xE1, 0x11, 0xA8, 0xE4, 0xB6,
				       0x22, 0x46, 0x2F, 0x89, 0x7D, 0xA4, 0x8C,
				       0x02, 0xB8, 0x07, 0xCA, 0xDD, 0xC2, 0x80,
				       0x17, 0x18, 0x6D, 0xC8, 0x56, 0xD8, 0xCF,
				       0x3D, 0xC2, 0x02, 0x48 };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_ASCONCXOF);

	lc_xof_nocheck(ascon, msg, sizeof(msg), act, sizeof(act));

	lc_compare_selftest(LC_ALG_STATUS_ASCONCXOF, act, exp, sizeof(exp),
			    "Ascon CXOF");
}
