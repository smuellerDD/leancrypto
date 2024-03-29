/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
#include "ascon_selftest.h"

void ascon_128_selftest_common(const struct lc_hash *ascon, int *tested,
			       const char *impl)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = {
		0x80, 0x13, 0xEA, 0xAA, 0x19, 0x51, 0x58, 0x0A,
		0x7B, 0xEF, 0x7D, 0x29, 0xBA, 0xC3, 0x23, 0x37,
		0x7E, 0x64, 0xF2, 0x79, 0xEA, 0x73, 0xE6, 0x88,
		0x1B, 0x8A, 0xED, 0x69, 0x85, 0x5E, 0xF7, 0x64
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_hash(ascon, msg, sizeof(msg), act);
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

void ascon_128a_selftest_common(const struct lc_hash *ascon, int *tested,
				const char *impl)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = {
		0x7B, 0x4B, 0xD4, 0xD5, 0x73, 0x19, 0x66, 0x01,
		0x0E, 0xA4, 0xF5, 0xF3, 0x6C, 0x74, 0x36, 0x11,
		0x0C, 0x64, 0x19, 0x07, 0xD1, 0x2A, 0x1F, 0x12,
		0x16, 0x92, 0x2D, 0xEB, 0xD6, 0x1B, 0x13, 0xFE
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_hash(ascon, msg, sizeof(msg), act);
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

void ascon_xof_selftest_common(const struct lc_hash *ascon, int *tested,
			       const char *impl)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = {
		0x66, 0xFB, 0x74, 0x17, 0x47, 0x82, 0xAF, 0xED,
		0x89, 0x84, 0x78, 0xAA, 0x72, 0x90, 0x58, 0xD5,
		0xC3, 0x0A, 0xF1, 0x9A, 0xF2, 0xF5, 0xD4, 0xE1,
		0xCE, 0x65, 0xCD, 0x32, 0x05, 0x94, 0xEF, 0x66
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_xof(ascon, msg, sizeof(msg), act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

void ascon_xofa_selftest_common(const struct lc_hash *ascon, int *tested,
				const char *impl)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = {
		0xE2, 0xFE, 0xE1, 0x11, 0xA8, 0xE4, 0xB6, 0x22,
		0x46, 0x2F, 0x89, 0x7D, 0xA4, 0x8C, 0x02, 0xB8,
		0x07, 0xCA, 0xDD, 0xC2, 0x80, 0x17, 0x18, 0x6D,
		0xC8, 0x56, 0xD8, 0xCF, 0x3D, 0xC2, 0x02, 0x48
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_xof(ascon, msg, sizeof(msg), act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}
