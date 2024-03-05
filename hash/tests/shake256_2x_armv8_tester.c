/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_cshake.h"
#include "lc_sha3.h"
#include "visibility.h"

#include "shake_2x_armv8.h"

static int shake256_2x_tester(void)
{
	static const uint8_t msg1[] = { 0x6C, 0x9E, 0xC8, 0x5C, 0xBA, 0xBA,
					0x62, 0xF5, 0xBC, 0xFE, 0xA1, 0x9E,
					0xB9, 0xC9, 0x20, 0x52, 0xD8, 0xFF,
					0x18, 0x81, 0x52, 0xE9, 0x61, 0xC1,
					0xEC, 0x5C, 0x75, 0xBF, 0xC3, 0xC9,
					0x1C, 0x8D };
	static const uint8_t exp1[] = { 0x7d, 0x6a, 0x09, 0x6e, 0x13, 0x66,
					0x1d, 0x9d, 0x0e, 0xca, 0xf5, 0x38,
					0x30, 0xa1, 0x92, 0x87, 0xe0, 0xb3,
					0x6e, 0xce, 0x48, 0x82, 0xeb, 0x58,
					0x0b, 0x78, 0x5c, 0x1d, 0xef, 0x2d,
					0xe5, 0xaa, 0x6c };
	uint8_t act1[sizeof(exp1)];
	uint8_t act2[sizeof(exp1)];
	uint8_t *out0 = act1;
	uint8_t *out1 = act2;
	const uint8_t *in0 = msg1;
	const uint8_t *in1 = msg1;
	int ret;

	shake256x2_armv8(out0, out1, sizeof(exp1), in0, in1, sizeof(msg1));

	ret = lc_compare(act1, exp1, sizeof(act1), "SHAKE256 2x ARMv8 lane 1");
	if (ret)
		return ret;
	ret = lc_compare(act2, exp1, sizeof(act2), "SHAKE256 2x ARMv8 lane 2");
	if (ret)
		return ret;

	return 0;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return shake256_2x_tester();
}
