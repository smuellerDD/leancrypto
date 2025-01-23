/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "shake_4x_avx2.h"

static int shake128_4x_tester(void)
{
	static const uint8_t msg1[] = { 0xBE, 0x94, 0xD8, 0x3D, 0x37,
					0x66, 0xCF, 0x3E, 0xD3, 0x0A,
					0x11, 0x0C, 0x47, 0xA2 };
	static const uint8_t exp1[] = { 0xB0, 0x46, 0x01, 0xAA, 0x4D, 0x2C,
					0x30, 0xF6, 0x5F, 0x94, 0xD7, 0x02,
					0x5D, 0xBD, 0x22, 0x39 };
	uint8_t act1[sizeof(exp1)];
	uint8_t act2[sizeof(exp1)];
	uint8_t act3[sizeof(exp1)];
	uint8_t act4[sizeof(exp1)];
	uint8_t *out0 = act1;
	uint8_t *out1 = act2;
	uint8_t *out2 = act3;
	uint8_t *out3 = act4;

	const uint8_t *in0 = msg1;
	const uint8_t *in1 = msg1;
	const uint8_t *in2 = msg1;
	const uint8_t *in3 = msg1;
	int ret;

	shake128x4(out0, out1, out2, out3, sizeof(exp1), in0, in1, in2, in3,
		   sizeof(msg1));

	ret = lc_compare(act1, exp1, sizeof(act1), "SHAKE128 4x AVX2 lane 1");
	if (ret)
		return ret;
	ret = lc_compare(act2, exp1, sizeof(act2), "SHAKE128 4x AVX2 lane 2");
	if (ret)
		return ret;
	ret = lc_compare(act3, exp1, sizeof(act3), "SHAKE128 4x AVX2 lane 3");
	if (ret)
		return ret;
	ret = lc_compare(act4, exp1, sizeof(act4), "SHAKE128 4x AVX2 lane 4");
	if (ret)
		return ret;

	return 0;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return shake128_4x_tester();
}
