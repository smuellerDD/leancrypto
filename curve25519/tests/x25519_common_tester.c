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

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "compare.h"
#include "../src/x25519_scalarmult.h"
#include "ret_checkers.h"
#include "visibility.h"

static int x25519_scalarmult_common_tester(unsigned int loops)
{
	/*
	 * Test vector is
	 * from https://github.com/jedisct1/libsodium.git/test/default/scalarmult7.c
	 * by taking variable p1 and printing out the out1 variable.
	 */
	static unsigned char p1[] = { 0x72, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7,
				      0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
				      0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26,
				      0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
				      0xaa, 0x9b, 0x4e, 0xea };
	static const uint8_t exp[] = { 0x03, 0xad, 0x40, 0x80, 0xc2, 0x91, 0x0b,
				       0x5e, 0x0b, 0xe2, 0x2f, 0x6c, 0x5f, 0x7c,
				       0x7e, 0x08, 0xe6, 0x42, 0x46, 0x2e, 0xf0,
				       0xec, 0x93, 0xa6, 0x54, 0xc5, 0xc3, 0x4d,
				       0xc9, 0x5b, 0x55, 0x6d };
	static const uint8_t scalar[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	uint8_t out[sizeof(exp)];
	unsigned int i;
	int ret;

	for (i = 0; i < loops; i++)
		CKINT(crypto_scalarmult_curve25519(out, scalar, p1));
	lc_compare(out, exp, sizeof(exp), "X25519 AVX scalar multiplication\n");

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argv;
	(void)argc;

	if (argc != 2)
		ret += x25519_scalarmult_common_tester(1);
	else
		ret += x25519_scalarmult_common_tester(100000);

	return ret;
}
