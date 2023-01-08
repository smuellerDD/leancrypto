/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "lc_kdf_fb.h"
#include "lc_sha256.h"
#include "visibility.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/FeedbackModeNOzeroiv.zip
 */
static int kdf_fb_tester(void)
{
	int ret;
	static const uint8_t key[] = {
		0x93, 0xf6, 0x98, 0xe8, 0x42, 0xee, 0xd7, 0x53,
		0x94, 0xd6, 0x29, 0xd9, 0x57, 0xe2, 0xe8, 0x9c,
		0x6e, 0x74, 0x1f, 0x81, 0x0b, 0x62, 0x3c, 0x8b,
		0x90, 0x1e, 0x38, 0x37, 0x6d, 0x06, 0x8e, 0x7b
	};
	static const uint8_t iv[] = {
		0x9f, 0x57, 0x5d, 0x90, 0x59, 0xd3, 0xe0, 0xc0,
		0x80, 0x3f, 0x08, 0x11, 0x2f, 0x8a, 0x80, 0x6d,
		0xe3, 0xc3, 0x47, 0x19, 0x12, 0xcd, 0xf4, 0x2b,
		0x09, 0x53, 0x88, 0xb1, 0x4b, 0x33, 0x50, 0x8e,
	};
	static const uint8_t label[] = {
		0x53, 0xb8, 0x9c, 0x18, 0x69, 0x0e, 0x20, 0x57,
		0xa1, 0xd1, 0x67, 0x82, 0x2e, 0x63, 0x6d, 0xe5,
		0x0b, 0xe0, 0x01, 0x85, 0x32, 0xc4, 0x31, 0xf7,
		0xf5, 0xe3, 0x7f, 0x77, 0x13, 0x92, 0x20, 0xd5,
		0xe0, 0x42, 0x59, 0x9e, 0xbe, 0x26, 0x6a, 0xf5,
		0x76, 0x7e, 0xe1, 0x8c, 0xd2, 0xc5, 0xc1, 0x9a,
		0x1f, 0x0f, 0x80
	};
	static const uint8_t exp[] = {
		0xbd, 0x14, 0x76, 0xf4, 0x3a, 0x4e, 0x31, 0x57,
		0x47, 0xcf, 0x59, 0x18, 0xe0, 0xea, 0x5b, 0xc0,
		0xd9, 0x87, 0x69, 0x45, 0x74, 0x77, 0xc3, 0xab,
		0x18, 0xb7, 0x42, 0xde, 0xf0, 0xe0, 0x79, 0xa9,
		0x33, 0xb7, 0x56, 0x36, 0x5a, 0xfb, 0x55, 0x41,
		0xf2, 0x53, 0xfe, 0xe4, 0x3c, 0x6f, 0xd7, 0x88,
		0xa4, 0x40, 0x41, 0x03, 0x85, 0x09, 0xe9, 0xee,
		0xb6, 0x8f, 0x7d, 0x65, 0xff, 0xbb, 0x5f, 0x95
	};
	uint8_t act[sizeof(exp)];

	static const uint8_t key2[] = {
		0x51, 0x5D, 0x42, 0x18, 0x50, 0x32, 0xD6, 0x3D,
		0x41, 0x89, 0x23, 0x71, 0xB6, 0x66, 0xC0, 0xA3
	};
	static const uint8_t iv2[] = {
		0x83, 0xAE, 0xC4, 0x0E, 0xC6, 0x5F, 0xE2, 0x0B,
		0x49, 0x4A, 0x88, 0x56, 0x1B, 0xDA, 0x5C, 0x69,
		0x22, 0xF7, 0xBF, 0x6A, 0x4F, 0xD9, 0x4F, 0x19,
		0x9D, 0x87, 0x84, 0xC0, 0xC0, 0x63, 0x6C, 0xCB
	};
	static const uint8_t label2[] = {
		0x5e, 0xdb, 0xe4, 0x27, 0xd9, 0x31, 0x90, 0xdf,
		0xac, 0x0e, 0x4b, 0x79, 0x0c, 0x5d, 0x77, 0xab,
		0x66, 0xd6, 0xe9, 0xee, 0x81, 0x92, 0x7c, 0x85,
		0x6b, 0x92, 0xbb, 0x99, 0xc2, 0x62, 0x35, 0xb0
	};
	static const uint8_t exp2[] = {
		0xaa
	};
	uint8_t act2[sizeof(exp2)];

	if (lc_kdf_fb(lc_sha256, key, sizeof(key), iv, sizeof(iv),
		      label, sizeof(label), act, sizeof(act))) {
		printf("FB KDF failed\n");
		return 1;
	}

	ret = compare(act, exp, sizeof(exp), "FB KDF SHA-256");

	if (lc_kdf_fb(lc_sha256, key2, sizeof(key2), iv2, sizeof(iv2),
		      label2, sizeof(label2), act2, sizeof(act2))) {
		printf("FB KDF failed\n");
		return 1;
	}

	ret += compare(act2, exp2, sizeof(exp2), "FB KDF SHA-256");

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kdf_fb_tester();
}
