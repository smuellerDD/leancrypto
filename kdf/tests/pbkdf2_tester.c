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
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "lc_pbkdf2.h"
#include "visibility.h"

static int pbkdf2_tester(void)
{
	/* RFC 5869 vector */
	static const uint8_t pw[] = { 0x70, 0x61, 0x73, 0x73,
				      0x77, 0x6f, 0x72, 0x64 };
	static const uint8_t salt[] = { 0x73, 0x61, 0x6c, 0x74 };
	static uint32_t count = 4096;
	static const uint8_t exp_256[] = { 0xc5, 0xe4, 0x78, 0xd5, 0x92,
					   0x88, 0xc8, 0x41, 0xaa, 0x53,
					   0x0d, 0xb6, 0x84, 0x5c, 0x4c,
					   0x8d, 0x96, 0x28, 0x93, 0xa0 };
	static const uint8_t exp_512[] = { 0xd1, 0x97, 0xb1, 0xb3, 0x3d,
					   0xb0, 0x14, 0x3e, 0x01, 0x8b,
					   0x12, 0xf3, 0xd1, 0xd1, 0x47,
					   0x9e, 0x6c, 0xde, 0xbd, 0xcc };
	uint8_t act[sizeof(exp_256)];
	int ret = 0;

	if (lc_pbkdf2(lc_sha256, pw, sizeof(pw), salt, sizeof(salt), count, act,
		      sizeof(act))) {
		printf("PKBDF2 failed\n");
		return 1;
	}
	ret += lc_compare(act, exp_256, sizeof(exp_256), "PBKDF SHA-256");

	if (lc_pbkdf2(lc_sha512, pw, sizeof(pw), salt, sizeof(salt), count, act,
		      sizeof(act))) {
		printf("PKBDF2 failed\n");
		return 1;
	}
	ret += lc_compare(act, exp_512, sizeof(exp_512), "PBKDF SHA-512");

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return pbkdf2_tester();
}
