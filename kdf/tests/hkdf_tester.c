/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>

#include "compare.h"
#include "lc_hkdf.h"
#include "lc_sha256.h"
#include "math_helper.h"

static int hkdf_tester(void)
{
	/* RFC 5869 vector */
	static const uint8_t ikm[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};
	static const uint8_t salt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c
	};
	static const uint8_t info[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9
	};
	static const uint8_t exp[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
		0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
		0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
		0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
		0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
		0x58, 0x65
	};
	uint8_t act[sizeof(exp)];
	LC_HKDF_CTX_ON_STACK(hkdf, lc_sha256);
	LC_HKDF_DRNG_CTX_ON_STACK(hkdf_rng, lc_sha256);
	struct lc_hkdf_ctx *hkdf_heap = NULL;
	unsigned int i = 0;
	int ret;

	if (lc_hkdf_extract(hkdf, ikm, sizeof(ikm), salt, sizeof(salt))) {
		printf("HKDF extract stack failed\n");
		return 1;
	}

	if (lc_hkdf_expand(hkdf, info, sizeof(info), act, sizeof(act))) {
		printf("HKDF expand stack failed\n");
		return 1;
	}

	ret = compare(act, exp, sizeof(exp), "HKDF SHA-256 stack");
	lc_hkdf_zero(hkdf);

	if (lc_rng_seed(hkdf_rng, ikm, sizeof(ikm), salt, sizeof(salt))) {
		printf("HKDF extract stack failed\n");
		return 1;
	}

	if (lc_rng_generate(hkdf_rng, info, sizeof(info), act, sizeof(act))) {
		printf("HKDF expand stack failed\n");
		return 1;
	}
	ret += compare(act, exp, sizeof(exp), "HKDF SHA-256 RNG");

	/*
	 * Verify that subsequent calls to the "RNG" of HKDF returns the same
	 * data as one common HKDF call. This shows that the RNG version
	 * can be inserted into any cipher implementation to generate the
	 * same data as if one HKDF call would be made to generate the entire
	 * requested buffer that is handed down to the wrapping cipher.
	 */
	/* Iterate through block sizes */
	for (i = 1; i <= sizeof(exp); i++) {
		size_t j = 0;

		/* Reinitialize the HKDF context */
		lc_rng_zero(hkdf_rng);
		if (lc_rng_seed(hkdf_rng, ikm, sizeof(ikm),
				salt, sizeof(salt))) {
			printf("HKDF extract stack failed\n");
			return 1;
		}

		/*
		 * Fill the entire requested buffer size with the given block
		 * size.
		 */
		while (j < sizeof(exp)) {
			size_t todo = min_t(size_t, i, sizeof(exp) - j);

			if (lc_rng_generate(hkdf_rng, info, sizeof(info),
					    act + j, todo)) {
				printf("HKDF expand stack failed\n");
				return 1;
			}

			j += todo;
		}
		ret += compare(act, exp, sizeof(exp),
			       "HKDF SHA-256 regenerate");
	}

	lc_rng_zero(hkdf_rng);

	if (lc_hkdf(lc_sha256, ikm, sizeof(ikm), salt, sizeof(salt),
		    info, sizeof(info), act, sizeof(act))) {
		printf("HKDF oneshot on stack failed\n");
		return 1;
	}
	ret += compare(act, exp, sizeof(exp), "HKDF SHA-256 oneshot");

	if (lc_hkdf_alloc(lc_sha256, &hkdf_heap)) {
		printf("HKDF alloc failed\n");
		lc_hkdf_zero_free(hkdf_heap);
		return 1;
	}

	if (lc_hkdf_extract(hkdf_heap, ikm, sizeof(ikm), salt, sizeof(salt))) {
		printf("HKDF extract heap failed\n");
		return 1;
	}

	if (lc_hkdf_expand(hkdf_heap, info, sizeof(info), act, sizeof(act))) {
		printf("HKDF expand heap failed\n");
		return 1;
	}

	ret += compare(act, exp, sizeof(exp), "HKDF SHA-256 heap");
	lc_hkdf_zero_free(hkdf_heap);

	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hkdf_tester();
}
