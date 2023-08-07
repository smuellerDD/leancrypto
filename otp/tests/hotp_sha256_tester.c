/*
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "lc_hotp.h"
#include "lc_totp.h"

/*
 * SHA-256 TOTP test vectors.
 */
static int hotp_sha256(void)
{
	/* HOTP test vectors from RFC 4226 */
	static const uint8_t hmac256_key[] = "\x31\x32\x33\x34\x35\x36\x37\x38"
					     "\x39\x30\x31\x32\x33\x34\x35\x36"
					     "\x37\x38\x39\x30\x31\x32\x33\x34"
					     "\x35\x36\x37\x38\x39\x30\x31\x32";
	static const uint64_t time[] = { 59,	     1111111109, 1111111111,
					 1234567890, 2000000000, 20000000000 };
	static const unsigned int totp_sha256[] = { 46119246, 68084774,
						    67062674, 91819424,
						    90698825, 77737706 };

	int ret, result = 0;
	unsigned int i;
	uint32_t totp_val;

	for (i = 0; i < 6; i++) {
		uint64_t counter = time[i] / 30;

		lc_hotp(hmac256_key, sizeof(hmac256_key) - 1, counter, 8,
			&totp_val);

		if (totp_val != totp_sha256[i]) {
			printf("SHA-256 Test FAIL for counter %u (exp %u, calc %u)\n",
			       i, totp_sha256[i], totp_val);
			result++;
		}
	}

	ret = lc_totp(hmac256_key, sizeof(hmac256_key) - 1, 30, 6, &totp_val);
	if (ret) {
		printf("Test FAIL for totp %u\n", totp_val);
		result++;
	}

	return result;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hotp_sha256();
}
