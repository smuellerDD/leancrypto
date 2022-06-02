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
#include "lc_kdf_ctr.h"
#include "lc_sha256.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/CounterMode.zip
 */
static int kdf_ctr_tester(void)
{
	static const uint8_t key[] = {
		0xdd, 0x1d, 0x91, 0xb7, 0xd9, 0x0b, 0x2b, 0xd3,
		0x13, 0x85, 0x33, 0xce, 0x92, 0xb2, 0x72, 0xfb,
		0xf8, 0xa3, 0x69, 0x31, 0x6a, 0xef, 0xe2, 0x42,
		0xe6, 0x59, 0xcc, 0x0a, 0xe2, 0x38, 0xaf, 0xe0
	};
	static const uint8_t label[] = {
		0x01, 0x32, 0x2b, 0x96, 0xb3, 0x0a, 0xcd, 0x19,
		0x79, 0x79, 0x44, 0x4e, 0x46, 0x8e, 0x1c, 0x5c,
		0x68, 0x59, 0xbf, 0x1b, 0x1c, 0xf9, 0x51, 0xb7,
		0xe7, 0x25, 0x30, 0x3e, 0x23, 0x7e, 0x46, 0xb8,
		0x64, 0xa1, 0x45, 0xfa, 0xb2, 0x5e, 0x51, 0x7b,
		0x08, 0xf8, 0x68, 0x3d, 0x03, 0x15, 0xbb, 0x29,
		0x11, 0xd8, 0x0a, 0x0e, 0x8a, 0xba, 0x17, 0xf3,
		0xb4, 0x13, 0xfa, 0xac
	};
	static const uint8_t exp[] = {
		0x10, 0x62, 0x13, 0x42, 0xbf, 0xb0, 0xfd, 0x40,
		0x04, 0x6c, 0x0e, 0x29, 0xf2, 0xcf, 0xdb, 0xf0
	};
	uint8_t act[sizeof(exp)];

	if (lc_kdf_ctr(lc_sha256, key, sizeof(key), label, sizeof(label),
		       act, sizeof(act))) {
		printf("CTR KDF failed\n");
		return 1;
	}

	return compare(act, exp, sizeof(exp), "CTR KDF SHA-256");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kdf_ctr_tester();
}
