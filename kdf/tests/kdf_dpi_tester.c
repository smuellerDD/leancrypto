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
#include "lc_kdf_dpi.h"
#include "lc_sha256.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/PipelineModewithCounter.zip
 */
static int kdf_dpi_tester(void)
{
	static const uint8_t key[] = {
		0x02, 0xd3, 0x6f, 0xa0, 0x21, 0xc2, 0x0d, 0xdb,
		0xde, 0xe4, 0x69, 0xf0, 0x57, 0x94, 0x68, 0xba,
		0xe5, 0xcb, 0x13, 0xb5, 0x48, 0xb6, 0xc6, 0x1c,
		0xdf, 0x9d, 0x3e, 0xc4, 0x19, 0x11, 0x1d, 0xe2
	};
	static const uint8_t label[] = {
		0x85, 0xab, 0xe3, 0x8b, 0xf2, 0x65, 0xfb, 0xdc,
		0x64, 0x45, 0xae, 0x5c, 0x71, 0x15, 0x9f, 0x15,
		0x48, 0xc7, 0x3b, 0x7d, 0x52, 0x6a, 0x62, 0x31,
		0x04, 0x90, 0x4a, 0x0f, 0x87, 0x92, 0x07, 0x0b,
		0x3d, 0xf9, 0x90, 0x2b, 0x96, 0x69, 0x49, 0x04,
		0x25, 0xa3, 0x85, 0xea, 0xdb, 0x0f, 0x9c, 0x76,
		0xe4, 0x6f, 0x0f
	};
	static const uint8_t exp[] = {
		0xd6, 0x9f, 0x74, 0xf5, 0x18, 0xc9, 0xf6, 0x4f,
		0x90, 0xa0, 0xbe, 0xeb, 0xab, 0x69, 0xf6, 0x89,
		0xb7, 0x3b, 0x5c, 0x13, 0xeb, 0x0f, 0x86, 0x0a,
		0x95, 0xca, 0xd7, 0xd9, 0x81, 0x4f, 0x8c, 0x50,
		0x6e, 0xb7, 0xb1, 0x79, 0xa5, 0xc5, 0xb4, 0x46,
		0x6a, 0x9e, 0xc1, 0x54, 0xc3, 0xbf, 0x1c, 0x13,
		0xef, 0xd6, 0xec, 0x0d, 0x82, 0xb0, 0x2c, 0x29,
		0xaf, 0x2c, 0x69, 0x02, 0x99, 0xed, 0xc4, 0x53
	};
	uint8_t act[sizeof(exp)];

	if (lc_kdf_dpi(lc_sha256, key, sizeof(key), label, sizeof(label),
		       act, sizeof(act))) {
		printf("DPI KDF failed\n");
		return 1;
	}

	return compare(act, exp, sizeof(exp), "DPI KDF SHA-256");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kdf_dpi_tester();
}
