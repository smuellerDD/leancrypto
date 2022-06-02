/*
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#include "binhexbin.h"
#include "compare.h"
#include "lc_sha3.h"

static int sha3_224_tester(void)
{
	LC_HASH_CTX_ON_STACK(ctx224, lc_sha3_224);
	static const uint8_t msg_224[] = { 0x50, 0xEF, 0x73 };
	static const uint8_t exp_224[] = { 0x42, 0xF9, 0xE4, 0xEA, 0xE8, 0x55,
					   0x49, 0x61, 0xD1, 0xD2, 0x7D, 0x47,
					   0xD9, 0xAF, 0x08, 0xAF, 0x98, 0x8F,
					   0x18, 0x9F, 0x53, 0x42, 0x2A, 0x07,
					   0xD8, 0x7C, 0x68, 0xC1 };
	uint8_t act[LC_SHA3_224_SIZE_DIGEST];
	int ret;

	printf("hash ctx len %lu\n", LC_HASH_CTX_SIZE(lc_sha3_224));
	lc_hash_init(ctx224);
	lc_hash_update(ctx224, msg_224, 3);
	lc_hash_final(ctx224, act);
	ret = compare(act, exp_224, LC_SHA3_224_SIZE_DIGEST, "SHA3-224");
	lc_hash_zero(ctx224);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return sha3_224_tester();
}
