/*
 * Copyright (C) 2015 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file
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

#include <inttypes.h>
#include <stdio.h>

#define CONVERSION_TEST
#include "conv_be_le.h"

static int compiler_test_le(void)
{
#if (defined(GCC_VERSION) && (GCC_VERSION >= 40400))
	uint16_t u16 = 1234;
	uint32_t u32 = 1234567890;
	uint64_t u64 = 1234567890123456789;

	if (_lc_bswap16(u16) != __builtin_bswap16(u16)) {
		printf("FAIL: compiler swap16 is not consistent with C (compiler %d, C %d)\n",
		       __builtin_bswap16(u16), _lc_bswap16(u16));
		return 1;
	}

	if (_lc_bswap32(u32) != __builtin_bswap32(u32)) {
		printf("FAIL: compiler swap32 is not consistent with C (compiler %u, C %u)\n",
		       __builtin_bswap32(u32), _lc_bswap32(u32));
		return 1;
	}

	if (_lc_bswap64(u64) != __builtin_bswap64(u64)) {
		printf("FAIL: compiler swap64 is not consistent with C (compiler %" PRIu64
		       ", C %" PRIu64 ")\n",
		       __builtin_bswap64(u64), _lc_bswap64(u64));
		return 1;
	}

	return 0;

#else
	printf("DEACT: compiler swap not defined\n");
	return 0;
#endif
}

static int sw_test_le(void)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint16_t u16 = 1234;
	uint32_t u32 = 1234567890;
	uint64_t u64 = 1234567890123456789;

	if (_lc_swap16(u16) != be_bswap16(u16)) {
		printf("FAIL: macro swap16 is not consistent with C (macro %d, C %d)\n",
		       be_bswap16(u16), _lc_bswap16(u16));
	}

	if (_lc_bswap32(u32) != be_bswap32(u32)) {
		printf("FAIL: macro swap32 is not consistent with C (macro %u, C %u)\n",
		       be_bswap32(u32), _lc_bswap32(u32));
		return 1;
	}

	if (_lc_bswap64(u64) != be_bswap64(u64)) {
		printf("FAIL: macro swap64 is not consistent with C (macro %" PRIu64
		       ", C %" PRIu64 ")\n",
		       be_bswap64(u64), _lc_bswap64(u64));
		return 1;
	}
#endif

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = compiler_test_le();
	ret += sw_test_le();
	return ret;
}
