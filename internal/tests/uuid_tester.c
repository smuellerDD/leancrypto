/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "lc_rng.h"
#include "lc_uuid.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	char uuid_str[37];
	uint8_t uuid[16], uuid2[16];
	int ret;

	(void)argc;
	(void)argv;

	ret = lc_uuid_random(uuid_str);
	if (!ret)
		printf("random UUID %s\n", uuid_str);

	ret = lc_uuid_time(uuid_str, 0);
	if (!ret)
		printf("time UUID %s\n", uuid_str);

#ifdef LC_DRNG_PRESENT
	lc_rng_generate(lc_seeded_rng, NULL, 0, uuid, 16);
	lc_uuid_bin2hex(uuid, uuid_str);
	ret = lc_uuid_hex2bin(uuid_str, 36, uuid2);
	if (ret) {
		printf("UUID parsing failed: %d\n", ret);
		return -ret;
	}
	if (memcmp(uuid, uuid2, 16)) {
		printf("UUID parsing failed: %s", uuid_str);
		lc_uuid_bin2hex(uuid2, uuid_str);
		printf(" - %s\n", uuid_str);
		return EFAULT;
	}
	printf("UUID parsing successful: %s\n", uuid_str);
#else
	(void)uuid;
	(void)uuid2;
#endif

	return 0;
}
