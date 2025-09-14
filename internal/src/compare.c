/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "ext_headers_internal.h"
#include "lc_status.h"
#include "lc_memcmp_secure.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_compare, const uint8_t *act, const uint8_t *exp,
		      const size_t len, const char *info)
{
	/* In EFI-compilation, printf is not defined */
	(void)info;

	if (lc_memcmp_secure(act, len, exp, len)) {
		unsigned int i;

		printf("Expected %s ", info);
		for (i = 0; i < len; i++) {
			printf("0x%.2x ", *(exp + i));
			if (!((i + 1) % 8))
				printf("\n");
		}

		printf("\n");

		printf("Actual %s ", info);
		for (i = 0; i < len; i++) {
			printf("0x%.2x ", *(act + i));
			if (!((i + 1) % 8))
				printf("\n");
		}

		printf("\n");

		return 1;
	}

	return 0;
}

int lc_compare_selftest(uint64_t flag, const uint8_t *act, const uint8_t *exp,
			const size_t len, const char *info)
{
	if (lc_compare(act, exp, len, info)) {
		alg_status_set_result(lc_alg_status_result_failed, flag);
		return 1;
	}

	alg_status_set_result(lc_alg_status_result_passed, flag);
	return 0;
}

void lc_disable_selftest(void)
{
	alg_status_set_result(lc_alg_status_result_passed, (uint64_t)-1);
}
