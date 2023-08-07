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
#include "ext_headers.h"
#include "lc_status.h"
#include "visibility.h"

/*
 * This variable controls whether a self test should be (re-)executed. A self
 * test is executed, if the self-test state variable is less than this level
 * variable. Once the self test is executed, it is set to the level. An API
 * is provided allowing a caller to trigger the re-execution of self tests
 * by simply incrementing this variable by one.
 */
static int lc_selftest_level = 1;

/*
 * This is no interface function, but to access the global variable, the
 * visibility is required to get the same scope, seemingly.
 */
LC_INTERFACE_FUNCTION(int, get_current_selftest_level, void)
{
	return lc_selftest_level;
}

LC_INTERFACE_FUNCTION(void, lc_rerun_selftests, void)
{
	if (lc_selftest_level < INT_MAX)
		__sync_add_and_fetch(&lc_selftest_level, 1);
}

LC_INTERFACE_FUNCTION(int, lc_compare, const uint8_t *act, const uint8_t *exp,
		      const size_t len, const char *info)
{
	if (memcmp(act, exp, len)) {
		unsigned int i;

		printf("Expected %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(exp + i));

		printf("\n");

		printf("Actual %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(act + i));

		printf("\n");

		return 1;
	}

	return 0;
}

void lc_compare_selftest(const uint8_t *act, const uint8_t *exp,
			 const size_t len, const char *info)
{
	assert(!lc_compare(act, exp, len, info));
}
