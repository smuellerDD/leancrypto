/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
#include "fips_integrity_check.h"
#include "initialization.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

int fips_integrity_check(const struct lc_fips_integrity_sections *secs,
			 size_t n_secs,
			 const uint8_t exp[LC_SHA3_256_SIZE_DIGEST],
			 uint8_t act[LC_SHA3_256_SIZE_DIGEST])
{
	size_t i;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_256);
	int ret;

	/*
	 * TODO It is unclear why GCC seems to not honor the priorities of the
	 * constructors. It seems that the fips_integrity_checker_dep is run
	 * before the lc_activate_library which implies that without the
	 * following call, the library is not initialized at this point. This
	 * causes the hash invocation to return -EOPNOTSUPP since the library
	 * is still gated at this point.
	 */
	if (lc_status_get_result(LC_ALG_STATUS_FLAG_LIB) <=
	    lc_alg_status_result_ongoing)
		lc_activate_library();

	CKINT(lc_hash_init(hash_ctx));
	for (i = 0; i < n_secs; i++, secs++) {
		const uint8_t *start = secs->section_start_p,
			      *end = secs->section_end_p;
		size_t section_length = (size_t)(end - start);

		lc_hash_update(hash_ctx, start, section_length);
	}

	lc_hash_final(hash_ctx, act);
	lc_hash_zero(hash_ctx);

	ret = lc_compare(act, exp, LC_SHA3_256_SIZE_DIGEST, "Sections");

out:
	return ret;
}
