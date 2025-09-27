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
			 uint8_t act[LC_SHA3_256_SIZE_DIGEST], int rerun)
{
	size_t i;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_256);
	int ret = 0;

	/*
	 * Mark the library to be in FIPS integrity check state, but stop if
	 * there is another check ongoing.
	 */
	if (lc_activate_library_selftest_init(rerun))
		goto out;

	/*
	 * As the SHA3-256 state is still in error state, invoke the nocheck
	 * call.
	 */
	CKINT(lc_sha3_256->init_nocheck(hash_ctx->hash_state));

	for (i = 0; i < n_secs; i++, secs++) {
		const uint8_t *start = secs->section_start_p,
			      *end = secs->section_end_p;
		size_t section_length = (size_t)(end - start);

		lc_hash_update(hash_ctx, start, section_length);
	}

	lc_hash_final(hash_ctx, act);
	lc_hash_zero(hash_ctx);

#ifdef LC_FIPS140_DEBUG
	/*
	 * Alter the result of the digest to verify that the failure handling of
	 * the library integrity error is appropriate.
	 */
	act[0] ^= 0x01;
#endif

	ret = lc_compare_selftest(LC_ALG_STATUS_LIB, act, exp,
				  LC_SHA3_256_SIZE_DIGEST,
				  "FIPS integrity test");

	/* Mark the library to be fully available. */
	if (!ret)
		lc_activate_library_selftest_fini();

out:
	return ret;
}
