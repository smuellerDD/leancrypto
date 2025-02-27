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
#include "fips_mode.h"
#include "lc_sha3.h"

/*
 * This flag is enabled by the FIPS 140 integrity test (i.e. when leancrypto
 * is started as a FIPS module)
 */
static int lc_fips140_enabled = 0;

void fips140_mode_enable(void)
{
	lc_fips140_enabled = 1;
}

int fips140_mode_enabled(void)
{
	return lc_fips140_enabled;
}

static int
fips_integrity_check_one(const struct lc_fips_integrity_sections *secs,
			 struct lc_fips_integrity_section_actual *act)
{
	const uint8_t *start = secs->section_start_p,
		      *end = secs->section_end_p;
	size_t section_length = (size_t)(end - start);

	lc_hash(lc_sha3_256, start, section_length, act->digest);

	return lc_compare(act->digest, secs->expected_digest, sizeof(act->digest),
			  secs->desc);
}

int fips_integrity_check(const struct lc_fips_integrity_sections *secs,
			 struct lc_fips_integrity_section_actual *act,
			 size_t n_secs)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < n_secs; i++, secs++, act++)
		ret |= fips_integrity_check_one(secs, act);

	return ret;
}
