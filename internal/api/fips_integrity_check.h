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

#ifndef FIPS_INTEGRITY_CHECK_H
#define FIPS_INTEGRITY_CHECK_H

#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_fips_integrity_sections {
	const char *desc;
	const uint8_t expected_digest[LC_SHA3_256_SIZE_DIGEST];
	const void *section_start_p;
	const void *section_end_p;
};
struct lc_fips_integrity_section_actual {
	uint8_t digest[LC_SHA3_256_SIZE_DIGEST];
};

void fips140_mode_enable(void);

int fips_integrity_check(const struct lc_fips_integrity_sections *secs,
			 struct lc_fips_integrity_section_actual *act,
			 size_t n_secs);

#ifdef __cplusplus
}
#endif

#endif /* FIPS_INTEGRITY_CHECK_H */
