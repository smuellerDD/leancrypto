/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef SPHINCS_PCT_H
#define SPHINCS_PCT_H

#include "fips_mode.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int _lc_sphincs_pct_fips(const struct lc_sphincs_pk *pk,
				       const struct lc_sphincs_sk *sk)
{
	struct workspace {
		uint8_t m[32];
		struct lc_sphincs_sig sig;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_sphincs_sign(&ws->sig, ws->m, sizeof(ws->m), sk,
			      lc_seeded_rng));
	CKINT(lc_sphincs_verify(&ws->sig, ws->m, sizeof(ws->m), pk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int lc_sphincs_pct_fips(const struct lc_sphincs_pk *pk,
				      const struct lc_sphincs_sk *sk)
{
	FIPS140_PCT_LOOP(_lc_sphincs_pct_fips(pk, sk))

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_PCT_H */
