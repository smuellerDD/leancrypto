/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef SNTRUP_PCT_H
#define SNTRUP_PCT_H

#include "fips_mode.h"
#include "lc_sntrup.h"
#include "lc_memcmp_secure.h"
#include "small_stack_support.h"
#include "params.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int _lc_sntrup_pct_fips(const struct CRYPTO_NAMESPACE(pk) * pk,
				      const struct CRYPTO_NAMESPACE(sk) * sk)
{
	struct workspace {
		struct CRYPTO_NAMESPACE(ct) ct;
		struct CRYPTO_NAMESPACE(ss) ss1, ss2;
	};
	uint8_t *ss1_p, *ss2_p;
	size_t ss1_size, ss2_size;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(CRYPTO_NAMESPACE(kem_enc)(&ws->ct, &ws->ss1, pk));
	CKINT(CRYPTO_NAMESPACE(kem_dec)(&ws->ss2, &ws->ct, sk));

	ss1_p = ws->ss1.ss;
	ss1_size = sizeof(ws->ss1.ss);
	ss2_p = ws->ss2.ss;
	ss2_size = sizeof(ws->ss2.ss);

	/*
	 * Timecop: the SNTRUP SS will not reveal anything about the SK or PK.
	 * Further, it is not a secret here, as it is generated for testing.
	 * Thus, we can ignore side channels here.
	 */
	unpoison(ss1_p, ss1_size);
	unpoison(ss2_p, ss2_size);

	CKINT(lc_memcmp_secure(ss1_p, ss1_size, ss2_p, ss2_size));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int lc_sntrup_pct_fips(const struct CRYPTO_NAMESPACE(pk) * pk,
				     const struct CRYPTO_NAMESPACE(sk) * sk)
{
	FIPS140_PCT_LOOP(_lc_sntrup_pct_fips(pk, sk),
			 LC_ALG_STATUS_SNTRUP_KEYGEN)
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SNTRUP_PCT_H */
