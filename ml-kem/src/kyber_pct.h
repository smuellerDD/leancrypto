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

#include "kyber_type.h"
#include "lc_memcmp_secure.h"
#include "small_stack_support.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

static inline int _lc_kyber_pct_fips(const struct lc_kyber_pk *pk,
				     const struct lc_kyber_sk *sk)
{
	struct workspace {
		uint8_t m[32];
		struct lc_kyber_ct ct;
		struct lc_kyber_ss ss1, ss2;
	};
	uint8_t *ss1_p, *ss2_p;
	size_t ss1_size, ss2_size;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, ws->m, sizeof(ws->m)));

	CKINT(lc_kyber_enc(&ws->ct, &ws->ss1, pk));
	CKINT(lc_kyber_dec(&ws->ss2, &ws->ct, sk));

	ss1_p = ws->ss1.ss;
	ss1_size = sizeof(ws->ss1.ss);
	ss2_p = ws->ss2.ss;
	ss2_size = sizeof(ws->ss2.ss);

	/*
	 * Timecop: the Kyber SS will not reveal anything about the SK or PK.
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

static inline int lc_kyber_pct_fips(const struct lc_kyber_pk *pk,
				    const struct lc_kyber_sk *sk)
{
#ifdef LC_FIPS140
	return _lc_kyber_pct_fips(pk, sk);
#else
	(void)pk;
	(void)sk;
	return 0;
#endif
}
