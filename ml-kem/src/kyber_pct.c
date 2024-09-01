/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "lc_kyber.h"
#include "lc_memcmp_secure.h"
#include "lc_memset_secure.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_pct, const struct lc_kyber_pk *pk,
		      const struct lc_kyber_sk *sk)
{
	uint8_t m[32];
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss1, ss2;
	uint8_t *ss1_p, *ss2_p;
	size_t ss1_size, ss2_size;
	int ret;

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, m, sizeof(m)));

	CKINT(lc_kyber_enc(&ct, &ss1, pk));
	CKINT(lc_kyber_dec(&ss2, &ct, sk));

	CKINT(lc_kyber_ss_ptr(&ss1_p, &ss1_size, &ss1));
	CKINT(lc_kyber_ss_ptr(&ss2_p, &ss2_size, &ss2));

	/*
	 * Timecop: the Kyber SS will not reveal anything about the SK or PK.
	 * Further, it is not a secret here, as it is generated for testing.
	 * Thus, we can ignore side channels here.
	 */
	unpoison(ss1_p, ss1_size);
	unpoison(ss2_p, ss2_size);

	CKINT(lc_memcmp_secure(ss1_p, ss1_size, ss2_p, ss2_size));

out:
	lc_memset_secure(&ct, 0, sizeof(ct));
	lc_memset_secure(&ss1, 0, sizeof(ss1));
	lc_memset_secure(&ss2, 0, sizeof(ss2));
	return ret;
}
